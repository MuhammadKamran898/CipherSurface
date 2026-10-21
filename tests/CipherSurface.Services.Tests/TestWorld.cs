using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services.Tests;

public sealed class FakeTime : TimeProvider
{
    private DateTimeOffset _now;
    public FakeTime(DateTimeOffset now) => _now = now;
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>Verifier whose answer is scripted by call number (0, 1, 2 ...).</summary>
public sealed class ScriptedVerifier : IOwnershipVerifier
{
    private readonly Func<int, VerificationObservation> _script;
    private int _calls;

    public ScriptedVerifier(VerificationMethod method, Func<int, VerificationObservation> script)
    {
        Method = method;
        _script = script;
    }

    public VerificationMethod Method { get; }
    public int Calls => _calls;

    public Task<VerificationObservation> CheckAsync(VerificationRequest request, CancellationToken ct) =>
        Task.FromResult(_script(Interlocked.Increment(ref _calls) - 1));
}

public sealed class TestWorld
{
    public required TestDatabase Db { get; init; }
    public required FakeTime Time { get; init; }
    public required ScriptedVerifier Dns { get; init; }
    public required ScriptedVerifier Http { get; init; }
    public required AuditLogWriter Audit { get; init; }
    public required DomainOnboardingService Onboarding { get; init; }
    public required ChallengeService Challenges { get; init; }
    public required VerificationService Verification { get; init; }

    public static readonly DateTimeOffset Start = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);
    private int _counter;

    public static async Task<TestWorld> CreateAsync(
        PostgresFixture postgres,
        Func<int, VerificationObservation>? dnsScript = null,
        VerificationOptions? options = null)
    {
        var db = await postgres.CreateDatabaseAsync();
        var time = new FakeTime(Start);
        var dns = new ScriptedVerifier(VerificationMethod.DnsTxt, dnsScript ?? (_ => VerificationObservation.Valid()));
        var http = new ScriptedVerifier(VerificationMethod.HttpFile, _ => VerificationObservation.Valid());
        var registry = new VerifierRegistry(new IOwnershipVerifier[] { dns, http });
        var audit = new AuditLogWriter(time);
        var claims = new ClaimService(time, audit);

        return new TestWorld
        {
            Db = db,
            Time = time,
            Dns = dns,
            Http = http,
            Audit = audit,
            Onboarding = new DomainOnboardingService(db, time, audit, new DomainNameValidator()),
            Challenges = new ChallengeService(db, time, audit),
            Verification = new VerificationService(db, time, registry, claims, audit, options ?? new VerificationOptions(),
                delay: (_, _) => Task.CompletedTask)
        };
    }

    /// <summary>Creates an organization with one member in the given role.</summary>
    public async Task<Actor> NewOrgAsync(string name, MembershipRole role = MembershipRole.Owner, string? ip = null)
    {
        var n = Interlocked.Increment(ref _counter);
        await using var db = Db.CreateDbContext();
        var org = new Organization { Id = Guid.NewGuid(), Name = name, Status = OrganizationStatus.Active, CreatedAt = Start };
        var user = new User { Id = Guid.NewGuid(), Email = $"user{n}-{Guid.NewGuid():N}@example.org", PasswordHash = "x", CreatedAt = Start };
        db.Organizations.Add(org);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        db.Memberships.Add(new Membership { Id = Guid.NewGuid(), OrganizationId = org.Id, UserId = user.Id, Role = role, CreatedAt = Start });
        await db.SaveChangesAsync();
        return new Actor(user.Id, org.Id, ip ?? $"203.0.113.{n % 250 + 1}");
    }

    public Task<Guid> AddDomainAsync(Actor actor, string name) =>
        Onboarding.AddDomainAsync(actor, name, "v1", "I am authorized to monitor this domain.", CancellationToken.None);

    public async Task<Domain> GetDomainAsync(Guid id)
    {
        await using var db = Db.CreateDbContext();
        return await db.Domains.AsNoTracking().SingleAsync(d => d.Id == id);
    }

    public async Task<VerificationChallenge> GetChallengeAsync(Guid id)
    {
        await using var db = Db.CreateDbContext();
        return await db.VerificationChallenges.AsNoTracking().SingleAsync(c => c.Id == id);
    }

    public async Task SuspendAsync(Guid organizationId)
    {
        await using var db = Db.CreateDbContext();
        var org = await db.Organizations.SingleAsync(o => o.Id == organizationId);
        org.Status = OrganizationStatus.Suspended;
        await db.SaveChangesAsync();
    }
}
