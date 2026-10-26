using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using CipherSurface.Verification.Email;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services.Tests;

public sealed class FakeTime : TimeProvider
{
    private DateTimeOffset _now;
    public FakeTime(DateTimeOffset now) => _now = now;
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>Verifier whose answer is scripted by call number (0, 1, 2 ...). The script can be replaced mid-test.</summary>
public sealed class ScriptedVerifier : IOwnershipVerifier
{
    private int _calls;

    public ScriptedVerifier(VerificationMethod method, Func<int, VerificationObservation> script)
    {
        Method = method;
        Script = script;
    }

    public VerificationMethod Method { get; }
    public Func<int, VerificationObservation> Script { get; set; }
    public int Calls => _calls;

    public Task<VerificationObservation> CheckAsync(VerificationRequest request, CancellationToken ct) =>
        Task.FromResult(Script(Interlocked.Increment(ref _calls) - 1));
}

public sealed class TestPlatformAdminPolicy : IPlatformAdminPolicy
{
    public HashSet<Guid> Admins { get; } = new();
    public Task<bool> IsPlatformAdminAsync(Guid userId, CancellationToken ct) => Task.FromResult(Admins.Contains(userId));
}

public sealed class RecordingEmailSender : IEmailSender
{
    public List<EmailMessage> Sent { get; } = new();
    public bool FailNext { get; set; }

    public Task SendAsync(EmailMessage message, CancellationToken ct)
    {
        if (FailNext)
        {
            FailNext = false;
            throw new InvalidOperationException("SMTP is down");
        }
        lock (Sent) Sent.Add(message);
        return Task.CompletedTask;
    }
}

public sealed class TestWorld
{
    public required TestDatabase Db { get; init; }
    public required FakeTime Time { get; init; }
    public required ScriptedVerifier Dns { get; init; }
    public required ScriptedVerifier Http { get; init; }
    public required RecordingEmailSender Sender { get; init; }
    public required AuditLogWriter Audit { get; init; }
    public required DomainOnboardingService Onboarding { get; init; }
    public required ChallengeService Challenges { get; init; }
    public required VerificationService Verification { get; init; }
    public required EmailVerificationService Email { get; init; }
    public required EvidenceReverificationService Reverify { get; init; }
    public required EvidenceLifecycleService Lifecycle { get; init; }
    public required DisputeService Disputes { get; init; }
    public required ScanStartService Scans { get; init; }
    public required ScanRunService Runs { get; init; }
    public required ScanPayloadSigner Signer { get; init; }
    public required GrantService Grants { get; init; }
    public required OrganizationService Orgs { get; init; }
    public required TestPlatformAdminPolicy AdminPolicy { get; init; }
    public required PlatformAdminGate AdminGate { get; init; }

    public static readonly DateTimeOffset Start = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);
    private int _counter;

    public static async Task<TestWorld> CreateAsync(
        PostgresFixture postgres,
        Func<int, VerificationObservation>? dnsScript = null,
        VerificationOptions? options = null,
        EmailVerificationOptions? emailOptions = null)
    {
        var db = await postgres.CreateDatabaseAsync();
        var time = new FakeTime(Start);
        var dns = new ScriptedVerifier(VerificationMethod.DnsTxt, dnsScript ?? (_ => VerificationObservation.Valid()));
        var http = new ScriptedVerifier(VerificationMethod.HttpFile, _ => VerificationObservation.Valid());
        var registry = new VerifierRegistry(new IOwnershipVerifier[] { dns, http });
        var audit = new AuditLogWriter(time);
        var claims = new ClaimService(time, audit);
        var sender = new RecordingEmailSender();
        var attemptOptions = options ?? new VerificationOptions();
        var adminPolicy = new TestPlatformAdminPolicy();
        var signer = new ScanPayloadSigner(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());

        return new TestWorld
        {
            Db = db,
            Time = time,
            Dns = dns,
            Http = http,
            Sender = sender,
            Audit = audit,
            Onboarding = new DomainOnboardingService(db, time, audit, new DomainNameValidator()),
            Challenges = new ChallengeService(db, time, audit),
            Verification = new VerificationService(db, time, registry, claims, audit, attemptOptions, delay: (_, _) => Task.CompletedTask),
            Email = new EmailVerificationService(db, time, claims, audit, sender, emailOptions, attemptOptions),
            Reverify = new EvidenceReverificationService(db, time, registry, audit),
            Lifecycle = new EvidenceLifecycleService(db, time, audit),
            Disputes = new DisputeService(db, time, audit),
            Scans = new ScanStartService(db, time, registry, audit),
            Runs = new ScanRunService(db, time, registry, audit, signer),
            Signer = signer,
            Grants = new GrantService(db, time, audit),
            Orgs = new OrganizationService(db, time, audit),
            AdminPolicy = adminPolicy,
            AdminGate = new PlatformAdminGate(adminPolicy)
        };
    }

    /// <summary>Creates an organization with one member in the given role.</summary>
    public async Task<Actor> NewOrgAsync(string name, MembershipRole role = MembershipRole.Owner, string? ip = null)
    {
        await using var db = Db.CreateDbContext();
        var org = new Organization { Id = Guid.NewGuid(), Name = name, Status = OrganizationStatus.Active, CreatedAt = Start };
        db.Organizations.Add(org);
        await db.SaveChangesAsync();
        return await AddMemberAsync(org.Id, role, ip);
    }

    /// <summary>Adds another user to an existing organization.</summary>
    public async Task<Actor> AddMemberAsync(Guid organizationId, MembershipRole role, string? ip = null)
    {
        var n = Interlocked.Increment(ref _counter);
        await using var db = Db.CreateDbContext();
        var user = new User { Id = Guid.NewGuid(), Email = $"user{n}-{Guid.NewGuid():N}@example.org", PasswordHash = "x", CreatedAt = Start };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        db.Memberships.Add(new Membership { Id = Guid.NewGuid(), OrganizationId = organizationId, UserId = user.Id, Role = role, CreatedAt = Start });
        await db.SaveChangesAsync();
        return new Actor(user.Id, organizationId, ip ?? $"203.0.113.{n % 250 + 1}");
    }

    public Task<Guid> AddDomainAsync(Actor actor, string name) =>
        Onboarding.AddDomainAsync(actor, name, "v1", "I am authorized to monitor this domain.", CancellationToken.None);

    public async Task AddRuleAsync(Actor by, Guid domainId, ScopeRuleType type, string pattern)
    {
        await using var db = Db.CreateDbContext();
        db.ScopeRules.Add(new ScopeRule { Id = Guid.NewGuid(), DomainId = domainId, RuleType = type, Pattern = pattern, CreatedByUserId = by.UserId, CreatedAt = Start });
        await db.SaveChangesAsync();
    }

    public Task<ScanStartResult> StartScanAsync(Actor actor, Guid domainId, params string[] targets) =>
        Scans.StartAsync(actor, domainId, targets, DecisionTrigger.Manual, null, null, CancellationToken.None);

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

    public async Task<VerificationEvidence> GetEvidenceAsync(Guid id)
    {
        await using var db = Db.CreateDbContext();
        return await db.VerificationEvidence.AsNoTracking().SingleAsync(e => e.Id == id);
    }

    /// <summary>A real user row (the dispute record points at it) acting as platform administrator.</summary>
    public async Task<PlatformAdmin> NewPlatformAdminAsync()
    {
        var n = Interlocked.Increment(ref _counter);
        await using var db = Db.CreateDbContext();
        var user = new User { Id = Guid.NewGuid(), Email = $"platform{n}-{Guid.NewGuid():N}@example.org", PasswordHash = "x", CreatedAt = Start };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        AdminPolicy.Admins.Add(user.Id);
        return await AdminGate.AuthorizeAsync(user.Id, CancellationToken.None);
    }

    public async Task SuspendAsync(Guid organizationId)
    {
        await using var db = Db.CreateDbContext();
        var org = await db.Organizations.SingleAsync(o => o.Id == organizationId);
        org.Status = OrganizationStatus.Suspended;
        await db.SaveChangesAsync();
    }
}

/// <summary>Ready-made starting states for tests.</summary>
public static class Scenarios
{
    public static async Task<(Guid DomainId, Guid EvidenceId)> VerifiedByDnsAsync(TestWorld world, Actor owner, string name = "example.com")
    {
        var domainId = await world.AddDomainAsync(owner, name);
        var challenge = await world.Challenges.IssueAsync(owner, domainId, VerificationMethod.DnsTxt, null, CancellationToken.None);
        await world.Verification.VerifyAsync(owner, challenge.ChallengeId, CancellationToken.None);
        return (domainId, await EvidenceIdAsync(world, challenge.ChallengeId));
    }

    public static async Task<Guid> AddHttpEvidenceAsync(TestWorld world, Actor owner, Guid domainId)
    {
        var challenge = await world.Challenges.IssueAsync(owner, domainId, VerificationMethod.HttpFile, null, CancellationToken.None);
        await world.Verification.VerifyAsync(owner, challenge.ChallengeId, CancellationToken.None);
        return await EvidenceIdAsync(world, challenge.ChallengeId);
    }

    /// <summary>A holds example.com (verified by DNS); B verified the same name and was disputed.</summary>
    public static async Task<OpenDispute> OpenDisputeAsync(TestWorld world, string name = "example.com")
    {
        var a = await world.NewOrgAsync("Holder");
        var b = await world.NewOrgAsync("Claimant");
        var (domainA, evidenceA) = await VerifiedByDnsAsync(world, a, name);
        var (domainB, evidenceB) = await VerifiedByDnsAsync(world, b, name);
        await using var db = world.Db.CreateDbContext();
        var disputeId = await db.DomainDisputes.Where(d => d.ClaimantDomainId == domainB).Select(d => d.Id).SingleAsync();
        return new OpenDispute(a, b, domainA, evidenceA, domainB, evidenceB, disputeId);
    }

    /// <summary>Verified by DNS, with the whole domain and its subdomains included in scope.</summary>
    public static async Task<(Guid DomainId, Guid EvidenceId)> ScannableByDnsAsync(TestWorld world, Actor owner, string name = "example.com")
    {
        var verified = await VerifiedByDnsAsync(world, owner, name);
        await world.AddRuleAsync(owner, verified.DomainId, ScopeRuleType.Include, name);
        await world.AddRuleAsync(owner, verified.DomainId, ScopeRuleType.Include, "*." + name);
        return verified;
    }

    /// <summary>A scan that was allowed and handed to a worker.</summary>
    public static async Task<(Guid RunId, ScanWorkOrder Order)> RunningScanAsync(TestWorld world, Actor owner, Guid domainId, params string[] targets)
    {
        var started = await world.StartScanAsync(owner, domainId, targets);
        if (!started.Allowed) throw new InvalidOperationException($"The scan was denied: {started.FailedCheckCode}");
        var order = await world.Runs.BeginAsync(started.ScanRunId!.Value, CancellationToken.None);
        return (started.ScanRunId.Value, order);
    }

    public static async Task<(Guid DomainId, Guid EvidenceId)> VerifiedByEmailAsync(TestWorld world, Actor owner, string name = "example.com")
    {
        var domainId = await world.AddDomainAsync(owner, name);
        var (challengeId, token) = await IssueEmailAsync(world, owner, domainId, $"admin@{name}");
        await world.Email.ConfirmAsync(owner, challengeId, token, CancellationToken.None);
        return (domainId, await EvidenceIdAsync(world, challengeId));
    }

    public static async Task<(Guid ChallengeId, string Token)> IssueEmailAsync(TestWorld world, Actor actor, Guid domainId, string recipient)
    {
        await world.Email.IssueAsync(actor, domainId, recipient, new Uri("https://app.ciphersurface.test/verify-email"), CancellationToken.None);
        return ParseLink(world.Sender.Sent[^1]);
    }

    public static (Guid ChallengeId, string Token) ParseLink(EmailMessage message)
    {
        var match = System.Text.RegularExpressions.Regex.Match(message.TextBody, @"\?c=([0-9a-fA-F-]{36})&t=([A-Za-z0-9_-]+)");
        return (Guid.Parse(match.Groups[1].Value), match.Groups[2].Value);
    }

    private static async Task<Guid> EvidenceIdAsync(TestWorld world, Guid challengeId)
    {
        await using var db = world.Db.CreateDbContext();
        return await db.VerificationEvidence.Where(e => e.ChallengeId == challengeId).Select(e => e.Id).SingleAsync();
    }
}

public sealed record OpenDispute(Actor Holder, Actor Claimant, Guid HolderDomainId, Guid HolderEvidenceId, Guid ClaimantDomainId, Guid ClaimantEvidenceId, Guid DisputeId);
