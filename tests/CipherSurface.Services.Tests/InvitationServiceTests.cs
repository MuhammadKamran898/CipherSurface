using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CipherSurface.Auth;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class InvitationServiceTests
{
    private const string Password = "correct horse battery staple";
    private const string Ip = "203.0.113.60";
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly PostgresFixture _postgres;
    public InvitationServiceTests(PostgresFixture postgres) => _postgres = postgres;

    // ------------------------------------------------------------------ world

    private sealed class World
    {
        public required TestDatabase Db { get; init; }
        public required AuthHost Host { get; init; }
        public required Actor Owner { get; init; }

        public Guid OrganizationId => Owner.OrganizationId;
        public FakeTime Time => Host.Time;

        public async Task<T> Run<T>(Func<InvitationService, Task<T>> call)
        {
            using var scope = Host.Provider.CreateScope();
            return await call(scope.ServiceProvider.GetRequiredService<InvitationService>());
        }

        public Task Run(Func<InvitationService, Task> call) => Run(async s => { await call(s); return 0; });

        /// <summary>A user (with an organization of their own) who is also a member of this organization.</summary>
        public async Task<Actor> AddMemberAsync(MembershipRole role, string email)
        {
            var registered = await Host.Run(a => a.RegisterAsync(email, Password, $"Org of {email}", Ct));
            await using var db = Db.CreateDbContext();
            db.Memberships.Add(new Membership { Id = Guid.NewGuid(), OrganizationId = OrganizationId, UserId = registered.UserId, Role = role, CreatedAt = Time.GetUtcNow() });
            await db.SaveChangesAsync(Ct);
            return new Actor(registered.UserId, OrganizationId, Ip);
        }

        public Task<InvitationIssued> InviteAsync(string email, MembershipRole role = MembershipRole.Analyst, Actor? by = null) =>
            Run(s => s.IssueAsync(by ?? Owner, email, role, Ct));

        public async Task<List<Invitation>> InvitationsAsync()
        {
            await using var db = Db.CreateDbContext();
            return await db.Invitations.AsNoTracking().OrderBy(i => i.CreatedAt).ThenBy(i => i.Email).ToListAsync(Ct);
        }

        public async Task<List<AuditLog>> AuditAsync(Guid? organizationId = null)
        {
            await using var db = Db.CreateDbContext();
            var org = organizationId ?? OrganizationId;
            return await db.AuditLogs.AsNoTracking().Where(a => a.OrganizationId == org && a.Action.StartsWith("invitation.")).OrderBy(a => a.Sequence).ToListAsync(Ct);
        }

        public async Task<User?> UserByEmailAsync(string email)
        {
            await using var db = Db.CreateDbContext();
            return await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Email == email, Ct);
        }

        public async Task UpdateAsync(Func<CipherSurfaceDbContext, Task> change)
        {
            await using var db = Db.CreateDbContext();
            await change(db);
        }
    }

    private async Task<World> NewWorldAsync(InvitationOptions? options = null)
    {
        var db = await _postgres.CreateDatabaseAsync();
        var time = new FakeTime(TestWorld.Start);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(time);
        services.AddCipherSurfaceData(db.ConnectionString);
        services.AddCipherSurfaceAuth(new JwtOptions(), TokenKeys.Generate("test-key").Keys, options);
        var host = new AuthHost { Provider = services.BuildServiceProvider(), Time = time, Options = new JwtOptions(), Keys = TokenKeys.Generate("test-key").Keys };
        var owner = await host.Run(a => a.RegisterAsync("owner@example.com", Password, "Acme", Ct));
        return new World { Db = db, Host = host, Owner = new Actor(owner.UserId, owner.OrganizationId, Ip) };
    }

    private static async Task<ServiceException> FailsAsync(string code, Func<Task> call)
    {
        var ex = await Assert.ThrowsAsync<ServiceException>(call);
        Assert.Equal(code, ex.Code);
        return ex;
    }

    private static string Sha256Hex(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static string Field(AuditLog entry, string name) => JsonDocument.Parse(entry.Data).RootElement.GetProperty(name).ToString();

    // ------------------------------------------------------------------ issuing

    [Fact]
    public async Task AnOwnerCanInvite_AndOnlyTheHashOfTheTokenIsStored()
    {
        var w = await NewWorldAsync();

        var issued = await w.InviteAsync("  New.Person@Example.COM ", MembershipRole.Analyst);

        Assert.Equal("new.person@example.com", issued.Email);
        Assert.Equal(MembershipRole.Analyst, issued.Role);
        Assert.Equal(TestWorld.Start.AddDays(7), issued.ExpiresAt);
        Assert.True(issued.Token.Length >= 43);
        Assert.DoesNotContain('=', issued.Token);

        var row = Assert.Single(await w.InvitationsAsync());
        Assert.Equal(issued.InvitationId, row.Id);
        Assert.Equal(Sha256Hex(issued.Token), row.TokenHash);
        Assert.NotEqual(issued.Token, row.TokenHash);
        Assert.Equal(InvitationStatus.Pending, row.Status);
        Assert.Equal(w.Owner.UserId, row.CreatedByUserId);
        Assert.Equal(w.OrganizationId, row.OrganizationId);
        Assert.Null(row.ResolvedAt);
    }

    [Fact]
    public async Task EveryTokenIsDifferent()
    {
        var w = await NewWorldAsync();

        var a = await w.InviteAsync("a@example.com");
        var b = await w.InviteAsync("b@example.com");

        Assert.NotEqual(a.Token, b.Token);
        Assert.NotEqual((await w.InvitationsAsync())[0].TokenHash, (await w.InvitationsAsync())[1].TokenHash);
    }

    [Theory]
    [InlineData(MembershipRole.Admin)]
    [InlineData(MembershipRole.Analyst)]
    [InlineData(MembershipRole.Viewer)]
    public async Task AnyOfTheThreeRolesCanBeInvited(MembershipRole role)
    {
        var w = await NewWorldAsync();

        var issued = await w.InviteAsync("new@example.com", role);

        Assert.Equal(role, issued.Role);
    }

    [Theory]
    [InlineData(MembershipRole.Owner)]
    [InlineData((MembershipRole)42)]
    public async Task OwnerCannotBeInvited_AndNeitherCanAnUnknownRole(MembershipRole role)
    {
        var w = await NewWorldAsync();

        await FailsAsync("InvalidRole", () => w.InviteAsync("new@example.com", role));

        Assert.Empty(await w.InvitationsAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-email")]
    [InlineData("a@b")]
    public async Task AnInvalidEmailIsRejected(string? email)
    {
        var w = await NewWorldAsync();

        await FailsAsync("EmailInvalid", () => w.Run(s => s.IssueAsync(w.Owner, email, MembershipRole.Viewer, Ct)));
    }

    [Fact]
    public async Task AnAdminCanInvite_ButAnAnalystAViewerAndAStrangerCannot()
    {
        var w = await NewWorldAsync();
        var admin = await w.AddMemberAsync(MembershipRole.Admin, "admin@example.com");
        var analyst = await w.AddMemberAsync(MembershipRole.Analyst, "analyst@example.com");
        var viewer = await w.AddMemberAsync(MembershipRole.Viewer, "viewer@example.com");
        var stranger = await w.Host.Run(a => a.RegisterAsync("stranger@example.com", Password, "Elsewhere", Ct));
        var forged = new Actor(stranger.UserId, w.OrganizationId, Ip);

        await w.InviteAsync("one@example.com", MembershipRole.Viewer, admin);
        foreach (var actor in new[] { analyst, viewer, forged })
            await FailsAsync("NotAllowed", () => w.InviteAsync("two@example.com", MembershipRole.Viewer, actor));

        Assert.Single(await w.InvitationsAsync());
    }

    [Fact]
    public async Task ASuspendedOrganizationCannotInvite()
    {
        var w = await NewWorldAsync();
        await w.UpdateAsync(db => db.Organizations.ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, OrganizationStatus.Suspended), Ct));

        await FailsAsync("OrganizationSuspended", () => w.InviteAsync("new@example.com"));
    }

    [Fact]
    public async Task InvitingAnExistingMemberIsRejected_ButAnAccountOutsideTheOrganizationIsFine()
    {
        var w = await NewWorldAsync();
        await w.AddMemberAsync(MembershipRole.Viewer, "member@example.com");
        await w.Host.Run(a => a.RegisterAsync("outsider@example.com", Password, "Their org", Ct));

        await FailsAsync("AlreadyMember", () => w.InviteAsync("MEMBER@example.com"));
        await w.InviteAsync("outsider@example.com");

        Assert.Single(await w.InvitationsAsync());
    }

    [Fact]
    public async Task ACustomLifetimeIsHonoured()
    {
        var w = await NewWorldAsync(new InvitationOptions { Lifetime = TimeSpan.FromDays(2) });

        var issued = await w.InviteAsync("new@example.com");

        Assert.Equal(TestWorld.Start.AddDays(2), issued.ExpiresAt);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    public void ALifetimeOutsideOneToThirtyDaysIsRejected(int days)
    {
        var time = new FakeTime(TestWorld.Start);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new InvitationService(null!, null!, new AuditLogWriter(time), time, new InvitationOptions { Lifetime = TimeSpan.FromDays(days) }));
    }

    // ------------------------------------------------------------------ reissuing

    [Fact]
    public async Task IssuingAgain_SupersedesTheEarlierInvitation_SoItsTokenStopsWorking()
    {
        var w = await NewWorldAsync();
        var first = await w.InviteAsync("new@example.com", MembershipRole.Viewer);

        var second = await w.InviteAsync("New@Example.com", MembershipRole.Admin);

        var rows = await w.InvitationsAsync();
        Assert.Equal(2, rows.Count);
        var old = rows.Single(r => r.Id == first.InvitationId);
        Assert.Equal(InvitationStatus.Superseded, old.Status);
        Assert.Equal(TestWorld.Start, old.ResolvedAt);
        Assert.Equal(w.Owner.UserId, old.ResolvedByUserId);
        Assert.Single(rows, r => r.Status == InvitationStatus.Pending && r.Id == second.InvitationId);

        await FailsAsync("InvitationNotPending", () => w.Run(s => s.PreviewAsync(first.Token, Ct)));
        Assert.Equal(MembershipRole.Admin, (await w.Run(s => s.PreviewAsync(second.Token, Ct))).Role);

        var created = (await w.AuditAsync()).Last();
        Assert.Equal(first.InvitationId.ToString("D"), Field(created, "supersededInvitationId"));
    }

    [Fact]
    public async Task AnExpiredInvitation_IsSupersededToo_SoReissuingAfterExpiryWorks()
    {
        var w = await NewWorldAsync();
        var first = await w.InviteAsync("new@example.com");
        w.Time.Advance(TimeSpan.FromDays(8));

        var second = await w.InviteAsync("new@example.com");

        Assert.Equal(InvitationStatus.Superseded, (await w.InvitationsAsync()).Single(r => r.Id == first.InvitationId).Status);
        Assert.NotNull(await w.Run(s => s.PreviewAsync(second.Token, Ct)));
    }

    [Fact]
    public async Task TheSameEmailCanBeInvitedToTwoOrganizationsIndependently()
    {
        var w = await NewWorldAsync();
        var other = await w.Host.Run(a => a.RegisterAsync("other-owner@example.com", Password, "Other org", Ct));
        var otherActor = new Actor(other.UserId, other.OrganizationId, Ip);

        var mine = await w.InviteAsync("shared@example.com");
        var theirs = await w.Run(s => s.IssueAsync(otherActor, "shared@example.com", MembershipRole.Viewer, Ct));

        Assert.NotNull(await w.Run(s => s.PreviewAsync(mine.Token, Ct)));
        Assert.NotNull(await w.Run(s => s.PreviewAsync(theirs.Token, Ct)));
    }

    [Fact]
    public async Task TheLimitOfOpenInvitations_CountsOnlyUnexpiredOnesForOtherEmails()
    {
        var w = await NewWorldAsync(new InvitationOptions { MaxPendingPerOrganization = 2 });
        await w.InviteAsync("a@example.com");
        await w.InviteAsync("b@example.com");

        await FailsAsync("TooManyInvitations", () => w.InviteAsync("c@example.com"));
        await w.InviteAsync("a@example.com");   // replacing one of the two is not a third

        w.Time.Advance(TimeSpan.FromDays(8));   // both have expired, so they no longer count
        await w.InviteAsync("c@example.com");
        await w.InviteAsync("d@example.com");
    }

    // ------------------------------------------------------------------ audit

    [Fact]
    public async Task CreationRevocationAndAcceptance_AreAudited_WithoutAnyToken()
    {
        var w = await NewWorldAsync();
        var revoked = await w.InviteAsync("revoked@example.com", MembershipRole.Viewer);
        await w.Run(s => s.RevokeAsync(w.Owner, revoked.InvitationId, Ct));
        var accepted = await w.InviteAsync("joined@example.com", MembershipRole.Analyst);
        var result = await w.Run(s => s.AcceptAsNewAccountAsync(accepted.Token, Password, "198.51.100.9", Ct));

        var entries = await w.AuditAsync();

        Assert.Equal(new[] { "invitation.created", "invitation.revoked", "invitation.created", "invitation.accepted" }, entries.Select(e => e.Action).ToArray());
        Assert.All(entries, e => Assert.Equal("Invitation", e.EntityType));
        Assert.Equal(revoked.InvitationId, entries[0].EntityId);
        Assert.Equal(w.Owner.UserId, entries[0].ActorId);
        Assert.Equal(Ip, entries[0].Ip);
        Assert.Equal("revoked@example.com", Field(entries[0], "email"));
        Assert.Equal("Viewer", Field(entries[0], "role"));
        var acceptance = entries[3];
        Assert.Equal(result.UserId, acceptance.ActorId);
        Assert.Equal("198.51.100.9", acceptance.Ip);
        Assert.Equal("True", Field(acceptance, "newAccount"));

        await using var db = w.Db.CreateDbContext();
        var everything = string.Join('\n', await db.AuditLogs.AsNoTracking().Select(a => a.Data).ToListAsync(Ct));
        foreach (var token in new[] { revoked.Token, accepted.Token })
        {
            Assert.DoesNotContain(token, everything);
            Assert.DoesNotContain(Sha256Hex(token), everything);   // not even the hash
        }
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, w.OrganizationId, Ct)).Intact);
    }

    // ------------------------------------------------------------------ revoking and listing

    [Fact]
    public async Task Revoking_EndsThePendingInvitation()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com");
        w.Time.Advance(TimeSpan.FromHours(3));

        await w.Run(s => s.RevokeAsync(w.Owner, issued.InvitationId, Ct));

        var row = Assert.Single(await w.InvitationsAsync());
        Assert.Equal(InvitationStatus.Revoked, row.Status);
        Assert.Equal(TestWorld.Start.AddHours(3), row.ResolvedAt);
        Assert.Equal(w.Owner.UserId, row.ResolvedByUserId);
        await FailsAsync("InvitationNotPending", () => w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct)));
        Assert.Null(await w.UserByEmailAsync("new@example.com"));
    }

    [Fact]
    public async Task ARevokedOrAcceptedOrUnknownInvitationCannotBeRevoked()
    {
        var w = await NewWorldAsync();
        var revoked = await w.InviteAsync("a@example.com");
        await w.Run(s => s.RevokeAsync(w.Owner, revoked.InvitationId, Ct));
        var accepted = await w.InviteAsync("b@example.com");
        await w.Run(s => s.AcceptAsNewAccountAsync(accepted.Token, Password, Ip, Ct));

        await FailsAsync("InvitationNotPending", () => w.Run(s => s.RevokeAsync(w.Owner, revoked.InvitationId, Ct)));
        await FailsAsync("InvitationNotPending", () => w.Run(s => s.RevokeAsync(w.Owner, accepted.InvitationId, Ct)));
        await FailsAsync("NotFound", () => w.Run(s => s.RevokeAsync(w.Owner, Guid.NewGuid(), Ct)));
    }

    [Fact]
    public async Task RevokingIsLimitedToManagers_AndToTheOwnOrganization()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com");
        var analyst = await w.AddMemberAsync(MembershipRole.Analyst, "analyst@example.com");
        var other = await w.Host.Run(a => a.RegisterAsync("other-owner@example.com", Password, "Other org", Ct));
        var otherActor = new Actor(other.UserId, other.OrganizationId, Ip);
        var forged = new Actor(other.UserId, w.OrganizationId, Ip);

        await FailsAsync("NotAllowed", () => w.Run(s => s.RevokeAsync(analyst, issued.InvitationId, Ct)));
        await FailsAsync("NotFound", () => w.Run(s => s.RevokeAsync(otherActor, issued.InvitationId, Ct)));   // another organization's invitation looks missing
        await FailsAsync("NotAllowed", () => w.Run(s => s.RevokeAsync(forged, issued.InvitationId, Ct)));

        Assert.Equal(InvitationStatus.Pending, Assert.Single(await w.InvitationsAsync()).Status);
    }

    [Fact]
    public async Task TheList_ShowsStates_NewestFirst_OfOneOrganizationOnly_AndNeverAToken()
    {
        var w = await NewWorldAsync();
        var pending = await w.InviteAsync("pending@example.com");
        var revoked = await w.InviteAsync("revoked@example.com");
        await w.Run(s => s.RevokeAsync(w.Owner, revoked.InvitationId, Ct));
        var accepted = await w.InviteAsync("accepted@example.com");
        await w.Run(s => s.AcceptAsNewAccountAsync(accepted.Token, Password, Ip, Ct));
        await w.InviteAsync("replaced@example.com");
        await w.InviteAsync("replaced@example.com");
        var other = await w.Host.Run(a => a.RegisterAsync("other-owner@example.com", Password, "Other org", Ct));
        await w.Run(s => s.IssueAsync(new Actor(other.UserId, other.OrganizationId, Ip), "theirs@example.com", MembershipRole.Viewer, Ct));
        w.Time.Advance(TimeSpan.FromDays(8));
        var late = await w.InviteAsync("late@example.com");

        var list = await w.Run(s => s.ListAsync(w.Owner, Ct));

        Assert.Equal(6, list.Count);   // theirs@ belongs to another organization
        Assert.Equal(late.InvitationId, list[0].Id);   // newest first
        Assert.Equal(InvitationState.Expired, list.Single(i => i.Id == pending.InvitationId).State);
        Assert.Equal(InvitationState.Revoked, list.Single(i => i.Id == revoked.InvitationId).State);
        Assert.Equal(InvitationState.Accepted, list.Single(i => i.Id == accepted.InvitationId).State);
        Assert.Equal(1, list.Count(i => i.State == InvitationState.Superseded));
        Assert.Equal(InvitationState.Pending, list[0].State);
        var json = JsonSerializer.Serialize(list);
        foreach (var token in new[] { pending.Token, revoked.Token, accepted.Token, late.Token })
            Assert.DoesNotContain(token, json);
        Assert.DoesNotContain("tokenHash", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OnlyManagersCanListInvitations()
    {
        var w = await NewWorldAsync();
        var viewer = await w.AddMemberAsync(MembershipRole.Viewer, "viewer@example.com");

        await FailsAsync("NotAllowed", () => w.Run(s => s.ListAsync(viewer, Ct)));
    }

    // ------------------------------------------------------------------ preview

    [Fact]
    public async Task Previewing_ShowsWhatTheLinkIsFor_AndChangesNothing()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com", MembershipRole.Viewer);
        await w.Host.Run(a => a.RegisterAsync("known@example.com", Password, "Known org", Ct));
        var known = await w.InviteAsync("known@example.com", MembershipRole.Analyst);
        var before = await w.InvitationsAsync();

        var preview = await w.Run(s => s.PreviewAsync(issued.Token, Ct));
        var again = await w.Run(s => s.PreviewAsync("  " + issued.Token + "  ", Ct));
        var knownPreview = await w.Run(s => s.PreviewAsync(known.Token, Ct));

        Assert.Equal(("Acme", "new@example.com", MembershipRole.Viewer, false), (preview.OrganizationName, preview.Email, preview.Role, preview.AccountExists));
        Assert.Equal(preview, again);
        Assert.True(knownPreview.AccountExists);
        Assert.Equal(before.Select(r => (r.Id, r.Status)), (await w.InvitationsAsync()).Select(r => (r.Id, r.Status)));
        Assert.Equal(2, (await w.AuditAsync()).Count);   // only the two creations: previewing writes nothing
        // ...and the invitation is still there to accept afterwards.
        await w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("definitely-not-a-real-token")]
    public async Task AnUnknownOrEmptyTokenIsInvalid(string? token)
    {
        var w = await NewWorldAsync();

        await FailsAsync("InvalidInvitation", () => w.Run(s => s.PreviewAsync(token, Ct)));
        await FailsAsync("InvalidInvitation", () => w.Run(s => s.AcceptAsNewAccountAsync(token, Password, Ip, Ct)));
        await FailsAsync("InvalidInvitation", () => w.Run(s => s.AcceptAsExistingAccountAsync(w.Owner.UserId, token, Ip, Ct)));
    }

    [Fact]
    public async Task AVeryLongTokenIsInvalid_WithoutBeingHashed()
    {
        var w = await NewWorldAsync();

        await FailsAsync("InvalidInvitation", () => w.Run(s => s.PreviewAsync(new string('a', 5000), Ct)));
    }

    [Fact]
    public async Task ATokenIsNotValidAfterItsLifetime()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com");
        w.Time.Advance(TimeSpan.FromDays(7) - TimeSpan.FromSeconds(1));
        Assert.NotNull(await w.Run(s => s.PreviewAsync(issued.Token, Ct)));

        w.Time.Advance(TimeSpan.FromSeconds(1));

        await FailsAsync("InvitationExpired", () => w.Run(s => s.PreviewAsync(issued.Token, Ct)));
    }

    // ------------------------------------------------------------------ accepting as a new person

    [Fact]
    public async Task AcceptingAsANewPerson_CreatesTheAccount_TheMembership_AndConsumesTheInvitation()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com", MembershipRole.Analyst);
        w.Time.Advance(TimeSpan.FromDays(1));

        var accepted = await w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct));

        Assert.True(accepted.NewAccount);
        Assert.Equal((w.OrganizationId, MembershipRole.Analyst), (accepted.OrganizationId, accepted.Role));
        var user = (await w.UserByEmailAsync("new@example.com"))!;
        Assert.Equal(accepted.UserId, user.Id);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.False(user.EmailConfirmed);   // holding the link does not prove the mailbox is theirs

        await using var db = w.Db.CreateDbContext();
        var membership = await db.Memberships.AsNoTracking().SingleAsync(m => m.UserId == user.Id);
        Assert.Equal((w.OrganizationId, MembershipRole.Analyst), (membership.OrganizationId, membership.Role));
        var row = await db.Invitations.AsNoTracking().SingleAsync();
        Assert.Equal(InvitationStatus.Accepted, row.Status);
        Assert.Equal(TestWorld.Start.AddDays(1), row.ResolvedAt);
        Assert.Equal(user.Id, row.ResolvedByUserId);

        // The password they chose works.
        var tokens = await w.Host.Run(a => a.LoginAsync("new@example.com", Password, Ip, Ct));
        Assert.False(string.IsNullOrEmpty(tokens.AccessToken));
    }

    [Fact]
    public async Task AWeakPassword_RollsEverythingBack_AndTheInvitationStaysUsable()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com");

        await FailsAsync("WeakPassword", () => w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, "short", Ip, Ct)));

        Assert.Null(await w.UserByEmailAsync("new@example.com"));
        Assert.Equal(InvitationStatus.Pending, Assert.Single(await w.InvitationsAsync()).Status);
        Assert.Single(await w.AuditAsync());
        await w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct));
    }

    [Fact]
    public async Task AnExpiredToken_CreatesNothing()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com");
        w.Time.Advance(TimeSpan.FromDays(7));

        await FailsAsync("InvitationExpired", () => w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct)));

        Assert.Null(await w.UserByEmailAsync("new@example.com"));
        Assert.Equal(InvitationStatus.Pending, Assert.Single(await w.InvitationsAsync()).Status);
    }

    [Fact]
    public async Task ATokenCanBeUsedOnlyOnce()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com");
        await w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct));

        await FailsAsync("InvitationNotPending", () => w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct)));
        await FailsAsync("InvitationNotPending", () => w.Run(s => s.AcceptAsExistingAccountAsync(w.Owner.UserId, issued.Token, Ip, Ct)));
        await FailsAsync("InvitationNotPending", () => w.Run(s => s.PreviewAsync(issued.Token, Ct)));

        await using var db = w.Db.CreateDbContext();
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == "new@example.com"));
        Assert.Equal(2, await db.Memberships.CountAsync(m => m.OrganizationId == w.OrganizationId));   // the owner and the one invitee
    }

    [Fact]
    public async Task IfAnAccountAlreadyExistsForTheEmail_TheNewAccountPathRefuses_AndKeepsTheInvitation()
    {
        var w = await NewWorldAsync();
        await w.Host.Run(a => a.RegisterAsync("known@example.com", Password, "Their own org", Ct));
        var issued = await w.InviteAsync("known@example.com");

        await FailsAsync("AccountExists", () => w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, "another long passphrase", Ip, Ct)));

        Assert.Equal(InvitationStatus.Pending, Assert.Single(await w.InvitationsAsync()).Status);
        // their existing password was not replaced
        await w.Host.Run(a => a.LoginAsync("known@example.com", Password, Ip, Ct));
    }

    [Fact]
    public async Task AcceptanceRechecksTheOrganizationAndTheInviter_InsideTheTransaction()
    {
        var w = await NewWorldAsync();
        var admin = await w.AddMemberAsync(MembershipRole.Admin, "admin@example.com");

        // 1. the organization is suspended after the invitation was issued
        var a = await w.InviteAsync("a@example.com");
        await w.UpdateAsync(db => db.Organizations.ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, OrganizationStatus.Suspended), Ct));
        await FailsAsync("OrganizationSuspended", () => w.Run(s => s.AcceptAsNewAccountAsync(a.Token, Password, Ip, Ct)));
        await w.UpdateAsync(db => db.Organizations.ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, OrganizationStatus.Active), Ct));

        // 2. the inviter is demoted
        var b = await w.InviteAsync("b@example.com", MembershipRole.Viewer, admin);
        await w.UpdateAsync(db => db.Memberships.Where(m => m.UserId == admin.UserId).ExecuteUpdateAsync(s => s.SetProperty(m => m.Role, MembershipRole.Viewer), Ct));
        await FailsAsync("InvitationNoLongerValid", () => w.Run(s => s.AcceptAsNewAccountAsync(b.Token, Password, Ip, Ct)));

        // 3. the inviter leaves the organization
        await w.UpdateAsync(db => db.Memberships.Where(m => m.UserId == admin.UserId).ExecuteUpdateAsync(s => s.SetProperty(m => m.Role, MembershipRole.Admin), Ct));
        var c = await w.InviteAsync("c@example.com", MembershipRole.Viewer, admin);
        await w.UpdateAsync(db => db.Memberships.Where(m => m.UserId == admin.UserId).ExecuteDeleteAsync(Ct));
        await FailsAsync("InvitationNoLongerValid", () => w.Run(s => s.AcceptAsNewAccountAsync(c.Token, Password, Ip, Ct)));

        // 4. the inviter's account is disabled
        var d = await w.InviteAsync("d@example.com", MembershipRole.Viewer);
        await w.UpdateAsync(db => db.Users.Where(u => u.Id == w.Owner.UserId).ExecuteUpdateAsync(s => s.SetProperty(u => u.Status, UserStatus.Disabled), Ct));
        await FailsAsync("InvitationNoLongerValid", () => w.Run(s => s.AcceptAsNewAccountAsync(d.Token, Password, Ip, Ct)));

        foreach (var email in new[] { "a@example.com", "b@example.com", "c@example.com", "d@example.com" })
            Assert.Null(await w.UserByEmailAsync(email));
        Assert.All((await w.InvitationsAsync()).Where(i => i.Email is "a@example.com" or "b@example.com" or "c@example.com" or "d@example.com"),
            i => Assert.Equal(InvitationStatus.Pending, i.Status));
    }

    // ------------------------------------------------------------------ accepting with an existing account

    [Fact]
    public async Task ASignedInAccountWithTheInvitedEmail_JoinsWithoutAPassword_AndItsEmailStaysAsItWas()
    {
        var w = await NewWorldAsync();
        var existing = await w.Host.Run(a => a.RegisterAsync("known@example.com", Password, "Their own org", Ct));
        var issued = await w.InviteAsync("known@example.com", MembershipRole.Viewer);
        var before = (await w.UserByEmailAsync("known@example.com"))!;

        var accepted = await w.Run(s => s.AcceptAsExistingAccountAsync(existing.UserId, issued.Token, "198.51.100.7", Ct));

        Assert.False(accepted.NewAccount);
        Assert.Equal((existing.UserId, w.OrganizationId, MembershipRole.Viewer), (accepted.UserId, accepted.OrganizationId, accepted.Role));
        await using var db = w.Db.CreateDbContext();
        Assert.True(await db.Memberships.AnyAsync(m => m.UserId == existing.UserId && m.OrganizationId == w.OrganizationId && m.Role == MembershipRole.Viewer));
        Assert.True(await db.Memberships.AnyAsync(m => m.UserId == existing.UserId && m.OrganizationId == existing.OrganizationId && m.Role == MembershipRole.Owner));   // their own organization is untouched
        Assert.Equal(InvitationStatus.Accepted, (await db.Invitations.SingleAsync()).Status);
        var user = (await w.UserByEmailAsync("known@example.com"))!;
        Assert.Equal(before.EmailConfirmed, user.EmailConfirmed);
        Assert.Equal(before.PasswordHash, user.PasswordHash);
        var entry = (await w.AuditAsync()).Last();
        Assert.Equal("invitation.accepted", entry.Action);
        Assert.Equal("False", Field(entry, "newAccount"));
        Assert.Equal("198.51.100.7", entry.Ip);
    }

    [Fact]
    public async Task ASignedInAccountWithAnotherEmail_IsRefused_AndNothingChanges()
    {
        var w = await NewWorldAsync();
        var other = await w.Host.Run(a => a.RegisterAsync("someone-else@example.com", Password, "Other org", Ct));
        var issued = await w.InviteAsync("known@example.com", MembershipRole.Viewer);

        await FailsAsync("InvitationEmailMismatch", () => w.Run(s => s.AcceptAsExistingAccountAsync(other.UserId, issued.Token, Ip, Ct)));

        await using var db = w.Db.CreateDbContext();
        Assert.False(await db.Memberships.AnyAsync(m => m.UserId == other.UserId && m.OrganizationId == w.OrganizationId));
        Assert.Equal(InvitationStatus.Pending, (await db.Invitations.SingleAsync()).Status);
    }

    [Fact]
    public async Task ADisabledOrUnknownAccountCannotAcceptWithAnExistingAccount()
    {
        var w = await NewWorldAsync();
        var existing = await w.Host.Run(a => a.RegisterAsync("known@example.com", Password, "Their own org", Ct));
        var issued = await w.InviteAsync("known@example.com");
        await w.UpdateAsync(db => db.Users.Where(u => u.Id == existing.UserId).ExecuteUpdateAsync(s => s.SetProperty(u => u.Status, UserStatus.Disabled), Ct));

        await FailsAsync("AccountDisabled", () => w.Run(s => s.AcceptAsExistingAccountAsync(existing.UserId, issued.Token, Ip, Ct)));
        await FailsAsync("Unauthorized", () => w.Run(s => s.AcceptAsExistingAccountAsync(Guid.NewGuid(), issued.Token, Ip, Ct)));
    }

    [Fact]
    public async Task AnExistingMember_CannotJoinTwice_AndTheInvitationIsNotConsumed()
    {
        var w = await NewWorldAsync();
        var member = await w.AddMemberAsync(MembershipRole.Viewer, "member@example.com");
        // Invited before they became a member: build that state directly, since issuing would now refuse.
        var token = OpaqueTokensForTests.New();
        await w.UpdateAsync(async db =>
        {
            db.Invitations.Add(new Invitation
            {
                Id = Guid.NewGuid(), OrganizationId = w.OrganizationId, Email = "member@example.com", Role = MembershipRole.Admin,
                TokenHash = Sha256Hex(token), Status = InvitationStatus.Pending, CreatedByUserId = w.Owner.UserId,
                CreatedAt = w.Time.GetUtcNow(), ExpiresAt = w.Time.GetUtcNow().AddDays(7)
            });
            await db.SaveChangesAsync(Ct);
        });

        await FailsAsync("AlreadyMember", () => w.Run(s => s.AcceptAsExistingAccountAsync(member.UserId, token, Ip, Ct)));

        await using var db = w.Db.CreateDbContext();
        Assert.Equal(MembershipRole.Viewer, (await db.Memberships.SingleAsync(m => m.UserId == member.UserId && m.OrganizationId == w.OrganizationId)).Role);   // the role did not change
        Assert.Equal(InvitationStatus.Pending, (await db.Invitations.SingleAsync()).Status);
    }

    [Fact]
    public async Task RevokedExpiredAndReusedInvitations_AreRefusedForExistingAccountsToo()
    {
        var w = await NewWorldAsync();
        var existing = await w.Host.Run(a => a.RegisterAsync("known@example.com", Password, "Their own org", Ct));
        var revoked = await w.InviteAsync("known@example.com");
        await w.Run(s => s.RevokeAsync(w.Owner, revoked.InvitationId, Ct));
        await FailsAsync("InvitationNotPending", () => w.Run(s => s.AcceptAsExistingAccountAsync(existing.UserId, revoked.Token, Ip, Ct)));

        var expiring = await w.InviteAsync("known@example.com");
        w.Time.Advance(TimeSpan.FromDays(8));
        await FailsAsync("InvitationExpired", () => w.Run(s => s.AcceptAsExistingAccountAsync(existing.UserId, expiring.Token, Ip, Ct)));
    }

    // ------------------------------------------------------------------ simultaneous acceptance

    [Fact]
    public async Task EightSimultaneousAcceptances_AsANewAccount_ProduceExactlyOneAccountAndMembership()
    {
        var w = await NewWorldAsync();
        var issued = await w.InviteAsync("new@example.com", MembershipRole.Analyst);

        var outcomes = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
        {
            try
            {
                await w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct));
                return "ok";
            }
            catch (ServiceException ex)
            {
                return ex.Code;
            }
        }));

        Assert.Single(outcomes, o => o == "ok");
        Assert.Equal(7, outcomes.Count(o => o == "InvitationNotPending"));
        await using var db = w.Db.CreateDbContext();
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == "new@example.com"));
        Assert.Equal(1, await db.Memberships.CountAsync(m => m.Role == MembershipRole.Analyst));
        Assert.Equal(InvitationStatus.Accepted, (await db.Invitations.SingleAsync()).Status);
        Assert.Single(await w.AuditAsync(), e => e.Action == "invitation.accepted");
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, w.OrganizationId, Ct)).Intact);
    }

    [Fact]
    public async Task EightSimultaneousAcceptances_WithAnExistingAccount_CreateOneMembership()
    {
        var w = await NewWorldAsync();
        var existing = await w.Host.Run(a => a.RegisterAsync("known@example.com", Password, "Their own org", Ct));
        var issued = await w.InviteAsync("known@example.com", MembershipRole.Viewer);

        var outcomes = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
        {
            try
            {
                await w.Run(s => s.AcceptAsExistingAccountAsync(existing.UserId, issued.Token, Ip, Ct));
                return "ok";
            }
            catch (ServiceException ex)
            {
                return ex.Code;
            }
        }));

        Assert.Single(outcomes, o => o == "ok");
        Assert.Equal(7, outcomes.Count(o => o == "InvitationNotPending"));
        await using var db = w.Db.CreateDbContext();
        Assert.Equal(1, await db.Memberships.CountAsync(m => m.UserId == existing.UserId && m.OrganizationId == w.OrganizationId));
    }

    [Fact]
    public async Task TwoInvitationsForTheSameNewEmail_CreateOneAccount_AndTheOtherCanJoinWithIt()
    {
        var w = await NewWorldAsync();
        var otherOwner = await w.Host.Run(a => a.RegisterAsync("other-owner@example.com", Password, "Other org", Ct));
        var otherActor = new Actor(otherOwner.UserId, otherOwner.OrganizationId, Ip);
        var mine = await w.InviteAsync("shared@example.com", MembershipRole.Viewer);
        var theirs = await w.Run(s => s.IssueAsync(otherActor, "shared@example.com", MembershipRole.Analyst, Ct));

        var outcomes = await Task.WhenAll(new[] { mine.Token, theirs.Token }.Select(async token =>
        {
            try
            {
                await w.Run(s => s.AcceptAsNewAccountAsync(token, Password, Ip, Ct));
                return "ok";
            }
            catch (ServiceException ex)
            {
                return ex.Code;
            }
        }));

        Assert.Single(outcomes, o => o == "ok");
        Assert.Single(outcomes, o => o == "AccountExists");
        var user = (await w.UserByEmailAsync("shared@example.com"))!;
        await using var db = w.Db.CreateDbContext();
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == "shared@example.com"));

        // The invitation that lost keeps working for the account that now exists.
        var losing = outcomes[0] == "ok" ? theirs.Token : mine.Token;
        var accepted = await w.Run(s => s.AcceptAsExistingAccountAsync(user.Id, losing, Ip, Ct));
        Assert.False(accepted.NewAccount);
        Assert.Equal(2, await db.Memberships.CountAsync(m => m.UserId == user.Id));
    }

    [Fact]
    public async Task AcceptingRacingARevocation_EndsInOneConsistentState()
    {
        var w = await NewWorldAsync();
        for (var i = 0; i < 6; i++)
        {
            var email = $"person{i}@example.com";
            var issued = await w.InviteAsync(email, MembershipRole.Viewer);

            var results = await Task.WhenAll(
                CodeOf(() => w.Run(s => s.AcceptAsNewAccountAsync(issued.Token, Password, Ip, Ct))),
                CodeOf(() => w.Run(s => s.RevokeAsync(w.Owner, issued.InvitationId, Ct))));

            var row = (await w.InvitationsAsync()).Single(r => r.Id == issued.InvitationId);
            var user = await w.UserByEmailAsync(email);
            if (row.Status == InvitationStatus.Accepted)
            {
                Assert.NotNull(user);
                Assert.Equal(new[] { null, "InvitationNotPending" }, results);
            }
            else
            {
                Assert.Equal(InvitationStatus.Revoked, row.Status);
                Assert.Null(user);
                Assert.Equal(new[] { "InvitationNotPending", null }, results);
            }
        }

        await using var db = w.Db.CreateDbContext();
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, w.OrganizationId, Ct)).Intact);
    }

    [Fact]
    public async Task ParallelIssuingOfTheSameEmail_LeavesExactlyOnePending()
    {
        var w = await NewWorldAsync();

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => CodeOf(() => w.InviteAsync("new@example.com"))));

        Assert.All(results, Assert.Null);   // every call succeeds: each supersedes the one before it
        var rows = await w.InvitationsAsync();
        Assert.Equal(8, rows.Count);
        Assert.Single(rows, r => r.Status == InvitationStatus.Pending);
        Assert.Equal(7, rows.Count(r => r.Status == InvitationStatus.Superseded));
    }

    [Fact]
    public async Task ParallelIssuing_CannotExceedTheLimit()
    {
        var w = await NewWorldAsync(new InvitationOptions { MaxPendingPerOrganization = 3 });

        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(i => CodeOf(() => w.InviteAsync($"person{i}@example.com"))));

        Assert.Equal(3, results.Count(r => r is null));
        Assert.Equal(7, results.Count(r => r == "TooManyInvitations"));
    }

    private static async Task<string?> CodeOf(Func<Task> call)
    {
        try
        {
            await call();
            return null;
        }
        catch (ServiceException ex)
        {
            return ex.Code;
        }
    }

    /// <summary>A token generator that does not need access to the Auth project's internals.</summary>
    private static class OpaqueTokensForTests
    {
        public static string New() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
