using System.Net;
using System.Text.Json;
using CipherSurface.Data.Enums;
using CipherSurface.Services.Tests;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class InvitationEndpointTests
{
    private const string AcceptBase = "https://app.example.com/accept-invitation";
    private readonly PostgresFixture _postgres;
    public InvitationEndpointTests(PostgresFixture postgres) => _postgres = postgres;

    private static IReadOnlyDictionary<string, string?> WithLink() => new Dictionary<string, string?> { ["CipherSurface:Invitations:AcceptBaseUrl"] = AcceptBase };

    /// <summary>A host with an organization owner who is signed in.</summary>
    private async Task<(ApiHost Host, Tokens Owner, Guid OrganizationId, Guid OwnerId)> StartAsync(
        IReadOnlyDictionary<string, string?>? settings = null, TimeProvider? time = null)
    {
        var host = await ApiHost.StartAsync(_postgres, settings, time: time);
        var (ownerId, orgId, _) = await host.RegisterAsync("owner@example.com", "Acme");
        return (host, await host.LoginAsync("owner@example.com"), orgId, ownerId);
    }

    private static Task<HttpResponseMessage> Preview(ApiHost host, string? token) =>
        host.SendAsync(HttpMethod.Post, "/api/v1/invitations/preview", new { token });

    private static Task<HttpResponseMessage> AcceptNew(ApiHost host, string? token, string? password = ApiHost.Password) =>
        host.SendAsync(HttpMethod.Post, "/api/v1/invitations/accept", new { token, password });

    private static Task<HttpResponseMessage> AcceptExisting(ApiHost host, string? token, string? bearer) =>
        host.SendAsync(HttpMethod.Post, "/api/v1/invitations/accept/existing", new { token }, bearer);

    // ------------------------------------------------------------------ issuing

    [Fact]
    public async Task AnOwnerInvites_AndReceivesTheTokenAndALink_Once()
    {
        var (host, owner, orgId, _) = await StartAsync(WithLink());
        await using var _ = host;

        var invited = await host.InviteAsync(owner.Access, "New.Person@Example.com", "analyst");

        Assert.Equal("new.person@example.com", invited.Body.GetProperty("email").GetString());
        Assert.Equal("Analyst", invited.Body.GetProperty("role").GetString());
        Assert.True(invited.Body.GetProperty("expiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddDays(6));
        Assert.Equal($"{AcceptBase}#token={invited.Token}", invited.Link);   // the token sits after '#', which browsers never send to a server

        // Never again: the list has no token, and the database has only its hash.
        var list = await host.GetAsync("/api/v1/invitations", owner.Access);
        var text = await list.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        Assert.DoesNotContain(invited.Token, text);
        Assert.DoesNotContain("token", text, StringComparison.OrdinalIgnoreCase);
        await using var db = host.Database.CreateDbContext();
        var row = await db.Invitations.SingleAsync();
        Assert.NotEqual(invited.Token, row.TokenHash);
        Assert.Equal(64, row.TokenHash.Length);
        Assert.Equal(orgId, row.OrganizationId);
    }

    [Fact]
    public async Task WithoutAConfiguredBaseUrl_NoLinkIsMade_ButTheTokenStillIs()
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;

        var invited = await host.InviteAsync(owner.Access, "new@example.com");

        Assert.Null(invited.Link);
        Assert.False(string.IsNullOrEmpty(invited.Token));
    }

    [Fact]
    public async Task OnlyOwnersAndAdminsInvite_AndAnonymousCallersCannot()
    {
        var (host, _, orgId, _) = await StartAsync();
        await using var _ = host;
        var (adminId, _, _) = await host.RegisterAsync("admin@example.com", "Admin org");
        var (analystId, _, _) = await host.RegisterAsync("analyst@example.com", "Analyst org");
        await host.AddMembershipAsync(adminId, orgId, MembershipRole.Admin);
        await host.AddMembershipAsync(analystId, orgId, MembershipRole.Analyst);
        var admin = await host.LoginAsync("admin@example.com");
        var analyst = await host.LoginAsync("analyst@example.com");

        Assert.Equal(HttpStatusCode.Created, (await host.SendAsync(HttpMethod.Post, "/api/v1/invitations", new { email = "a@example.com", role = "Viewer" }, admin.Access, orgId)).StatusCode);
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/invitations", new { email = "b@example.com", role = "Viewer" }, analyst.Access, orgId), HttpStatusCode.Forbidden, "NotAllowed");
        await Check.ProblemAsync(await host.GetAsync("/api/v1/invitations", analyst.Access, orgId), HttpStatusCode.Forbidden, "NotAllowed");
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/invitations", new { email = "c@example.com", role = "Viewer" }), HttpStatusCode.Unauthorized, "Unauthorized");
        await Check.ProblemAsync(await host.GetAsync("/api/v1/invitations"), HttpStatusCode.Unauthorized, "Unauthorized");
    }

    [Fact]
    public async Task TheOrganizationHeaderChoosesWhereTheInvitationIsIssued()
    {
        var (host, _, ownOrg, ownerId) = await StartAsync();
        await using var _ = host;
        var (_, otherOrg, _) = await host.RegisterAsync("other@example.com", "Other org");
        await host.AddMembershipAsync(ownerId, otherOrg, MembershipRole.Admin);
        var owner = await host.LoginAsync("owner@example.com");

        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/invitations", new { email = "a@example.com", role = "Viewer" }, owner.Access),
            HttpStatusCode.BadRequest, "OrganizationRequired");
        await host.InviteAsync(owner.Access, "a@example.com", "Viewer", otherOrg);

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(otherOrg, (await db.Invitations.SingleAsync()).OrganizationId);
        Assert.NotEqual(ownOrg, otherOrg);
    }

    [Theory]
    [InlineData("Owner")]
    [InlineData("owner")]
    [InlineData("")]
    [InlineData("1")]
    [InlineData("Root")]
    [InlineData(null)]
    public async Task OwnerAndUnknownRolesAreRefused(string? role)
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/invitations", new { email = "a@example.com", role }, owner.Access);

        await Check.ProblemAsync(response, HttpStatusCode.BadRequest, "InvalidRole");
        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.Invitations);
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("")]
    public async Task AnInvalidEmailIsRefused(string email)
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;

        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/invitations", new { email, role = "Viewer" }, owner.Access), HttpStatusCode.BadRequest, "EmailInvalid");
    }

    [Fact]
    public async Task InvitingAnExistingMemberIsAConflict_AndTheLimitIsEnforced()
    {
        var (host, owner, orgId, _) = await StartAsync(new Dictionary<string, string?> { ["CipherSurface:Invitations:MaxPendingPerOrganization"] = "2" });
        await using var _ = host;
        var (memberId, _, _) = await host.RegisterAsync("member@example.com", "Member org");
        await host.AddMembershipAsync(memberId, orgId, MembershipRole.Viewer);

        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/invitations", new { email = "member@example.com", role = "Viewer" }, owner.Access), HttpStatusCode.Conflict, "AlreadyMember");
        await host.InviteAsync(owner.Access, "a@example.com");
        await host.InviteAsync(owner.Access, "b@example.com");
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/invitations", new { email = "c@example.com", role = "Viewer" }, owner.Access), HttpStatusCode.Conflict, "TooManyInvitations");
    }

    [Fact]
    public async Task IssuingAgainSupersedesTheEarlierToken()
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;
        var first = await host.InviteAsync(owner.Access, "new@example.com", "Viewer");
        var second = await host.InviteAsync(owner.Access, "new@example.com", "Admin");

        await Check.ProblemAsync(await Preview(host, first.Token), HttpStatusCode.Conflict, "InvitationNotPending");
        var preview = await Check.JsonAsync(await Preview(host, second.Token));
        Assert.Equal("Admin", preview.GetProperty("role").GetString());

        var states = (await Check.JsonAsync(await host.GetAsync("/api/v1/invitations", owner.Access))).EnumerateArray().Select(i => i.GetProperty("state").GetString()).Order().ToArray();
        Assert.Equal(new[] { "Pending", "Superseded" }, states);
    }

    // ------------------------------------------------------------------ opening the link never consumes it

    [Fact]
    public async Task OpeningTheLinkIsAPreview_ItNeverConsumesAnything_AndNothingAcceptsOnGet()
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;
        var invited = await host.InviteAsync(owner.Access, "new@example.com", "Viewer");

        var first = await Check.JsonAsync(await Preview(host, invited.Token));
        var second = await Check.JsonAsync(await Preview(host, invited.Token));

        Assert.Equal("Acme", first.GetProperty("organizationName").GetString());
        Assert.Equal("new@example.com", first.GetProperty("email").GetString());
        Assert.Equal("Viewer", first.GetProperty("role").GetString());
        Assert.False(first.GetProperty("accountExists").GetBoolean());
        Assert.Equal(first.GetRawText(), second.GetRawText());

        // No GET route reads a token, in the path or the query string.
        foreach (var path in new[] { "/api/v1/invitations/preview", "/api/v1/invitations/accept", $"/api/v1/invitations/accept?token={invited.Token}", $"/api/v1/invitations/preview?token={invited.Token}" })
            Assert.True((await host.GetAsync(path)).StatusCode is HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotFound or HttpStatusCode.Unauthorized, path);

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(InvitationStatus.Pending, (await db.Invitations.SingleAsync()).Status);
        Assert.Equal(0, await db.Users.CountAsync(u => u.Email == "new@example.com"));
        Assert.Equal(HttpStatusCode.Created, (await AcceptNew(host, invited.Token)).StatusCode);   // and it is still there to accept
    }

    // ------------------------------------------------------------------ accepting as a new person

    [Fact]
    public async Task ANewPersonAccepts_ChoosesAPassword_AndIsNotSignedInOrVerified()
    {
        var (host, owner, orgId, _) = await StartAsync();
        await using var _ = host;
        var invited = await host.InviteAsync(owner.Access, "new@example.com", "Analyst");

        var response = await AcceptNew(host, invited.Token, "my own chosen passphrase");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(orgId, body.GetProperty("organizationId").GetGuid());
        Assert.Equal("Analyst", body.GetProperty("role").GetString());
        Assert.True(body.GetProperty("newAccount").GetBoolean());
        Assert.False(body.TryGetProperty("accessToken", out var access));   // accepting does not sign anyone in
        Assert.False(body.TryGetProperty("refreshToken", out var refresh));

        var tokens = await host.LoginAsync("new@example.com", "my own chosen passphrase");
        var org = await Check.JsonAsync(await host.GetAsync("/api/v1/organization", tokens.Access));
        Assert.Equal(("Acme", "Analyst"), (org.GetProperty("name").GetString(), org.GetProperty("role").GetString()));
        await using var db = host.Database.CreateDbContext();
        Assert.False((await db.Users.SingleAsync(u => u.Email == "new@example.com")).EmailConfirmed);
    }

    [Fact]
    public async Task ATokenWorksOnce_AndAWeakPasswordDoesNotBurnIt()
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;
        var invited = await host.InviteAsync(owner.Access, "new@example.com");

        await Check.ProblemAsync(await AcceptNew(host, invited.Token, "short"), HttpStatusCode.BadRequest, "WeakPassword");
        Assert.Equal(HttpStatusCode.Created, (await AcceptNew(host, invited.Token)).StatusCode);
        await Check.ProblemAsync(await AcceptNew(host, invited.Token), HttpStatusCode.Conflict, "InvitationNotPending");
        await Check.ProblemAsync(await Preview(host, invited.Token), HttpStatusCode.Conflict, "InvitationNotPending");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("never-issued")]
    public async Task AnUnknownTokenIsNotFound_OnEveryEndpoint(string? token)
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;

        await Check.ProblemAsync(await Preview(host, token), HttpStatusCode.NotFound, "InvalidInvitation");
        await Check.ProblemAsync(await AcceptNew(host, token), HttpStatusCode.NotFound, "InvalidInvitation");
        await Check.ProblemAsync(await AcceptExisting(host, token, owner.Access), HttpStatusCode.NotFound, "InvalidInvitation");
    }

    [Fact]
    public async Task AnExpiredInvitationIsGone()
    {
        var time = new AdjustableTime(DateTimeOffset.UtcNow);
        var (host, owner, _, _) = await StartAsync(time: time);
        await using var _ = host;
        var invited = await host.InviteAsync(owner.Access, "new@example.com");

        time.Advance(TimeSpan.FromDays(7) + TimeSpan.FromMinutes(1));

        await Check.ProblemAsync(await Preview(host, invited.Token), HttpStatusCode.Gone, "InvitationExpired");
        await Check.ProblemAsync(await AcceptNew(host, invited.Token), HttpStatusCode.Gone, "InvitationExpired");
        await using var db = host.Database.CreateDbContext();
        Assert.Equal(0, await db.Users.CountAsync(u => u.Email == "new@example.com"));
    }

    [Fact]
    public async Task ACustomLifetimeIsUsed()
    {
        var time = new AdjustableTime(DateTimeOffset.UtcNow);
        var (host, owner, _, _) = await StartAsync(new Dictionary<string, string?> { ["CipherSurface:Invitations:LifetimeDays"] = "2" }, time);
        await using var _ = host;
        var invited = await host.InviteAsync(owner.Access, "new@example.com");
        Assert.InRange((invited.Body.GetProperty("expiresAt").GetDateTimeOffset() - time.GetUtcNow()).TotalHours, 47.9, 48.1);

        time.Advance(TimeSpan.FromDays(2) + TimeSpan.FromMinutes(1));

        await Check.ProblemAsync(await Preview(host, invited.Token), HttpStatusCode.Gone, "InvitationExpired");
    }

    [Fact]
    public async Task IfTheInviterLosesTheirRole_TheInvitationNoLongerWorks()
    {
        var (host, _, orgId, _) = await StartAsync();
        await using var _ = host;
        var (adminId, _, _) = await host.RegisterAsync("admin@example.com", "Admin org");
        await host.AddMembershipAsync(adminId, orgId, MembershipRole.Admin);
        var admin = await host.LoginAsync("admin@example.com");
        var invited = await host.InviteAsync(admin.Access, "new@example.com", "Viewer", orgId);

        await host.SetRoleAsync(adminId, orgId, MembershipRole.Viewer);

        await Check.ProblemAsync(await AcceptNew(host, invited.Token), HttpStatusCode.Conflict, "InvitationNoLongerValid");
    }

    // ------------------------------------------------------------------ accepting with an existing account

    [Fact]
    public async Task ASignedInAccountWithTheInvitedEmailJoins()
    {
        var (host, owner, orgId, _) = await StartAsync();
        await using var _ = host;
        await host.RegisterAsync("known@example.com", "Known org");
        var invited = await host.InviteAsync(owner.Access, "Known@Example.com", "Viewer");
        Assert.True((await Check.JsonAsync(await Preview(host, invited.Token))).GetProperty("accountExists").GetBoolean());
        await Check.ProblemAsync(await AcceptNew(host, invited.Token, "an entirely different pass"), HttpStatusCode.Conflict, "AccountExists");
        var known = await host.LoginAsync("known@example.com");

        var accepted = await Check.JsonAsync(await AcceptExisting(host, invited.Token, known.Access));

        Assert.False(accepted.GetProperty("newAccount").GetBoolean());
        Assert.Equal(orgId, accepted.GetProperty("organizationId").GetGuid());
        var me = await Check.JsonAsync(await host.GetAsync("/api/v1/me", known.Access));
        Assert.Equal(2, me.GetProperty("organizations").GetArrayLength());
        var org = await Check.JsonAsync(await host.GetAsync("/api/v1/organization", known.Access, orgId));
        Assert.Equal("Viewer", org.GetProperty("role").GetString());
        await Check.ProblemAsync(await AcceptExisting(host, invited.Token, known.Access), HttpStatusCode.Conflict, "InvitationNotPending");
    }

    [Fact]
    public async Task AccountsWithAnotherEmailAndAnonymousCallersCannotAcceptAsAnExistingAccount()
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;
        await host.RegisterAsync("someone-else@example.com", "Other org");
        var invited = await host.InviteAsync(owner.Access, "known@example.com", "Viewer");
        var other = await host.LoginAsync("someone-else@example.com");

        await Check.ProblemAsync(await AcceptExisting(host, invited.Token, other.Access), HttpStatusCode.Forbidden, "InvitationEmailMismatch");
        await Check.ProblemAsync(await AcceptExisting(host, invited.Token, null), HttpStatusCode.Unauthorized, "Unauthorized");
        // the owner of the organization cannot accept for the invitee either
        await Check.ProblemAsync(await AcceptExisting(host, invited.Token, owner.Access), HttpStatusCode.Forbidden, "InvitationEmailMismatch");
        Assert.Equal("Pending", (await Check.JsonAsync(await host.GetAsync("/api/v1/invitations", owner.Access))).EnumerateArray().Single().GetProperty("state").GetString());
    }

    // ------------------------------------------------------------------ revoking

    [Fact]
    public async Task ARevokedInvitationStopsWorking_AndOnlyOwnManagersCanRevoke()
    {
        var (host, owner, orgId, _) = await StartAsync();
        await using var _ = host;
        var (analystId, _, _) = await host.RegisterAsync("analyst@example.com", "Analyst org");
        await host.AddMembershipAsync(analystId, orgId, MembershipRole.Analyst);
        var analyst = await host.LoginAsync("analyst@example.com");
        var (_, _, _) = await host.RegisterAsync("stranger@example.com", "Stranger org");
        var stranger = await host.LoginAsync("stranger@example.com");
        var invited = await host.InviteAsync(owner.Access, "new@example.com");

        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Delete, $"/api/v1/invitations/{invited.Id}", null, analyst.Access, orgId), HttpStatusCode.Forbidden, "NotAllowed");
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Delete, $"/api/v1/invitations/{invited.Id}", null, stranger.Access), HttpStatusCode.NotFound, "NotFound");
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Delete, $"/api/v1/invitations/{Guid.NewGuid()}", null, owner.Access), HttpStatusCode.NotFound, "NotFound");
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Delete, $"/api/v1/invitations/{invited.Id}"), HttpStatusCode.Unauthorized, "Unauthorized");

        Assert.Equal(HttpStatusCode.NoContent, (await host.SendAsync(HttpMethod.Delete, $"/api/v1/invitations/{invited.Id}", null, owner.Access)).StatusCode);

        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Delete, $"/api/v1/invitations/{invited.Id}", null, owner.Access), HttpStatusCode.Conflict, "InvitationNotPending");
        await Check.ProblemAsync(await AcceptNew(host, invited.Token), HttpStatusCode.Conflict, "InvitationNotPending");
        Assert.Equal("Revoked", (await Check.JsonAsync(await host.GetAsync("/api/v1/invitations", owner.Access))).EnumerateArray().Single().GetProperty("state").GetString());
    }

    // ------------------------------------------------------------------ concurrency, rate limits, secrecy

    [Fact]
    public async Task SixSimultaneousAcceptances_CreateOneAccount()
    {
        var (host, owner, _, _) = await StartAsync();
        await using var _ = host;
        var invited = await host.InviteAsync(owner.Access, "new@example.com", "Viewer");

        var responses = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => AcceptNew(host, invited.Token)));

        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Created);
        Assert.Equal(5, responses.Count(r => r.StatusCode == HttpStatusCode.Conflict));
        await using var db = host.Database.CreateDbContext();
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == "new@example.com"));
        Assert.Equal(1, await db.Memberships.CountAsync(m => m.Role == MembershipRole.Viewer));
    }

    [Fact]
    public async Task PreviewAndAcceptAreRateLimited_SeparatelyFromLogin()
    {
        var (host, owner, _, _) = await StartAsync(new Dictionary<string, string?> { ["CipherSurface:RateLimiting:InvitationRequestsPerMinute"] = "3" });
        await using var _ = host;

        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.NotFound, (await Preview(host, "never-issued")).StatusCode);
        var limited = await Preview(host, "never-issued");

        await Check.ProblemAsync(limited, HttpStatusCode.TooManyRequests, "RateLimited");
        Assert.NotNull(limited.Headers.RetryAfter);
        await Check.ProblemAsync(await AcceptNew(host, "never-issued"), HttpStatusCode.TooManyRequests, "RateLimited");
        await Check.ProblemAsync(await AcceptExisting(host, "never-issued", owner.Access), HttpStatusCode.TooManyRequests, "RateLimited");
        // logging in is a different limit
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "owner@example.com", password = ApiHost.Password })).StatusCode);
    }

    [Fact]
    public async Task TheTokenNeverReachesTheLogs_TheAuditTrail_OrAnyLaterResponse()
    {
        var (host, owner, orgId, _) = await StartAsync(WithLink());
        await using var _ = host;
        var invited = await host.InviteAsync(owner.Access, "new@example.com", "Analyst");
        await Preview(host, invited.Token);
        await AcceptNew(host, invited.Token, "my own chosen passphrase");
        await AcceptNew(host, invited.Token);   // a failed attempt with the used token
        await host.GetAsync("/api/v1/invitations", owner.Access);

        var log = string.Join('\n', host.Logs.Lines);
        Assert.DoesNotContain(invited.Token, log);
        Assert.DoesNotContain("my own chosen passphrase", log);
        await using var db = host.Database.CreateDbContext();
        var audits = string.Join('\n', await db.AuditLogs.Where(a => a.OrganizationId == orgId).Select(a => a.Data).ToListAsync());
        Assert.DoesNotContain(invited.Token, audits);
        Assert.Contains("invitation.accepted", string.Join('\n', await db.AuditLogs.Select(a => a.Action).ToListAsync()));
    }

    [Fact]
    public async Task ThereIsStillNoWayToRegisterWithoutAnInvitation()
    {
        var (host, _, _, _) = await StartAsync();
        await using var _ = host;

        await Check.ProblemAsync(await AcceptNew(host, "guessed-token"), HttpStatusCode.NotFound, "InvalidInvitation");
        Assert.Equal(1, await host.UserCountAsync());
    }
}
