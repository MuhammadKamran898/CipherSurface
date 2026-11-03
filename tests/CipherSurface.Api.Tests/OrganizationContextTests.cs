using System.Net;
using CipherSurface.Data.Enums;
using CipherSurface.Services.Tests;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class OrganizationContextTests
{
    private readonly PostgresFixture _postgres;
    public OrganizationContextTests(PostgresFixture postgres) => _postgres = postgres;

    [Fact]
    public async Task WithOneMembership_NoHeaderIsNeeded_AndTheRoleComesFromTheDatabase()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (_, orgId, _) = await host.RegisterAsync("owner@example.com", "Acme");
        var tokens = await host.LoginAsync("owner@example.com");

        var org = await Check.JsonAsync(await host.GetAsync("/api/v1/organization", tokens.Access));

        Assert.Equal(orgId, org.GetProperty("organizationId").GetGuid());
        Assert.Equal("Acme", org.GetProperty("name").GetString());
        Assert.Equal("Owner", org.GetProperty("role").GetString());
        Assert.Equal("Active", org.GetProperty("status").GetString());
    }

    [Fact]
    public async Task WithSeveralMemberships_AMissingHeaderIsAnError_NotAGuess()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, _, _) = await host.RegisterAsync("owner@example.com", "First");
        var (_, otherOrg, _) = await host.RegisterAsync("other@example.com", "Second");
        await host.AddMembershipAsync(userId, otherOrg, MembershipRole.Analyst);
        var tokens = await host.LoginAsync("owner@example.com");

        var response = await host.GetAsync("/api/v1/organization", tokens.Access);

        await Check.ProblemAsync(response, HttpStatusCode.BadRequest, "OrganizationRequired");
    }

    [Fact]
    public async Task TheHeaderSelectsAmongMemberships_AndEachRoleIsTheRealOne()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, ownOrg, _) = await host.RegisterAsync("owner@example.com", "First");
        var (_, otherOrg, _) = await host.RegisterAsync("other@example.com", "Second");
        await host.AddMembershipAsync(userId, otherOrg, MembershipRole.Analyst);
        var tokens = await host.LoginAsync("owner@example.com");

        var first = await Check.JsonAsync(await host.GetAsync("/api/v1/organization", tokens.Access, ownOrg));
        var second = await Check.JsonAsync(await host.GetAsync("/api/v1/organization", tokens.Access, otherOrg));

        Assert.Equal(("First", "Owner"), (first.GetProperty("name").GetString(), first.GetProperty("role").GetString()));
        Assert.Equal(("Second", "Analyst"), (second.GetProperty("name").GetString(), second.GetProperty("role").GetString()));
    }

    [Fact]
    public async Task TheHeaderNeverGrantsAnything_AnOrganizationTheUserDoesNotBelongToIsForbidden()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com", "Mine");
        var (_, strangerOrg, _) = await host.RegisterAsync("stranger@example.com", "Not mine");
        var tokens = await host.LoginAsync("owner@example.com");

        var existing = await host.GetAsync("/api/v1/organization", tokens.Access, strangerOrg);
        var missing = await host.GetAsync("/api/v1/organization", tokens.Access, Guid.NewGuid());

        var a = await Check.ProblemAsync(existing, HttpStatusCode.Forbidden, "NotAllowed");
        var b = await Check.ProblemAsync(missing, HttpStatusCode.Forbidden, "NotAllowed");
        Assert.Equal(a.GetProperty("detail").GetString(), b.GetProperty("detail").GetString());   // does not reveal which organizations exist
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("")]
    public async Task AMalformedHeader_IsABadRequest(string value)
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");

        var response = await host.GetAsync("/api/v1/organization", tokens.Access, headers: new Dictionary<string, string> { ["X-Organization-Id"] = value });

        await Check.ProblemAsync(response, HttpStatusCode.BadRequest, "InvalidOrganizationId");
    }

    [Fact]
    public async Task TwoOrganizationHeaders_AreABadRequest()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (_, orgId, _) = await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/organization");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens.Access);
        request.Headers.TryAddWithoutValidation("X-Organization-Id", orgId.ToString("D"));
        request.Headers.TryAddWithoutValidation("X-Organization-Id", Guid.NewGuid().ToString("D"));

        var response = await host.Client.SendAsync(request);

        await Check.ProblemAsync(response, HttpStatusCode.BadRequest, "InvalidOrganizationId");
    }

    [Fact]
    public async Task ARoleChangeInTheDatabase_AppliesToTheVeryNextRequest()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, orgId, _) = await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");
        Assert.Equal("Owner", (await Check.JsonAsync(await host.GetAsync("/api/v1/organization", tokens.Access))).GetProperty("role").GetString());

        await host.SetRoleAsync(userId, orgId, MembershipRole.Viewer);

        Assert.Equal("Viewer", (await Check.JsonAsync(await host.GetAsync("/api/v1/organization", tokens.Access))).GetProperty("role").GetString());
    }

    [Fact]
    public async Task ARemovedMembership_MeansNoAccessAtOnce()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, orgId, _) = await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");

        await host.RemoveMembershipAsync(userId, orgId);

        await Check.ProblemAsync(await host.GetAsync("/api/v1/organization", tokens.Access), HttpStatusCode.Forbidden, "NoOrganization");
        await Check.ProblemAsync(await host.GetAsync("/api/v1/organization", tokens.Access, orgId), HttpStatusCode.Forbidden, "NotAllowed");
    }

    [Fact]
    public async Task Me_ListsTheMemberships_WithoutNeedingAnOrganizationHeader()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, firstOrg, _) = await host.RegisterAsync("owner@example.com", "Alpha");
        var (_, secondOrg, _) = await host.RegisterAsync("other@example.com", "Beta");
        await host.AddMembershipAsync(userId, secondOrg, MembershipRole.Viewer);
        var tokens = await host.LoginAsync("owner@example.com");

        var me = await Check.JsonAsync(await host.GetAsync("/api/v1/me", tokens.Access));

        var organizations = me.GetProperty("organizations").EnumerateArray().ToList();
        Assert.Equal(2, organizations.Count);
        Assert.Equal(new[] { firstOrg, secondOrg }, organizations.Select(o => o.GetProperty("organizationId").GetGuid()).ToArray());
        Assert.Equal(new[] { "Owner", "Viewer" }, organizations.Select(o => o.GetProperty("role").GetString()).ToArray());
        Assert.False(me.GetProperty("isPlatformAdmin").GetBoolean());
    }

    [Fact]
    public async Task ABodyCannotChooseTheOrganizationOrTheRole()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com", "Mine");
        var (_, strangerOrg, _) = await host.RegisterAsync("stranger@example.com", "Not mine");
        var tokens = await host.LoginAsync("owner@example.com");

        // Even where a body is accepted, fields naming an organization or a role are never read.
        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password",
            new { organizationId = strangerOrg, role = "Owner", currentPassword = ApiHost.Password, newPassword = "another long passphrase" }, tokens.Access);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var relogin = await host.LoginAsync("owner@example.com", "another long passphrase");
        var org = await Check.JsonAsync(await host.GetAsync("/api/v1/organization", relogin.Access));
        Assert.Equal("Mine", org.GetProperty("name").GetString());
    }
}
