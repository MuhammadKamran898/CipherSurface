using System.Net;
using CipherSurface.Api.Security;
using CipherSurface.Data.Enums;
using CipherSurface.Services.Tests;
using Xunit;

namespace CipherSurface.Api.Tests;

/// <summary>A handler that declares an OrganizationContext parameter gets it resolved, checked and built on the server.</summary>
[Collection("postgres")]
public class OrganizationContextBindingTests
{
    private readonly PostgresFixture _postgres;
    public OrganizationContextBindingTests(PostgresFixture postgres) => _postgres = postgres;

    private static void MapContextRoutes(WebApplication app)
    {
        app.MapGet("/test/context", (OrganizationContext org) =>
            Results.Ok(new { org.Actor.OrganizationId, org.Actor.UserId, org.Actor.Ip, org.OrganizationName, Role = org.Role.ToString() })).RequireAuthorization();
        app.MapGet("/test/context-anonymous", (OrganizationContext org) => Results.Ok()).AllowAnonymous();
    }

    [Fact]
    public async Task AParameterIsResolvedFromTheTokenAndTheDatabase()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapContextRoutes);
        var (userId, orgId, _) = await host.RegisterAsync("owner@example.com", "Acme");
        var tokens = await host.LoginAsync("owner@example.com");

        var context = await Check.JsonAsync(await host.GetAsync("/test/context", tokens.Access));

        Assert.Equal(orgId, context.GetProperty("organizationId").GetGuid());
        Assert.Equal(userId, context.GetProperty("userId").GetGuid());
        Assert.Equal("127.0.0.1", context.GetProperty("ip").GetString());
        Assert.Equal("Acme", context.GetProperty("organizationName").GetString());
        Assert.Equal("Owner", context.GetProperty("role").GetString());
    }

    [Fact]
    public async Task TheHeaderSelectsAmongMemberships_AndIsNeverGuessed()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapContextRoutes);
        var (userId, ownOrg, _) = await host.RegisterAsync("owner@example.com", "First");
        var (_, otherOrg, _) = await host.RegisterAsync("other@example.com", "Second");
        await host.AddMembershipAsync(userId, otherOrg, MembershipRole.Analyst);
        var tokens = await host.LoginAsync("owner@example.com");

        await Check.ProblemAsync(await host.GetAsync("/test/context", tokens.Access), HttpStatusCode.BadRequest, "OrganizationRequired");
        Assert.Equal("Analyst", (await Check.JsonAsync(await host.GetAsync("/test/context", tokens.Access, otherOrg))).GetProperty("role").GetString());
        Assert.Equal("Owner", (await Check.JsonAsync(await host.GetAsync("/test/context", tokens.Access, ownOrg))).GetProperty("role").GetString());
    }

    [Fact]
    public async Task ANonMemberIsForbidden_AndAnAccountWithoutMembershipHasNoOrganization()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapContextRoutes);
        var (userId, orgId, _) = await host.RegisterAsync("owner@example.com", "Mine");
        var (_, strangerOrg, _) = await host.RegisterAsync("stranger@example.com", "Not mine");
        var tokens = await host.LoginAsync("owner@example.com");

        await Check.ProblemAsync(await host.GetAsync("/test/context", tokens.Access, strangerOrg), HttpStatusCode.Forbidden, "NotAllowed");

        await host.RemoveMembershipAsync(userId, orgId);
        await Check.ProblemAsync(await host.GetAsync("/test/context", tokens.Access), HttpStatusCode.Forbidden, "NoOrganization");
    }

    [Fact]
    public async Task AnAnonymousEndpoint_CannotGetAContext()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapContextRoutes);
        await host.RegisterAsync("owner@example.com");

        await Check.ProblemAsync(await host.GetAsync("/test/context-anonymous"), HttpStatusCode.Unauthorized, "Unauthorized");
    }

    [Fact]
    public async Task TheRoleIsReadFromTheDatabaseOnEveryRequest()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapContextRoutes);
        var (userId, orgId, _) = await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");
        Assert.Equal("Owner", (await Check.JsonAsync(await host.GetAsync("/test/context", tokens.Access))).GetProperty("role").GetString());

        await host.SetRoleAsync(userId, orgId, MembershipRole.Viewer);

        Assert.Equal("Viewer", (await Check.JsonAsync(await host.GetAsync("/test/context", tokens.Access))).GetProperty("role").GetString());
    }
}
