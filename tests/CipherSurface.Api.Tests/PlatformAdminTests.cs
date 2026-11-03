using System.Net;
using CipherSurface.Api.Configuration;
using CipherSurface.Api.Security;
using CipherSurface.Services.Tests;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class PlatformAdminTests
{
    private readonly PostgresFixture _postgres;
    public PlatformAdminTests(PostgresFixture postgres) => _postgres = postgres;

    private static void MapAdminRoute(WebApplication app) =>
        app.MapGet("/test/admin", () => Results.Ok("admin area")).RequireAuthorization(ApiPolicies.PlatformAdmin);

    /// <summary>Creates two accounts on one host, then restarts the API with the first one on the allowlist.</summary>
    private async Task<(ApiHost Host, Guid AdminId, Guid OrdinaryId)> StartWithAdminAsync(Func<Guid, string?> allowlist)
    {
        await using var setup = await ApiHost.StartAsync(_postgres);
        var (adminId, _, _) = await setup.RegisterAsync("admin@example.com", "Admin org");
        var (ordinaryId, _, _) = await setup.RegisterAsync("user@example.com", "User org");

        var settings = new Dictionary<string, string?>();
        if (allowlist(adminId) is { } entry) settings["CipherSurface:PlatformAdmins:UserIds:0"] = entry;
        var host = await ApiHost.StartAsync(_postgres, settings, MapAdminRoute, existing: setup.Database);
        return (host, adminId, ordinaryId);
    }

    [Fact]
    public async Task AnAllowlistedUser_PassesThePolicy_AndIsReportedAsAdmin()
    {
        var (host, _, _) = await StartWithAdminAsync(id => id.ToString("D"));
        await using var _ = host;
        var tokens = await host.LoginAsync("admin@example.com");

        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/test/admin", tokens.Access)).StatusCode);
        Assert.True((await Check.JsonAsync(await host.GetAsync("/api/v1/me", tokens.Access))).GetProperty("isPlatformAdmin").GetBoolean());
    }

    [Fact]
    public async Task AnyoneNotOnTheAllowlist_IsForbidden()
    {
        var (host, _, _) = await StartWithAdminAsync(id => id.ToString("D"));
        await using var _ = host;
        var tokens = await host.LoginAsync("user@example.com");

        await Check.ProblemAsync(await host.GetAsync("/test/admin", tokens.Access), HttpStatusCode.Forbidden, "Forbidden");
        Assert.False((await Check.JsonAsync(await host.GetAsync("/api/v1/me", tokens.Access))).GetProperty("isPlatformAdmin").GetBoolean());
    }

    [Fact]
    public async Task WithoutALogin_ThePolicyIsUnauthorized()
    {
        var (host, _, _) = await StartWithAdminAsync(id => id.ToString("D"));
        await using var _ = host;

        await Check.ProblemAsync(await host.GetAsync("/test/admin"), HttpStatusCode.Unauthorized, "Unauthorized");
    }

    [Fact]
    public async Task AnAdminIdSuppliedByTheCaller_ChangesNothing()
    {
        var (host, adminId, _) = await StartWithAdminAsync(id => id.ToString("D"));
        await using var _ = host;
        var tokens = await host.LoginAsync("user@example.com");

        var response = await host.GetAsync($"/test/admin?userId={adminId}", tokens.Access, headers: new Dictionary<string, string>
        {
            ["X-User-Id"] = adminId.ToString("D"),
            ["X-Platform-Admin"] = "true"
        });

        await Check.ProblemAsync(response, HttpStatusCode.Forbidden, "Forbidden");
    }

    [Fact]
    public async Task WithNoAllowlistConfigured_NobodyIsAnAdmin()
    {
        var (host, _, _) = await StartWithAdminAsync(_ => null);
        await using var _ = host;

        foreach (var email in new[] { "admin@example.com", "user@example.com" })
        {
            var tokens = await host.LoginAsync(email);
            await Check.ProblemAsync(await host.GetAsync("/test/admin", tokens.Access), HttpStatusCode.Forbidden, "Forbidden");
        }
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("")]
    public async Task AnInvalidAllowlistEntry_StopsTheApiFromStarting(string entry)
    {
        var ex = await Assert.ThrowsAsync<ApiConfigurationException>(() =>
            ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:PlatformAdmins:UserIds:0"] = entry }));

        Assert.Contains("PlatformAdmins", ex.Message);
    }

    [Fact]
    public async Task ADisabledAdmin_IsNoLongerAuthenticated_SoTheAllowlistCannotHelpThem()
    {
        var (host, adminId, _) = await StartWithAdminAsync(id => id.ToString("D"));
        await using var _ = host;
        var tokens = await host.LoginAsync("admin@example.com");

        await host.DisableUserAsync(adminId);

        await Check.ProblemAsync(await host.GetAsync("/test/admin", tokens.Access), HttpStatusCode.Unauthorized, "Unauthorized");
    }
}
