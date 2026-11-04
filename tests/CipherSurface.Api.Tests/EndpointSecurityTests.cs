using CipherSurface.Services.Tests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class EndpointSecurityTests
{
    private readonly PostgresFixture _postgres;
    public EndpointSecurityTests(PostgresFixture postgres) => _postgres = postgres;

    /// <summary>The complete list of endpoints that may be called without logging in. Adding one here is a deliberate decision.</summary>
    private static readonly string[] AnonymousEndpoints =
    [
        "POST /api/v1/auth/login",
        "POST /api/v1/auth/logout",
        "POST /api/v1/auth/refresh",
        "POST /api/v1/invitations/accept",
        "POST /api/v1/invitations/preview",
        "POST /api/v1/setup/owner"
    ];

    private static string Describe(Microsoft.AspNetCore.Routing.RouteEndpoint endpoint)
    {
        var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods ?? [];
        return $"{string.Join(",", methods)} /{endpoint.RoutePattern.RawText!.TrimStart('/')}";
    }

    [Fact]
    public async Task EveryApiEndpoint_RequiresALogin_ExceptTheListedAnonymousOnes()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var api = host.Endpoints.Where(e => e.RoutePattern.RawText!.StartsWith("/api/", StringComparison.Ordinal)).ToList();
        Assert.True(api.Count >= 13, $"Expected the auth, setup, me and organization endpoints; found {api.Count}.");

        var anonymous = api.Where(e => e.Metadata.GetMetadata<IAllowAnonymous>() is not null).Select(Describe).Order().ToArray();
        Assert.Equal(AnonymousEndpoints, anonymous);

        var unprotected = api.Where(e => e.Metadata.GetMetadata<IAllowAnonymous>() is null && !e.Metadata.GetOrderedMetadata<IAuthorizeData>().Any()).Select(Describe).ToList();
        Assert.True(unprotected.Count == 0, "These API endpoints require no login and are not on the anonymous list: " + string.Join("; ", unprotected));
    }
}
