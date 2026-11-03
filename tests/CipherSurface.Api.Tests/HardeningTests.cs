using System.Net;
using CipherSurface.Api.Security;
using CipherSurface.Services.Tests;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class HardeningTests
{
    private readonly PostgresFixture _postgres;
    public HardeningTests(PostgresFixture postgres) => _postgres = postgres;

    private static void MapIpRoute(WebApplication app) =>
        app.MapGet("/test/ip", (HttpContext http) => ClientIp.Of(http)).AllowAnonymous();

    private static IReadOnlyDictionary<string, string?> Limits(int auth, int global = 100000) => new Dictionary<string, string?>
    {
        ["CipherSurface:RateLimiting:AuthRequestsPerMinute"] = auth.ToString(),
        ["CipherSurface:RateLimiting:GlobalRequestsPerMinute"] = global.ToString()
    };

    private static Dictionary<string, string?> Proxy(IReadOnlyDictionary<string, string?> baseSettings)
    {
        var copy = new Dictionary<string, string?>(baseSettings) { ["CipherSurface:ForwardedHeaders:KnownProxies:0"] = "127.0.0.1" };
        return copy;
    }

    private static Task<HttpResponseMessage> BadLoginAsync(ApiHost host, string? forwardedFor = null) =>
        host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "nobody@example.com", password = "wrong wrong wrong" },
            headers: forwardedFor is null ? null : new Dictionary<string, string> { ["X-Forwarded-For"] = forwardedFor });

    // ------------------------------------------------------------------ rate limiting

    [Fact]
    public async Task AuthEndpoints_AreRateLimitedPerClient_WithRetryAfter()
    {
        await using var host = await ApiHost.StartAsync(_postgres, Limits(auth: 3));

        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await BadLoginAsync(host)).StatusCode);
        var limited = await BadLoginAsync(host);

        await Check.ProblemAsync(limited, HttpStatusCode.TooManyRequests, "RateLimited");
        Assert.True(limited.Headers.RetryAfter is not null);
    }

    [Fact]
    public async Task TheAuthLimit_AlsoCoversRefreshSetupAndChangePassword()
    {
        await using var host = await ApiHost.StartAsync(_postgres, Limits(auth: 2));

        // The limit is per client and shared by the auth endpoints, so three different calls exhaust it.
        await host.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh", new { refreshToken = "x" });
        await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner", new { email = "a@example.com", password = "x", organizationName = "x" });
        var limited = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/logout", new { refreshToken = "x" });

        await Check.ProblemAsync(limited, HttpStatusCode.TooManyRequests, "RateLimited");
    }

    [Fact]
    public async Task TheGlobalLimit_AppliesToEveryRoute()
    {
        await using var host = await ApiHost.StartAsync(_postgres, Limits(auth: 1000, global: 5), MapIpRoute);

        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/test/ip")).StatusCode);

        await Check.ProblemAsync(await host.GetAsync("/test/ip"), HttpStatusCode.TooManyRequests, "RateLimited");
    }

    [Fact]
    public async Task AnUntrustedForwardedForHeader_CannotBeUsedToEvadeTheLimit()
    {
        await using var host = await ApiHost.StartAsync(_postgres, Limits(auth: 3));

        for (var i = 0; i < 3; i++)
            await BadLoginAsync(host, forwardedFor: $"203.0.113.{i + 1}");
        var limited = await BadLoginAsync(host, forwardedFor: "203.0.113.200");

        await Check.ProblemAsync(limited, HttpStatusCode.TooManyRequests, "RateLimited");
    }

    [Fact]
    public async Task BehindATrustedProxy_EachRealClientHasItsOwnLimit()
    {
        await using var host = await ApiHost.StartAsync(_postgres, Proxy(Limits(auth: 2)));

        await BadLoginAsync(host, "203.0.113.1");
        await BadLoginAsync(host, "203.0.113.1");
        await Check.ProblemAsync(await BadLoginAsync(host, "203.0.113.1"), HttpStatusCode.TooManyRequests, "RateLimited");

        Assert.Equal(HttpStatusCode.Unauthorized, (await BadLoginAsync(host, "203.0.113.2")).StatusCode);   // a different client is unaffected
    }

    // ------------------------------------------------------------------ forwarded headers

    [Fact]
    public async Task ForwardedHeaders_AreIgnored_WhenNoProxyIsConfigured()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapIpRoute);

        var ip = await (await host.GetAsync("/test/ip", headers: new Dictionary<string, string> { ["X-Forwarded-For"] = "203.0.113.7" })).Content.ReadAsStringAsync();

        Assert.Equal("127.0.0.1", ip);
    }

    [Fact]
    public async Task ForwardedHeaders_AreTrusted_OnlyFromAConfiguredProxy()
    {
        await using var host = await ApiHost.StartAsync(_postgres, Proxy(new Dictionary<string, string?>()), MapIpRoute);

        var ip = await (await host.GetAsync("/test/ip", headers: new Dictionary<string, string> { ["X-Forwarded-For"] = "203.0.113.7" })).Content.ReadAsStringAsync();

        Assert.Equal("203.0.113.7", ip);
    }

    [Fact]
    public async Task AClientCannotSpoofItsAddress_ByPrependingToTheForwardedChain()
    {
        await using var host = await ApiHost.StartAsync(_postgres, Proxy(new Dictionary<string, string?>()), MapIpRoute);

        // The proxy appends the real client address at the end; whatever the client put in front is not trusted.
        var ip = await (await host.GetAsync("/test/ip", headers: new Dictionary<string, string> { ["X-Forwarded-For"] = "1.1.1.1, 203.0.113.7" })).Content.ReadAsStringAsync();

        Assert.Equal("203.0.113.7", ip);
    }

    // ------------------------------------------------------------------ CORS

    [Fact]
    public async Task WithNoOriginsConfigured_NoCrossOriginAccessIsGranted()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var simple = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "a@example.com", password = "x" },
            headers: new Dictionary<string, string> { ["Origin"] = "https://evil.example" });
        var preflight = await Preflight(host, "https://evil.example");

        Assert.False(simple.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(preflight.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task ACofiguredOrigin_GetsAStrictPreflightAnswer()
    {
        await using var host = await ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:Cors:AllowedOrigins:0"] = "https://app.example.com" });

        var response = await Preflight(host, "https://app.example.com");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal("https://app.example.com", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        var allowedHeaders = string.Join(",", response.Headers.GetValues("Access-Control-Allow-Headers")).ToLowerInvariant();
        Assert.Contains("authorization", allowedHeaders);
        Assert.Contains("x-organization-id", allowedHeaders);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
        Assert.DoesNotContain("*", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
    }

    [Fact]
    public async Task AnOriginThatIsNotListed_IsRefused_EvenWhenAnotherOneIsAllowed()
    {
        await using var host = await ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:Cors:AllowedOrigins:0"] = "https://app.example.com" });

        var response = await Preflight(host, "https://evil.example");

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Theory]
    [InlineData("*")]
    [InlineData("https://*.example.com")]
    [InlineData("https://app.example.com/path")]
    [InlineData("app.example.com")]
    [InlineData("ftp://app.example.com")]
    public async Task AWildcardOrMalformedOrigin_StopsTheApiFromStarting(string origin)
    {
        var ex = await Assert.ThrowsAsync<CipherSurface.Api.Configuration.ApiConfigurationException>(() =>
            ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:Cors:AllowedOrigins:0"] = origin }));

        Assert.Contains("Cors", ex.Message);
    }

    private static Task<HttpResponseMessage> Preflight(ApiHost host, string origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Options, "/api/v1/auth/login");
        request.Headers.Add("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "authorization,content-type,x-organization-id");
        return host.Client.SendAsync(request);
    }

    // ------------------------------------------------------------------ response headers

    [Fact]
    public async Task Responses_AreNeverCached_AndCarryBasicSecurityHeaders_AndNoServerHeader()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await BadLoginAsync(host);

        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.False(response.Headers.Contains("Server"));
    }
}
