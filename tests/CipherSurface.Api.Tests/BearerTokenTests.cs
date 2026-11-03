using System.Net;
using CipherSurface.Auth;
using CipherSurface.Services.Tests;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class BearerTokenTests
{
    private readonly PostgresFixture _postgres;
    public BearerTokenTests(PostgresFixture postgres) => _postgres = postgres;

    private static async Task ExpectUnauthorizedAsync(HttpResponseMessage response)
    {
        await Check.ProblemAsync(response, HttpStatusCode.Unauthorized, "Unauthorized");
        Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString());
    }

    private static (Guid UserId, Guid SessionId) Identity(Tokens tokens)
    {
        var payload = Check.Payload(tokens.Access);
        return (payload.GetProperty("sub").GetGuid(), payload.GetProperty("sid").GetGuid());
    }

    [Fact]
    public async Task AProtectedRoute_WithoutAToken_IsUnauthorized()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me"));
    }

    [Theory]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    [InlineData("Bearer not.a.jwt")]
    [InlineData("Token abc")]
    public async Task AMalformedAuthorizationHeader_IsUnauthorized(string header)
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", headers: new Dictionary<string, string> { ["Authorization"] = header }));
    }

    [Fact]
    public async Task ATokenInTheQueryString_IsIgnored()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");

        await ExpectUnauthorizedAsync(await host.GetAsync($"/api/v1/me?access_token={tokens.Access}"));
    }

    [Fact]
    public async Task AValidToken_Works()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, _, _) = await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");

        var me = await Check.JsonAsync(await host.GetAsync("/api/v1/me", tokens.Access));

        Assert.Equal(userId, me.GetProperty("userId").GetGuid());
        Assert.Equal("owner@example.com", me.GetProperty("email").GetString());
    }

    [Fact]
    public async Task AnExpiredToken_IsUnauthorized()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var (userId, sessionId) = Identity(await host.LoginAsync("owner@example.com"));
        var expired = TokenForge.Issue(host.Keys, userId, sessionId, now: DateTimeOffset.UtcNow.AddHours(-2));

        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", expired));
    }

    [Fact]
    public async Task ATokenFromAnotherIssuerOrForAnotherAudience_IsUnauthorized()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var (userId, sessionId) = Identity(await host.LoginAsync("owner@example.com"));

        var wrongIssuer = TokenForge.Issue(host.Keys, userId, sessionId, new JwtOptions { Issuer = "someone-else" });
        var wrongAudience = TokenForge.Issue(host.Keys, userId, sessionId, new JwtOptions { Audience = "another-api" });
        var correct = TokenForge.Issue(host.Keys, userId, sessionId);

        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", wrongIssuer));
        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", wrongAudience));
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/api/v1/me", correct)).StatusCode);   // proves the forged ones failed for the right reason
    }

    [Fact]
    public async Task ATokenSignedByAnotherKey_IsUnauthorized_EvenWithTheSameKeyId()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var (userId, sessionId) = Identity(await host.LoginAsync("owner@example.com"));
        var (otherKeys, _) = ApiHost.Generate(ApiHost.KeyId);

        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", TokenForge.Issue(otherKeys, userId, sessionId)));
    }

    [Fact]
    public async Task AnUnsignedToken_AndAnHmacTokenSignedWithThePublicKey_AreUnauthorized()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var (userId, sessionId) = Identity(await host.LoginAsync("owner@example.com"));

        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", TokenForge.Unsigned(userId, sessionId)));
        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", TokenForge.HmacWithPublicKey(host.Keys, userId, sessionId)));
    }

    [Fact]
    public async Task ATokenWhoseSessionNeverExisted_IsUnauthorized()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, _, _) = await host.RegisterAsync("owner@example.com");
        var forged = TokenForge.Issue(host.Keys, userId, Guid.NewGuid());   // correctly signed, but no such session

        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", forged));
    }

    [Fact]
    public async Task ADisabledAccount_LosesAccessAtOnce()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, _, _) = await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/api/v1/me", tokens.Access)).StatusCode);

        await host.DisableUserAsync(userId);

        await ExpectUnauthorizedAsync(await host.GetAsync("/api/v1/me", tokens.Access));
    }

    // ------------------------------------------------------------------ key rotation

    [Fact]
    public async Task ARetiredKey_IsTrustedOnlyWhileItsPublicKeyIsConfigured()
    {
        var (oldKeys, _) = ApiHost.Generate("key-old");
        var oldPublicFile = Path.Combine(Path.GetTempPath(), "cs-old-public-" + Guid.NewGuid().ToString("N") + ".pem");
        await File.WriteAllTextAsync(oldPublicFile, oldKeys.PublicPem);
        try
        {
            // A token issued before the rotation, signed by the old key, for a real session.
            await using var before = await ApiHost.StartAsync(_postgres);
            var (userId, _, _) = await before.RegisterAsync("owner@example.com");
            var (_, sessionId) = Identity(await before.LoginAsync("owner@example.com"));
            var oldToken = TokenForge.Issue(oldKeys, userId, sessionId);

            // After the rotation: a new key signs, the old public key is still listed for the overlap.
            await using (var overlap = await ApiHost.StartAsync(_postgres, new Dictionary<string, string?>
            {
                ["CipherSurface:Jwt:RetiredPublicKeys:0:KeyId"] = "key-old",
                ["CipherSurface:Jwt:RetiredPublicKeys:0:File"] = oldPublicFile
            }, existing: before.Database))
            {
                Assert.Equal(HttpStatusCode.OK, (await overlap.GetAsync("/api/v1/me", oldToken)).StatusCode);
                var fresh = await overlap.LoginAsync("owner@example.com");
                Assert.Equal(ApiHost.KeyId, Check.Header(fresh.Access).GetProperty("kid").GetString());   // new tokens use the new key
            }

            // Overlap over: the old key is removed from configuration and its tokens stop working.
            await using var after = await ApiHost.StartAsync(_postgres, existing: before.Database);
            await ExpectUnauthorizedAsync(await after.GetAsync("/api/v1/me", oldToken));
        }
        finally
        {
            File.Delete(oldPublicFile);
        }
    }
}
