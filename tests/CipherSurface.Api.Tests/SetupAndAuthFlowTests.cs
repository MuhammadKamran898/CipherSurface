using System.Net;
using System.Text.Json;
using CipherSurface.Services.Tests;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class SetupAndAuthFlowTests
{
    private readonly PostgresFixture _postgres;
    public SetupAndAuthFlowTests(PostgresFixture postgres) => _postgres = postgres;

    private static readonly object ValidSetup = new { email = "owner@example.com", password = ApiHost.Password, organizationName = "Acme" };
    private static IReadOnlyDictionary<string, string> Token(string value) => new Dictionary<string, string> { ["X-Setup-Token"] = value };

    // ------------------------------------------------------------------ setup (the only way an account is created here)

    [Fact]
    public async Task Setup_IsDisabled_WhenNoSetupTokenIsConfigured()
    {
        await using var host = await ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:Setup:Token"] = null });

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner", ValidSetup, headers: Token(ApiHost.SetupToken));

        await Check.ProblemAsync(response, HttpStatusCode.NotFound, "SetupDisabled");
        Assert.Equal(0, await host.UserCountAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("wrong-token-wrong-token-wrong-token-1")]
    public async Task Setup_RejectsAMissingOrWrongToken_AndCreatesNothing(string? token)
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner", ValidSetup, headers: token is null ? null : Token(token));

        await Check.ProblemAsync(response, HttpStatusCode.Forbidden, "SetupTokenInvalid");
        Assert.Equal(0, await host.UserCountAsync());
    }

    [Fact]
    public async Task Setup_CreatesTheFirstOwner_ThenCloses()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var first = await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner", ValidSetup, headers: Token(ApiHost.SetupToken));
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var created = JsonDocument.Parse(await first.Content.ReadAsStringAsync()).RootElement;
        Assert.NotEqual(Guid.Empty, created.GetProperty("userId").GetGuid());
        Assert.NotEqual(Guid.Empty, created.GetProperty("organizationId").GetGuid());

        var second = await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner",
            new { email = "second@example.com", password = ApiHost.Password, organizationName = "Other" }, headers: Token(ApiHost.SetupToken));
        await Check.ProblemAsync(second, HttpStatusCode.Conflict, "SetupClosed");
        Assert.Equal(1, await host.UserCountAsync());

        // The owner can sign in, and setup was recorded in the organization's audit chain.
        await host.LoginAsync("owner@example.com");
        await using var db = host.Database.CreateDbContext();
        var audit = await db.AuditLogs.SingleAsync(a => a.Action == "organization.created");
        Assert.Contains("first-owner", audit.Data);
    }

    [Fact]
    public async Task Setup_CannotBeRaced_OnlyOneCallWins()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(i =>
            host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner",
                new { email = $"owner{i}@example.com", password = ApiHost.Password, organizationName = $"Org {i}" }, headers: Token(ApiHost.SetupToken))));

        Assert.Single(results, r => r.StatusCode == HttpStatusCode.Created);
        Assert.Equal(5, results.Count(r => r.StatusCode == HttpStatusCode.Conflict));
        Assert.Equal(1, await host.UserCountAsync());
    }

    [Fact]
    public async Task Setup_WithAWeakPassword_IsRejected_AndLeavesSetupOpen()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var weak = await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner",
            new { email = "owner@example.com", password = "short", organizationName = "Acme" }, headers: Token(ApiHost.SetupToken));
        await Check.ProblemAsync(weak, HttpStatusCode.BadRequest, "WeakPassword");
        Assert.Equal(0, await host.UserCountAsync());

        var good = await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner", ValidSetup, headers: Token(ApiHost.SetupToken));
        Assert.Equal(HttpStatusCode.Created, good.StatusCode);
    }

    [Theory]
    [InlineData("not-an-email", "EmailInvalid")]
    [InlineData("", "EmailInvalid")]
    public async Task Setup_RejectsAnInvalidEmail(string email, string code)
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner",
            new { email, password = ApiHost.Password, organizationName = "Acme" }, headers: Token(ApiHost.SetupToken));

        await Check.ProblemAsync(response, HttpStatusCode.BadRequest, code);
    }

    [Theory]
    [InlineData("/api/v1/auth/register")]
    [InlineData("/api/v1/register")]
    [InlineData("/api/v1/users")]
    public async Task ThereIsNoPublicRegistration(string path)
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await host.SendAsync(HttpMethod.Post, path, new { email = "x@example.com", password = ApiHost.Password, organizationName = "X" });

        await Check.ProblemAsync(response, HttpStatusCode.NotFound, "NotFound");
        Assert.Equal(0, await host.UserCountAsync());
    }

    // ------------------------------------------------------------------ login

    [Fact]
    public async Task Login_ReturnsSignedTokens_WithAKeyIdAndNoRolesInTheToken()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");

        var tokens = await host.LoginAsync("owner@example.com");

        var header = Check.Header(tokens.Access);
        Assert.Equal("RS256", header.GetProperty("alg").GetString());
        Assert.Equal(ApiHost.KeyId, header.GetProperty("kid").GetString());
        var claims = Check.Payload(tokens.Access).EnumerateObject().Select(p => p.Name).ToHashSet();
        Assert.Superset(new HashSet<string> { "sub", "sid", "email", "exp", "iss", "aud" }, claims);
        Assert.DoesNotContain("role", claims);
        Assert.DoesNotContain("org", claims);
        Assert.DoesNotContain("organization", claims);
        Assert.False(string.IsNullOrWhiteSpace(tokens.Refresh));
        Assert.DoesNotContain('.', tokens.Refresh);   // opaque, not a JWT
    }

    [Fact]
    public async Task Login_GivesTheSameAnswer_ForAWrongPasswordAndAnUnknownEmail()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");

        var wrong = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "owner@example.com", password = "not the password at all" });
        var unknown = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "nobody@example.com", password = "not the password at all" });

        var a = await Check.ProblemAsync(wrong, HttpStatusCode.Unauthorized, "InvalidCredentials");
        var b = await Check.ProblemAsync(unknown, HttpStatusCode.Unauthorized, "InvalidCredentials");
        Assert.Equal(a.GetProperty("detail").GetString(), b.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Login_LocksTheAccountAfterFiveFailures_EvenForTheRightPassword()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");

        for (var i = 0; i < 4; i++)
            await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "owner@example.com", password = "wrong password here" }),
                HttpStatusCode.Unauthorized, "InvalidCredentials");
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "owner@example.com", password = "wrong password here" }),
            HttpStatusCode.TooManyRequests, "AccountLockedOut");

        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "owner@example.com", password = ApiHost.Password }),
            HttpStatusCode.TooManyRequests, "AccountLockedOut");
    }

    [Fact]
    public async Task Login_OfADisabledAccount_IsForbidden()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (userId, _, _) = await host.RegisterAsync("owner@example.com");
        await host.DisableUserAsync(userId);

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "owner@example.com", password = ApiHost.Password });

        await Check.ProblemAsync(response, HttpStatusCode.Forbidden, "AccountDisabled");
    }

    // ------------------------------------------------------------------ refresh and logout

    [Fact]
    public async Task Refresh_RotatesTheToken_AndReuseOfAnOldOneEndsTheWholeSession()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var first = await host.LoginAsync("owner@example.com");

        var rotated = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh", new { refreshToken = first.Refresh });
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var second = await ApiHost.ReadTokensAsync(rotated);
        Assert.NotEqual(first.Refresh, second.Refresh);
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/api/v1/me", second.Access)).StatusCode);

        // Presenting the old refresh token again looks like theft: the whole session is ended.
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh", new { refreshToken = first.Refresh }),
            HttpStatusCode.Unauthorized, "InvalidRefreshToken");
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh", new { refreshToken = second.Refresh }),
            HttpStatusCode.Unauthorized, "InvalidRefreshToken");
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync("/api/v1/me", second.Access)).StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-real-refresh-token")]
    public async Task Refresh_RejectsAMissingOrUnknownToken(string? token)
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh", new { refreshToken = token });

        await Check.ProblemAsync(response, HttpStatusCode.Unauthorized, "InvalidRefreshToken");
    }

    [Fact]
    public async Task Logout_EndsTheSessionAtOnce_NotWhenTheAccessTokenExpires()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/api/v1/me", tokens.Access)).StatusCode);

        var logout = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/logout", new { refreshToken = tokens.Refresh });

        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        await Check.ProblemAsync(await host.GetAsync("/api/v1/me", tokens.Access), HttpStatusCode.Unauthorized, "Unauthorized");
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh", new { refreshToken = tokens.Refresh }),
            HttpStatusCode.Unauthorized, "InvalidRefreshToken");
    }

    [Fact]
    public async Task Logout_WithAnUnknownToken_SucceedsQuietly()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/logout", new { refreshToken = "never-issued" });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Logout_EndsOnlyThatSession()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var phone = await host.LoginAsync("owner@example.com");
        var laptop = await host.LoginAsync("owner@example.com");

        await host.SendAsync(HttpMethod.Post, "/api/v1/auth/logout", new { refreshToken = phone.Refresh });

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync("/api/v1/me", phone.Access)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/api/v1/me", laptop.Access)).StatusCode);
    }

    // ------------------------------------------------------------------ change password

    [Fact]
    public async Task ChangePassword_EndsEverySession_AndTheNewPasswordWorks()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var phone = await host.LoginAsync("owner@example.com");
        var laptop = await host.LoginAsync("owner@example.com");
        const string newPassword = "an entirely new passphrase";

        var change = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password",
            new { currentPassword = ApiHost.Password, newPassword }, laptop.Access);

        Assert.Equal(HttpStatusCode.NoContent, change.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync("/api/v1/me", phone.Access)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync("/api/v1/me", laptop.Access)).StatusCode);
        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email = "owner@example.com", password = ApiHost.Password }),
            HttpStatusCode.Unauthorized, "InvalidCredentials");
        await host.LoginAsync("owner@example.com", newPassword);
    }

    [Fact]
    public async Task ChangePassword_WithAWrongCurrentPassword_IsABadRequest_NotAnExpiredSession()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password",
            new { currentPassword = "definitely not it", newPassword = "an entirely new passphrase" }, tokens.Access);

        await Check.ProblemAsync(response, HttpStatusCode.BadRequest, "CurrentPasswordIncorrect");
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync("/api/v1/me", tokens.Access)).StatusCode);   // session untouched
    }

    [Fact]
    public async Task ChangePassword_WithAWeakNewPassword_IsRejected()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.RegisterAsync("owner@example.com");
        var tokens = await host.LoginAsync("owner@example.com");

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password",
            new { currentPassword = ApiHost.Password, newPassword = "short" }, tokens.Access);

        await Check.ProblemAsync(response, HttpStatusCode.BadRequest, "WeakPassword");
    }

    [Fact]
    public async Task ChangePassword_RequiresALogin()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password",
            new { currentPassword = ApiHost.Password, newPassword = "an entirely new passphrase" });

        await Check.ProblemAsync(response, HttpStatusCode.Unauthorized, "Unauthorized");
    }

    [Fact]
    public async Task ChangePassword_NeverActsOnAUserIdFromTheBody()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var (victimId, _, _) = await host.RegisterAsync("victim@example.com", "Victim org");
        await host.RegisterAsync("attacker@example.com", "Attacker org");
        var attacker = await host.LoginAsync("attacker@example.com");

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password",
            new { userId = victimId, email = "victim@example.com", currentPassword = ApiHost.Password, newPassword = "attacker chosen password" }, attacker.Access);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);   // it changed the ATTACKER's own password
        await host.LoginAsync("victim@example.com");                    // the victim is untouched
        await host.LoginAsync("attacker@example.com", "attacker chosen password");
    }

    [Fact]
    public async Task NoSecretEverReachesTheLogs()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await host.SendAsync(HttpMethod.Post, "/api/v1/setup/owner", ValidSetup, headers: Token(ApiHost.SetupToken));
        var tokens = await host.LoginAsync("owner@example.com");
        await host.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password", new { currentPassword = "wrong wrong wrong!", newPassword = "brand new passphrase" }, tokens.Access);
        await host.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh", new { refreshToken = tokens.Refresh });

        var log = string.Join('\n', host.Logs.Lines);
        Assert.DoesNotContain(ApiHost.SetupToken, log);
        Assert.DoesNotContain(ApiHost.Password, log);
        Assert.DoesNotContain(tokens.Access, log);
        Assert.DoesNotContain(tokens.Refresh, log);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", log);
    }
}
