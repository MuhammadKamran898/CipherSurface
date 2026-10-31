using CipherSurface.Auth;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class AuthTests
{
    private const string Password = "correct horse battery staple";
    private const string Ip = "203.0.113.50";
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly PostgresFixture _postgres;
    public AuthTests(PostgresFixture postgres) => _postgres = postgres;

    private async Task<(TestDatabase Db, AuthHost Host)> Setup()
    {
        var db = await _postgres.CreateDatabaseAsync();
        return (db, AuthHost.Create(db));
    }

    private static Task<RegistrationResult> Register(AuthHost host, string email = "owner@example.com", string password = Password, string org = "Bright Cart") =>
        host.Run(a => a.RegisterAsync(email, password, org, Ct));

    private static Task<AuthTokens> Login(AuthHost host, string email = "owner@example.com", string password = Password) =>
        host.Run(a => a.LoginAsync(email, password, Ip, Ct));

    private static Task<AuthTokens> Refresh(AuthHost host, string? token) => host.Run(a => a.RefreshAsync(token, Ip, Ct));

    private static async Task<ServiceException> Fails(Func<Task> call) => await Assert.ThrowsAsync<ServiceException>(call);

    // ------------------------------------------------------------------ registration

    [Fact]
    public async Task Register_CreatesTheUser_TheOrganization_AndTheOwnerMembership_WithAHashedPassword()
    {
        var (db, host) = await Setup();

        var result = await Register(host, "  Owner@Example.COM ", Password, "  Bright Cart  ");

        await using var ctx = db.CreateDbContext();
        var user = await ctx.Users.SingleAsync(u => u.Id == result.UserId);
        Assert.Equal("owner@example.com", user.Email);
        Assert.Equal("owner@example.com", user.UserName);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.False(string.IsNullOrEmpty(user.PasswordHash));
        Assert.DoesNotContain(Password, user.PasswordHash);

        var org = await ctx.Organizations.SingleAsync(o => o.Id == result.OrganizationId);
        Assert.Equal("Bright Cart", org.Name);
        Assert.Equal(OrganizationStatus.Active, org.Status);
        var membership = await ctx.Memberships.SingleAsync(m => m.UserId == result.UserId);
        Assert.Equal(MembershipRole.Owner, membership.Role);
        Assert.Equal(org.Id, membership.OrganizationId);

        Assert.Contains("organization.created", await ctx.AuditLogs.Where(a => a.OrganizationId == org.Id).Select(a => a.Action).ToListAsync());
        Assert.True((await new AuditChainVerifier().VerifyAsync(ctx, org.Id, Ct)).Intact);
    }

    [Fact]
    public async Task Register_SameEmailTwice_IsRejected_IgnoringCase_AndCreatesNothingExtra()
    {
        var (db, host) = await Setup();
        await Register(host, "owner@example.com");

        var ex = await Fails(() => Register(host, "OWNER@example.com", Password, "Other Org"));

        Assert.Equal("EmailTaken", ex.Code);
        await using var ctx = db.CreateDbContext();
        Assert.Equal(1, await ctx.Organizations.CountAsync());
        Assert.Equal(1, await ctx.Users.CountAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-an-email")]
    [InlineData("a@b")]
    [InlineData("Name <a@b.com>")]
    [InlineData("x@@y.com")]
    public async Task Register_InvalidEmails_AreRejected(string email)
    {
        var (_, host) = await Setup();
        var ex = await Fails(() => Register(host, email));
        Assert.Equal("EmailInvalid", ex.Code);
    }

    [Fact]
    public async Task Register_RejectsWeakPasswordsAndBadOrganizationNames_WithoutLeavingAnythingBehind()
    {
        var (db, host) = await Setup();

        Assert.Equal("WeakPassword", (await Fails(() => Register(host, password: "short"))).Code);
        Assert.Equal("WeakPassword", (await Fails(() => Register(host, password: "elevenchars"))).Code);   // 11 characters
        Assert.Equal("OrganizationNameRequired", (await Fails(() => Register(host, org: "   "))).Code);
        Assert.Equal("OrganizationNameTooLong", (await Fails(() => Register(host, org: new string('x', 201)))).Code);

        await using var ctx = db.CreateDbContext();
        Assert.Equal(0, await ctx.Users.CountAsync());
        Assert.Equal(0, await ctx.Organizations.CountAsync());
        Assert.Equal(0, await ctx.Memberships.CountAsync());
    }

    // ------------------------------------------------------------------ login and the access token

    [Fact]
    public async Task Login_ReturnsAValidRs256Token_ThatCarriesNoRolesOrPrivileges_AndAHashedRefreshToken()
    {
        var (db, host) = await Setup();
        var registered = await Register(host);

        var tokens = await Login(host, "OWNER@example.com");

        var validated = await host.Tokens.ValidateAsync(tokens.AccessToken);
        Assert.NotNull(validated);
        Assert.Equal(registered.UserId, validated!.UserId);
        Assert.Equal("owner@example.com", validated.Email);
        Assert.NotEqual(Guid.Empty, validated.SessionId);
        Assert.Equal(TestWorld.Start.AddMinutes(15), tokens.AccessTokenExpiresAt);

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(tokens.AccessToken);
        Assert.Equal("RS256", jwt.Alg);
        Assert.Equal("ciphersurface", jwt.Issuer);
        var claimTypes = jwt.Claims.Select(c => c.Type).ToList();
        Assert.Equal(new[] { "aud", "email", "exp", "iat", "iss", "jti", "nbf", "sid", "sub" }, claimTypes.OrderBy(t => t).Distinct());
        Assert.DoesNotContain(claimTypes, t => t.Contains("role", StringComparison.OrdinalIgnoreCase) || t.Contains("admin", StringComparison.OrdinalIgnoreCase));

        await using var ctx = db.CreateDbContext();
        var stored = await ctx.RefreshTokens.SingleAsync();
        Assert.Equal(RefreshTokenService.Hash(tokens.RefreshToken), stored.TokenHash);
        Assert.NotEqual(tokens.RefreshToken, stored.TokenHash);
        Assert.Equal(64, stored.TokenHash.Length);
        Assert.Equal(TestWorld.Start.AddDays(14), stored.ExpiresAt);
        Assert.Equal(Ip, stored.CreatedByIp);
    }

    [Fact]
    public async Task Login_WrongPasswordAndUnknownEmail_LookExactlyTheSame()
    {
        var (_, host) = await Setup();
        await Register(host);

        Assert.Equal("InvalidCredentials", (await Fails(() => Login(host, password: "this is not the password"))).Code);
        Assert.Equal("InvalidCredentials", (await Fails(() => Login(host, "nobody@example.com"))).Code);
        Assert.Equal("InvalidCredentials", (await Fails(() => Login(host, "", ""))).Code);
    }

    [Fact]
    public async Task FiveWrongPasswords_LockTheAccount_EvenForTheRightPassword()
    {
        var (_, host) = await Setup();
        await Register(host);

        for (var i = 0; i < 4; i++)
            Assert.Equal("InvalidCredentials", (await Fails(() => Login(host, password: "wrong password " + i))).Code);
        Assert.Equal("AccountLockedOut", (await Fails(() => Login(host, password: "wrong password 5"))).Code);
        Assert.Equal("AccountLockedOut", (await Fails(() => Login(host))).Code);
    }

    [Fact]
    public async Task DisabledAccount_CannotLogIn_ButTheErrorNeverRevealsItToSomeoneWithoutThePassword()
    {
        var (db, host) = await Setup();
        var registered = await Register(host);
        await SetStatus(db, registered.UserId, UserStatus.Disabled);

        Assert.Equal("AccountDisabled", (await Fails(() => Login(host))).Code);
        Assert.Equal("InvalidCredentials", (await Fails(() => Login(host, password: "this is not the password"))).Code);
    }

    private static async Task SetStatus(TestDatabase db, Guid userId, UserStatus status)
    {
        await using var ctx = db.CreateDbContext();
        var user = await ctx.Users.SingleAsync(u => u.Id == userId);
        user.Status = status;
        await ctx.SaveChangesAsync();
    }

    // ------------------------------------------------------------------ validating tokens

    [Fact]
    public async Task AccessToken_IsValidForFifteenMinutes_ByTheInjectedClock()
    {
        var (_, host) = await Setup();
        await Register(host);
        var tokens = await Login(host);

        host.Time.Advance(TimeSpan.FromMinutes(14));
        Assert.NotNull(await host.Tokens.ValidateAsync(tokens.AccessToken));

        host.Time.Advance(TimeSpan.FromMinutes(2));   // 16 minutes
        Assert.Null(await host.Tokens.ValidateAsync(tokens.AccessToken));
    }

    [Fact]
    public async Task ForgedOrUnsuitableTokens_AreRejected()
    {
        var (db, host) = await Setup();
        await Register(host);
        var tokens = await Login(host);
        var parts = tokens.AccessToken.Split('.');

        // changed payload
        var tampered = parts[0] + "." + parts[1][..^2] + (parts[1][^2] == 'A' ? "B" : "A") + parts[1][^1] + "." + parts[2];
        Assert.Null(await host.Tokens.ValidateAsync(tampered));

        // "alg: none" with the real payload
        string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.Null(await host.Tokens.ValidateAsync(B64("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + parts[1] + "."));

        // signed by someone else's key
        var stranger = new AccessTokenService(host.Options, TokenKeys.Generate("test-key").Keys, host.Time);
        Assert.Null(await stranger.ValidateAsync(tokens.AccessToken));

        // meant for another audience or issuer
        Assert.Null(await new AccessTokenService(host.Options with { Audience = "another-api" }, host.Keys, host.Time).ValidateAsync(tokens.AccessToken));
        Assert.Null(await new AccessTokenService(host.Options with { Issuer = "someone-else" }, host.Keys, host.Time).ValidateAsync(tokens.AccessToken));

        Assert.Null(await host.Tokens.ValidateAsync(null));
        Assert.Null(await host.Tokens.ValidateAsync(""));
        Assert.Null(await host.Tokens.ValidateAsync("not.a.token"));
    }

    [Fact]
    public async Task APublicKeyAlone_ValidatesTokens_ButCanNeverIssueThem()
    {
        var (_, host) = await Setup();
        await Register(host);
        var tokens = await Login(host);
        var validateOnly = new AccessTokenService(host.Options, TokenKeys.FromPublicPem(host.Keys.PublicPem, "test-key"), host.Time);

        Assert.NotNull(await validateOnly.ValidateAsync(tokens.AccessToken));
        Assert.Throws<InvalidOperationException>(() => validateOnly.Issue(new CipherSurface.Data.Entities.User { Id = Guid.NewGuid(), Email = "a@b.com" }, Guid.NewGuid()));
    }

    [Fact]
    public void WeakRsaKeys_AreRefused()
    {
        using var weak = RSA.Create(1024);
        Assert.Throws<ArgumentException>(() => TokenKeys.FromPrivatePem(weak.ExportPkcs8PrivateKeyPem(), "weak"));
        Assert.Throws<ArgumentException>(() => TokenKeys.FromPublicPem(weak.ExportSubjectPublicKeyInfoPem(), "weak"));
    }

    // ------------------------------------------------------------------ refresh, logout, password change

    [Fact]
    public async Task Refresh_RotatesTheToken_AndKeepsTheSession()
    {
        var (db, host) = await Setup();
        await Register(host);
        var first = await Login(host);
        host.Time.Advance(TimeSpan.FromMinutes(20));

        var second = await Refresh(host, first.RefreshToken);

        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        var before = await host.Tokens.ValidateAsync(first.AccessToken);   // expired by now
        Assert.Null(before);
        var after = await host.Tokens.ValidateAsync(second.AccessToken);
        Assert.NotNull(after);

        await using var ctx = db.CreateDbContext();
        var rows = await ctx.RefreshTokens.OrderBy(t => t.CreatedAt).ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.Equal(rows[0].FamilyId, rows[1].FamilyId);
        Assert.Equal(after!.SessionId, rows[0].FamilyId);
        Assert.Equal("Rotated", rows[0].RevokedReason);
        Assert.Equal(rows[1].Id, rows[0].ReplacedByTokenId);
        Assert.Null(rows[1].RevokedAt);
    }

    [Fact]
    public async Task ReusingARotatedToken_RevokesTheWholeSession()
    {
        var (db, host) = await Setup();
        await Register(host);
        var first = await Login(host);
        var second = await Refresh(host, first.RefreshToken);

        Assert.Equal("InvalidRefreshToken", (await Fails(() => Refresh(host, first.RefreshToken))).Code);   // the old token comes back
        Assert.Equal("InvalidRefreshToken", (await Fails(() => Refresh(host, second.RefreshToken))).Code);  // so the newest one is dead too

        await using var ctx = db.CreateDbContext();
        Assert.All(await ctx.RefreshTokens.ToListAsync(), t => Assert.NotNull(t.RevokedAt));
        Assert.Contains(await ctx.RefreshTokens.ToListAsync(), t => t.RevokedReason == "ReuseDetected");
    }

    [Fact]
    public async Task RefreshToken_ExpiresAfterFourteenDays()
    {
        var (_, host) = await Setup();
        await Register(host);
        var tokens = await Login(host);

        host.Time.Advance(TimeSpan.FromDays(14) + TimeSpan.FromSeconds(1));

        Assert.Equal("InvalidRefreshToken", (await Fails(() => Refresh(host, tokens.RefreshToken))).Code);
    }

    [Fact]
    public async Task Logout_EndsTheSession_AndIsHarmlessWhenRepeatedOrGivenGarbage()
    {
        var (_, host) = await Setup();
        await Register(host);
        var tokens = await Login(host);

        await host.Run(a => a.LogoutAsync(tokens.RefreshToken, Ct));
        await host.Run(a => a.LogoutAsync(tokens.RefreshToken, Ct));
        await host.Run(a => a.LogoutAsync("garbage", Ct));
        await host.Run(a => a.LogoutAsync(null, Ct));

        Assert.Equal("InvalidRefreshToken", (await Fails(() => Refresh(host, tokens.RefreshToken))).Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("definitely-not-a-token")]
    public async Task Refresh_WithGarbage_IsAnOrdinaryInvalidRefreshToken(string? token)
    {
        var (_, host) = await Setup();
        Assert.Equal("InvalidRefreshToken", (await Fails(() => Refresh(host, token))).Code);
    }

    [Fact]
    public async Task ChangingThePassword_EndsEverySession_AndTheOldPasswordStopsWorking()
    {
        var (_, host) = await Setup();
        var registered = await Register(host);
        var tokens = await Login(host);
        var otherDevice = await Login(host);
        const string newPassword = "another long passphrase 42";

        Assert.Equal("InvalidCredentials", (await Fails(() => host.Run(a => a.ChangePasswordAsync(registered.UserId, "wrong current password", newPassword, Ct)))).Code);
        Assert.Equal("WeakPassword", (await Fails(() => host.Run(a => a.ChangePasswordAsync(registered.UserId, Password, "short", Ct)))).Code);

        await host.Run(a => a.ChangePasswordAsync(registered.UserId, Password, newPassword, Ct));

        Assert.Equal("InvalidRefreshToken", (await Fails(() => Refresh(host, tokens.RefreshToken))).Code);
        Assert.Equal("InvalidRefreshToken", (await Fails(() => Refresh(host, otherDevice.RefreshToken))).Code);
        Assert.Equal("InvalidCredentials", (await Fails(() => Login(host))).Code);
        Assert.NotNull(await Login(host, password: newPassword));
    }

    [Fact]
    public async Task AccountDisabledAfterLogin_CannotRefresh_AndTheSessionIsClosed()
    {
        var (db, host) = await Setup();
        var registered = await Register(host);
        var tokens = await Login(host);
        await SetStatus(db, registered.UserId, UserStatus.Disabled);

        Assert.Equal("InvalidRefreshToken", (await Fails(() => Refresh(host, tokens.RefreshToken))).Code);

        await using var ctx = db.CreateDbContext();
        Assert.All(await ctx.RefreshTokens.ToListAsync(), t => Assert.NotNull(t.RevokedAt));
    }

    [Fact]
    public async Task TwoSimultaneousRefreshes_OfOneToken_CannotBothSucceed()
    {
        var (_, host) = await Setup();
        await Register(host);
        var tokens = await Login(host);

        var errors = await Task.WhenAll(
            Refresh(host, tokens.RefreshToken).ContinueWith(t => t.Exception?.GetBaseException()),
            Refresh(host, tokens.RefreshToken).ContinueWith(t => t.Exception?.GetBaseException()));

        Assert.Equal(1, errors.Count(e => e is null));
        Assert.All(errors.Where(e => e is not null), e => Assert.Equal("InvalidRefreshToken", Assert.IsType<ServiceException>(e).Code));
    }

    // ------------------------------------------------------------------ the database rules

    [Fact]
    public async Task TheDatabaseProtectsRefreshTokens()
    {
        var (db, host) = await Setup();
        var registered = await Register(host);

        string Insert(string hash, string revokedAt = "NULL", string reason = "NULL", string expires = "'2026-10-27 12:00:00+00'") =>
            $"INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, created_at, expires_at, revoked_at, revoked_reason, replaced_by_token_id, created_by_ip) " +
            $"VALUES ('{Guid.NewGuid()}', '{registered.UserId}', '{Guid.NewGuid()}', '{hash}', '2026-10-20 12:00:00+00', {expires}, {revokedAt}, {reason}, NULL, '203.0.113.1')";

        await db.ExecuteAsync(Insert(new string('a', 64)));
        await Assert.ThrowsAnyAsync<Exception>(() => db.ExecuteAsync(Insert(new string('a', 64))));                                        // one hash, one row
        await Assert.ThrowsAnyAsync<Exception>(() => db.ExecuteAsync(Insert(new string('b', 64), revokedAt: "'2026-10-21 12:00:00+00'")));   // revoked without a reason
        await Assert.ThrowsAnyAsync<Exception>(() => db.ExecuteAsync(Insert(new string('c', 64), expires: "'2026-10-19 12:00:00+00'")));     // expires before it was created
    }
}
