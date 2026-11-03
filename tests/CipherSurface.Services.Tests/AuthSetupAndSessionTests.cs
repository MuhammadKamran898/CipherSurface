using CipherSurface.Auth;
using CipherSurface.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>First-owner setup, "is this session still alive", and signing-key rotation.</summary>
[Collection("postgres")]
public class AuthSetupAndSessionTests
{
    private const string Password = "correct horse battery staple";
    private const string Ip = "203.0.113.50";
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly PostgresFixture _postgres;
    public AuthSetupAndSessionTests(PostgresFixture postgres) => _postgres = postgres;

    private async Task<(TestDatabase Db, AuthHost Host)> SetupAsync()
    {
        var db = await _postgres.CreateDatabaseAsync();
        return (db, AuthHost.Create(db));
    }

    private static async Task<ServiceException> FailsAsync(Func<Task> call) => await Assert.ThrowsAsync<ServiceException>(call);

    private static Guid SessionOf(AuthTokens tokens) => Guid.Parse(new JsonWebToken(tokens.AccessToken).GetClaim("sid").Value);

    private static async Task<bool> SessionActiveAsync(AuthHost host, Guid userId, Guid sessionId)
    {
        using var scope = host.Provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<RefreshTokenService>().IsSessionActiveAsync(userId, sessionId, Ct);
    }

    // ------------------------------------------------------------------ first-owner setup

    [Fact]
    public async Task FirstOwnerSetup_CreatesTheOwnerAndOrganization_AndRecordsItInTheAuditChain()
    {
        var (db, host) = await SetupAsync();

        var result = await host.Run(a => a.RegisterFirstOwnerAsync("Owner@Example.com", Password, "  Bright Cart ", Ct));

        await using var context = db.CreateDbContext();
        var user = await context.Users.SingleAsync();
        Assert.Equal(result.UserId, user.Id);
        Assert.Equal("owner@example.com", user.Email);
        var membership = await context.Memberships.SingleAsync();
        Assert.Equal((result.OrganizationId, result.UserId), (membership.OrganizationId, membership.UserId));
        Assert.Equal("Bright Cart", (await context.Organizations.SingleAsync()).Name);
        var audit = await context.AuditLogs.SingleAsync(a => a.OrganizationId == result.OrganizationId);
        Assert.Equal("organization.created", audit.Action);
        Assert.Contains("first-owner", audit.Data);
    }

    [Fact]
    public async Task FirstOwnerSetup_IsClosedOnceAnyAccountExists_WhateverHowItWasCreated()
    {
        var (db, host) = await SetupAsync();
        await host.Run(a => a.RegisterAsync("someone@example.com", Password, "Existing", Ct));

        var ex = await FailsAsync(() => host.Run(a => a.RegisterFirstOwnerAsync("owner@example.com", Password, "Bright Cart", Ct)));

        Assert.Equal("SetupClosed", ex.Code);
        await using var context = db.CreateDbContext();
        Assert.Equal(1, await context.Users.CountAsync());
    }

    [Fact]
    public async Task FirstOwnerSetup_SecondCall_IsRefused()
    {
        var (_, host) = await SetupAsync();
        await host.Run(a => a.RegisterFirstOwnerAsync("owner@example.com", Password, "Bright Cart", Ct));

        var ex = await FailsAsync(() => host.Run(a => a.RegisterFirstOwnerAsync("another@example.com", Password, "Another", Ct)));

        Assert.Equal("SetupClosed", ex.Code);
    }

    [Fact]
    public async Task FirstOwnerSetup_WithAWeakPassword_RollsBack_AndLeavesSetupOpen()
    {
        var (db, host) = await SetupAsync();

        var ex = await FailsAsync(() => host.Run(a => a.RegisterFirstOwnerAsync("owner@example.com", "short", "Bright Cart", Ct)));

        Assert.Equal("WeakPassword", ex.Code);
        await using (var context = db.CreateDbContext())
        {
            Assert.Equal(0, await context.Users.CountAsync());
            Assert.Equal(0, await context.Organizations.CountAsync());
        }

        await host.Run(a => a.RegisterFirstOwnerAsync("owner@example.com", Password, "Bright Cart", Ct));
    }

    [Fact]
    public async Task FirstOwnerSetup_CalledInParallel_HasExactlyOneWinner()
    {
        var (db, host) = await SetupAsync();

        var outcomes = await Task.WhenAll(Enumerable.Range(0, 8).Select(async i =>
        {
            try
            {
                await host.Run(a => a.RegisterFirstOwnerAsync($"owner{i}@example.com", Password, $"Org {i}", Ct));
                return "ok";
            }
            catch (ServiceException ex)
            {
                return ex.Code;
            }
        }));

        Assert.Single(outcomes, o => o == "ok");
        Assert.Equal(7, outcomes.Count(o => o == "SetupClosed"));
        await using var context = db.CreateDbContext();
        Assert.Equal(1, await context.Users.CountAsync());
        Assert.Equal(1, await context.Organizations.CountAsync());
    }

    // ------------------------------------------------------------------ is the session behind a token still alive?

    [Fact]
    public async Task ASession_IsActiveAfterLogin_AndOnlyForItsOwnUser()
    {
        var (_, host) = await SetupAsync();
        var owner = await host.Run(a => a.RegisterAsync("owner@example.com", Password, "Org", Ct));
        var tokens = await host.Run(a => a.LoginAsync("owner@example.com", Password, Ip, Ct));

        Assert.True(await SessionActiveAsync(host, owner.UserId, SessionOf(tokens)));
        Assert.False(await SessionActiveAsync(host, Guid.NewGuid(), SessionOf(tokens)));       // someone else's session id
        Assert.False(await SessionActiveAsync(host, owner.UserId, Guid.NewGuid()));              // a session that never existed
    }

    [Fact]
    public async Task ASession_StaysActiveAcrossRotation_AndEndsOnLogout()
    {
        var (_, host) = await SetupAsync();
        var owner = await host.Run(a => a.RegisterAsync("owner@example.com", Password, "Org", Ct));
        var first = await host.Run(a => a.LoginAsync("owner@example.com", Password, Ip, Ct));
        var session = SessionOf(first);

        var second = await host.Run(a => a.RefreshAsync(first.RefreshToken, Ip, Ct));
        Assert.True(await SessionActiveAsync(host, owner.UserId, session));
        Assert.Equal(session, SessionOf(second));

        await host.Run(a => a.LogoutAsync(second.RefreshToken, Ct));
        Assert.False(await SessionActiveAsync(host, owner.UserId, session));
    }

    [Fact]
    public async Task ASession_EndsWhenItsRefreshTokenExpires()
    {
        var (_, host) = await SetupAsync();
        var owner = await host.Run(a => a.RegisterAsync("owner@example.com", Password, "Org", Ct));
        var tokens = await host.Run(a => a.LoginAsync("owner@example.com", Password, Ip, Ct));

        host.Time.Advance(host.Options.RefreshTokenLifetime - TimeSpan.FromMinutes(1));
        Assert.True(await SessionActiveAsync(host, owner.UserId, SessionOf(tokens)));

        host.Time.Advance(TimeSpan.FromMinutes(2));
        Assert.False(await SessionActiveAsync(host, owner.UserId, SessionOf(tokens)));
    }

    [Fact]
    public async Task ASession_EndsOnReuseDetection_AndOnPasswordChange()
    {
        var (_, host) = await SetupAsync();
        var owner = await host.Run(a => a.RegisterAsync("owner@example.com", Password, "Org", Ct));
        var stolen = await host.Run(a => a.LoginAsync("owner@example.com", Password, Ip, Ct));
        await host.Run(a => a.RefreshAsync(stolen.RefreshToken, Ip, Ct));
        await FailsAsync(() => host.Run(a => a.RefreshAsync(stolen.RefreshToken, Ip, Ct)));   // replay of a used token
        Assert.False(await SessionActiveAsync(host, owner.UserId, SessionOf(stolen)));

        var other = await host.Run(a => a.LoginAsync("owner@example.com", Password, Ip, Ct));
        await host.Run(a => a.ChangePasswordAsync(owner.UserId, Password, "an entirely new passphrase", Ct));
        Assert.False(await SessionActiveAsync(host, owner.UserId, SessionOf(other)));
    }

    // ------------------------------------------------------------------ key rotation

    [Fact]
    public async Task ARetiredPublicKey_ValidatesOldTokens_ButNeverSigns()
    {
        var (db, _) = await SetupAsync();
        var oldKeys = TokenKeys.Generate("key-old").Keys;
        var current = TokenKeys.Generate("key-new").Keys;
        var user = new User { Id = Guid.NewGuid(), Email = "owner@example.com" };
        var time = new FakeTime(TestWorld.Start);
        var oldToken = new AccessTokenService(new JwtOptions(), oldKeys, time).Issue(user, Guid.NewGuid()).Token;

        var rotated = current.WithRetiredPublicKey(oldKeys.PublicPem, "key-old");
        var service = new AccessTokenService(new JwtOptions(), rotated, time);

        Assert.NotNull(await service.ValidateAsync(oldToken));                                          // still trusted during the overlap
        Assert.Null(await new AccessTokenService(new JwtOptions(), current, time).ValidateAsync(oldToken));   // not once the old key is dropped
        var fresh = service.Issue(user, Guid.NewGuid()).Token;
        Assert.Equal("key-new", new JsonWebToken(fresh).Kid);                                            // new tokens always use the current key
        Assert.Contains(rotated.ValidationKeys, k => k.KeyId == "key-old");
        Assert.Equal("key-new", rotated.KeyId);
        _ = db;
    }

    [Fact]
    public void ARetiredKey_NeedsItsOwnId()
    {
        var current = TokenKeys.Generate("key-new").Keys;
        var other = TokenKeys.Generate("key-old").Keys;
        var rotated = current.WithRetiredPublicKey(other.PublicPem, "key-old");

        Assert.Throws<ArgumentException>(() => current.WithRetiredPublicKey(other.PublicPem, "key-new"));   // same id as the current key
        Assert.Throws<ArgumentException>(() => rotated.WithRetiredPublicKey(other.PublicPem, "key-old"));   // already listed
        Assert.Throws<ArgumentException>(() => current.WithRetiredPublicKey(other.PublicPem, " "));
    }

    [Fact]
    public void AWeakRetiredKey_IsRejected()
    {
        var current = TokenKeys.Generate("key-new").Keys;
        using var weak = System.Security.Cryptography.RSA.Create(1024);

        Assert.Throws<ArgumentException>(() => current.WithRetiredPublicKey(weak.ExportSubjectPublicKeyInfoPem(), "key-weak"));
    }
}
