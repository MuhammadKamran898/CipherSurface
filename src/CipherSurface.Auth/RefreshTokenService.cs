using System.Security.Cryptography;
using System.Text;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Services;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Auth;

public sealed record IssuedRefreshToken(string Token, Guid FamilyId, DateTimeOffset ExpiresAt, Guid UserId);

/// <summary>
/// Refresh tokens are random, stored only as SHA-256 hashes, rotated on every use and revocable. Presenting a token that
/// was already rotated means two parties hold it, so the whole session family is revoked.
/// </summary>
public sealed class RefreshTokenService
{
    private const string Invalid = "InvalidRefreshToken";

    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly JwtOptions _options;
    private readonly TimeProvider _time;

    public RefreshTokenService(IDbContextFactory<CipherSurfaceDbContext> factory, JwtOptions options, TimeProvider time)
    {
        _factory = factory;
        _options = options;
        _time = time;
    }

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    private static string NewToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Starts a new session family (a login).</summary>
    public async Task<IssuedRefreshToken> StartSessionAsync(Guid userId, string ip, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var issued = Add(db, userId, Guid.NewGuid(), ip, _time.GetUtcNow(), out _);
        await db.SaveChangesAsync(ct);
        return issued;
    }

    /// <summary>Exchanges a refresh token for a new one. Any problem is reported as the same InvalidRefreshToken.</summary>
    public async Task<IssuedRefreshToken> RotateAsync(string? presentedToken, string ip, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(presentedToken)) throw new ServiceException(Invalid, "The session is not valid.");
        var hash = Hash(presentedToken);

        ServiceException? failure = null;
        IssuedRefreshToken? issued = null;
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var now = _time.GetUtcNow();

            var token = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash, ct);
            if (token is null)
            {
                failure = new ServiceException(Invalid, "The session is not valid.");
            }
            else if (token.RevokedAt is not null)
            {
                if (token.ReplacedByTokenId is not null)
                    await RevokeFamilyInContextAsync(db, token.FamilyId, "ReuseDetected", now, ct);   // an old token came back: assume theft
                failure = new ServiceException(Invalid, "The session is not valid.");
            }
            else if (token.ExpiresAt <= now)
            {
                failure = new ServiceException(Invalid, "The session is not valid.");
            }
            else
            {
                issued = Add(db, token.UserId, token.FamilyId, ip, now, out var replacement);
                token.RevokedAt = now;
                token.RevokedReason = "Rotated";
                token.ReplacedByTokenId = replacement.Id;
                await db.SaveChangesAsync(ct);
            }

            await tx.CommitAsync(ct);   // commit first: a family revocation must survive the error we throw next
        }
        catch (DbUpdateConcurrencyException)
        {
            // Two simultaneous uses of the same token: one wins, the other is simply refused.
            throw new ServiceException(Invalid, "The session is not valid.");
        }

        if (failure is not null) throw failure;
        return issued!;
    }

    /// <summary>Logout: ends the session that owns this token. Unknown tokens are ignored.</summary>
    public async Task RevokeSessionAsync(string? presentedToken, string reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(presentedToken)) return;
        var hash = Hash(presentedToken);
        await using var db = await _factory.CreateDbContextAsync(ct);
        var familyId = await db.RefreshTokens.Where(t => t.TokenHash == hash).Select(t => (Guid?)t.FamilyId).SingleOrDefaultAsync(ct);
        if (familyId is null) return;
        await RevokeFamilyInContextAsync(db, familyId.Value, reason, _time.GetUtcNow(), ct);
    }

    public async Task RevokeSessionByIdAsync(Guid familyId, string reason, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        await RevokeFamilyInContextAsync(db, familyId, reason, _time.GetUtcNow(), ct);
    }

    /// <summary>Ends every session of a user (password change, account disabled).</summary>
    public async Task RevokeAllForUserAsync(Guid userId, string reason, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = _time.GetUtcNow();
        var live = await db.RefreshTokens.Where(t => t.UserId == userId && t.RevokedAt == null).ToListAsync(ct);
        foreach (var token in live) { token.RevokedAt = now; token.RevokedReason = reason; }
        await db.SaveChangesAsync(ct);
    }

    private static async Task RevokeFamilyInContextAsync(CipherSurfaceDbContext db, Guid familyId, string reason, DateTimeOffset now, CancellationToken ct)
    {
        var live = await db.RefreshTokens.Where(t => t.FamilyId == familyId && t.RevokedAt == null).ToListAsync(ct);
        foreach (var token in live) { token.RevokedAt = now; token.RevokedReason = reason; }
        await db.SaveChangesAsync(ct);
    }

    private IssuedRefreshToken Add(CipherSurfaceDbContext db, Guid userId, Guid familyId, string ip, DateTimeOffset now, out RefreshToken row)
    {
        var plain = NewToken();
        row = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            FamilyId = familyId,
            TokenHash = Hash(plain),
            CreatedAt = now,
            ExpiresAt = now + _options.RefreshTokenLifetime,
            CreatedByIp = ip
        };
        db.RefreshTokens.Add(row);
        return new IssuedRefreshToken(plain, familyId, row.ExpiresAt, userId);
    }
}
