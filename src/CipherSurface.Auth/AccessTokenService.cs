using System.Security.Claims;
using CipherSurface.Data.Entities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CipherSurface.Auth;

public sealed record AccessToken(string Token, DateTimeOffset ExpiresAt);
public sealed record ValidatedToken(Guid UserId, Guid SessionId, string Email);

/// <summary>
/// Issues and validates RS256 access tokens. A token says only WHO the caller is (sub, email) and which login session
/// it belongs to (sid). It carries no organization, role or platform-admin claim: those are looked up on the server for
/// every request, so a stale token can never keep a privilege that was taken away, and a caller can never add one.
/// </summary>
public sealed class AccessTokenService
{
    private readonly JwtOptions _options;
    private readonly TokenKeys _keys;
    private readonly TimeProvider _time;

    public AccessTokenService(JwtOptions options, TokenKeys keys, TimeProvider time)
    {
        _options = options;
        _keys = keys;
        _time = time;
    }

    public AccessToken Issue(User user, Guid sessionId)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (_keys.SigningKey is null)
            throw new InvalidOperationException("This instance holds only the public key and cannot issue tokens.");

        var now = _time.GetUtcNow();
        var expires = now + _options.AccessTokenLifetime;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", user.Id.ToString("D")),
                new Claim("email", user.Email ?? string.Empty),
                new Claim("sid", sessionId.ToString("D")),
                new Claim("jti", Guid.NewGuid().ToString("N"))
            }),
            NotBefore = now.UtcDateTime,
            IssuedAt = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(_keys.SigningKey, SecurityAlgorithms.RsaSha256)
        };
        return new AccessToken(new JsonWebTokenHandler().CreateToken(descriptor), expires);
    }

    /// <summary>
    /// For the JWT bearer middleware and for validate-only services. Only RS256 is accepted, so "alg: none" and
    /// HMAC-with-the-public-key tricks fail. Lifetime is judged by the injected clock.
    /// </summary>
    public TokenValidationParameters ValidationParameters() => new()
    {
        ValidateIssuer = true,
        ValidIssuer = _options.Issuer,
        ValidateAudience = true,
        ValidAudience = _options.Audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = _keys.ValidationKey,
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
        ValidateLifetime = true,
        ClockSkew = _options.ClockSkew,
        LifetimeValidator = (notBefore, expires, _, _) =>
        {
            var now = _time.GetUtcNow().UtcDateTime;
            return expires is not null
                   && (notBefore is null || now + _options.ClockSkew >= notBefore)
                   && now - _options.ClockSkew < expires;
        }
    };

    public async Task<ValidatedToken?> ValidateAsync(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, ValidationParameters());
        if (!result.IsValid) return null;

        var sub = result.ClaimsIdentity.FindFirst("sub")?.Value;
        var sid = result.ClaimsIdentity.FindFirst("sid")?.Value;
        if (!Guid.TryParse(sub, out var userId) || !Guid.TryParse(sid, out var sessionId)) return null;
        return new ValidatedToken(userId, sessionId, result.ClaimsIdentity.FindFirst("email")?.Value ?? string.Empty);
    }
}
