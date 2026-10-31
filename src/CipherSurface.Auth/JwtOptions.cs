namespace CipherSurface.Auth;

public sealed record JwtOptions
{
    public string Issuer { get; init; } = "ciphersurface";
    public string Audience { get; init; } = "ciphersurface-api";
    /// <summary>Short on purpose: an access token cannot be revoked, only outlived.</summary>
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(15);
    public TimeSpan RefreshTokenLifetime { get; init; } = TimeSpan.FromDays(14);
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);
}
