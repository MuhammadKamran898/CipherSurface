namespace CipherSurface.Data.Entities;

/// <summary>
/// One refresh token. The token itself is never stored, only its SHA-256 hash. Each use rotates it: the old row is
/// revoked and points at its replacement. Tokens of one login share a FamilyId, so reuse of an old token can end the whole session.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid FamilyId { get; set; }
    public string TokenHash { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }          // Rotated | LoggedOut | ReuseDetected | PasswordChanged | AccountDisabled
    public Guid? ReplacedByTokenId { get; set; }
    public string CreatedByIp { get; set; } = "";
    public uint Version { get; set; }                   // row version: two simultaneous uses of one token cannot both win

    public User User { get; set; } = null!;
}
