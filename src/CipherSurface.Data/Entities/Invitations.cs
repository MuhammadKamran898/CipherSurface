using CipherSurface.Data.Enums;

namespace CipherSurface.Data.Entities;

/// <summary>
/// An offer to join an organization with a role. Only a SHA-256 hash of the one-time token is stored, so the token
/// cannot be recovered from the database or from a backup. Email is stored normalized (lower-case). At most one
/// invitation per organization and email is Pending; issuing again supersedes the earlier one. A resolved invitation
/// (Accepted, Revoked, Superseded) never changes again, and the invited email, role and token never change at all.
/// </summary>
public class Invitation
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public string Email { get; set; } = "";
    public MembershipRole Role { get; set; }
    public string TokenHash { get; set; } = "";
    public InvitationStatus Status { get; set; } = InvitationStatus.Pending;
    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>When it stopped being Pending, and by whom: the person who accepted, revoked, or issued the replacement.</summary>
    public DateTimeOffset? ResolvedAt { get; set; }
    public Guid? ResolvedByUserId { get; set; }

    public uint Version { get; set; }   // maps to PostgreSQL xmin

    public Organization Organization { get; set; } = null!;
}
