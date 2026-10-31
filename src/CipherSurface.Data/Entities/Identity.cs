using CipherSurface.Data.Enums;
using Microsoft.AspNetCore.Identity;

namespace CipherSurface.Data.Entities;

public class Organization
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public OrganizationStatus Status { get; set; } = OrganizationStatus.Active;
    public DateTimeOffset CreatedAt { get; set; }
    public uint Version { get; set; } // maps to PostgreSQL xmin

    public List<Membership> Memberships { get; set; } = [];
    public List<Domain> Domains { get; set; } = [];
}

/// <summary>
/// The CipherSurface account. It extends ASP.NET Core Identity's user (id, email, password hash, lockout, security stamp),
/// so there is one account model and one password store. Organization roles live in Membership, not in Identity roles.
/// Email is stored lower-case (see the check constraint in UserConfiguration).
/// </summary>
public class User : IdentityUser<Guid>
{
    public UserStatus Status { get; set; } = UserStatus.Active;
    public DateTimeOffset CreatedAt { get; set; }
    public uint Version { get; set; }
}

public class Membership
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid UserId { get; set; }
    public MembershipRole Role { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public uint Version { get; set; }

    public Organization Organization { get; set; } = null!;
    public User User { get; set; } = null!;
}
