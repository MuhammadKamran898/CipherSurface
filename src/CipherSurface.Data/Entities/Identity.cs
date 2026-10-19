using CipherSurface.Data.Enums;

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

public class User
{
    public Guid Id { get; set; }
    public string Email { get; set; } = "";          // stored lower-case
    public string PasswordHash { get; set; } = "";
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
