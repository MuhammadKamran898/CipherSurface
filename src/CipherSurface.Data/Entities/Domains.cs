using CipherSurface.Data.Enums;

namespace CipherSurface.Data.Entities;

public class Domain
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    /// <summary>Normalized registrable domain, lower-case.</summary>
    public string Name { get; set; } = "";
    /// <summary>Derived from evidence by ONE service method. Nothing else writes it.</summary>
    public DomainStatus Status { get; set; } = DomainStatus.Pending;
    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public uint Version { get; set; }

    public Organization Organization { get; set; } = null!;
    public List<AuthorizationGrant> Grants { get; set; } = [];
    public List<VerificationChallenge> Challenges { get; set; } = [];
    public List<VerificationEvidence> Evidence { get; set; } = [];
    public List<ScopeRule> ScopeRules { get; set; } = [];
}

public class AuthorizationGrant
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DomainId { get; set; }
    public Guid GrantedByUserId { get; set; }
    public GrantType GrantType { get; set; } = GrantType.SelfAttestation;
    public string AttestationTextVersion { get; set; } = "";
    public string AttestationHash { get; set; } = "";
    public DateTimeOffset AcceptedAt { get; set; }
    public string Ip { get; set; } = "";
    public GrantStatus Status { get; set; } = GrantStatus.Active;
    public DateTimeOffset? RevokedAt { get; set; }
    public Guid? RevokedByUserId { get; set; }
    public uint Version { get; set; }

    public Domain Domain { get; set; } = null!;
}

public class DomainDispute
{
    public Guid Id { get; set; }
    public Guid IncumbentDomainId { get; set; }
    public Guid ClaimantDomainId { get; set; }
    public DisputeStatus Status { get; set; } = DisputeStatus.Open;
    public DateTimeOffset OpenedAt { get; set; }
    public DateTimeOffset? ResolvedAt { get; set; }
    public Guid? ResolvedByUserId { get; set; }
    public string? Note { get; set; }
    public uint Version { get; set; }

    public Domain IncumbentDomain { get; set; } = null!;
    public Domain ClaimantDomain { get; set; } = null!;
}
