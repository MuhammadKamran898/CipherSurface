namespace CipherSurface.Services;

/// <summary>
/// Tenant-level resource limits. The request rate limiters protect the service from one client address; these protect
/// it from one organization, however many addresses or users that organization uses.
/// </summary>
public sealed record GovernanceOptions
{
    public const int DefaultMaxDomainsPerOrganization = 100;

    /// <summary>
    /// Domain records one organization may hold, counting every row (Revoked ones too, because a revoked domain keeps its
    /// row and can be authorized again without taking another slot).
    /// </summary>
    public int MaxDomainsPerOrganization { get; init; } = DefaultMaxDomainsPerOrganization;
}
