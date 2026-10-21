using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

/// <summary>Domain status is DERIVED from evidence. This is the only code allowed to compute it.</summary>
public static class DomainStatusCalculator
{
    public static DomainStatus Compute(DomainStatus current, IReadOnlyCollection<EvidenceStatus> evidence, bool hasOpenDisputeAsClaimant)
    {
        if (current == DomainStatus.Revoked) return DomainStatus.Revoked;        // explicit action wins
        if (hasOpenDisputeAsClaimant) return DomainStatus.Disputed;              // then disputes

        if (evidence.Contains(EvidenceStatus.Active)) return DomainStatus.Verified;
        if (evidence.Contains(EvidenceStatus.AtRisk)) return DomainStatus.AtRisk;
        if (evidence.Count > 0) return DomainStatus.Lapsed;                      // only Lapsed/Expired/Revoked left

        return current == DomainStatus.Failed ? DomainStatus.Failed : DomainStatus.Pending;
    }
}

public static class DomainStatusService
{
    /// <summary>Recomputes and saves the status. Call inside the same transaction as the evidence change.</summary>
    public static async Task<DomainStatus> RecalculateAsync(CipherSurfaceDbContext db, Domain domain, CancellationToken ct)
    {
        var evidence = await db.VerificationEvidence
            .Where(e => e.DomainId == domain.Id)
            .Select(e => e.Status)
            .ToListAsync(ct);
        var hasOpenDispute = await db.DomainDisputes
            .AnyAsync(d => d.ClaimantDomainId == domain.Id && d.Status == DisputeStatus.Open, ct);

        var next = DomainStatusCalculator.Compute(domain.Status, evidence, hasOpenDispute);
        if (next != domain.Status)
        {
            domain.Status = next;
            await db.SaveChangesAsync(ct);
        }
        return next;
    }
}
