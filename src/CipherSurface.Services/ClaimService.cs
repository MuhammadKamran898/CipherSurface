using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

public static class EvidenceFactory
{
    /// <summary>Evidence for DNS, HTTP-file and meta-tag proofs (email has its own factory).</summary>
    public static VerificationEvidence ForObservable(VerificationChallenge challenge, DateTimeOffset now)
    {
        if (challenge.Method == VerificationMethod.AdminEmail)
            throw new ArgumentException("Use EmailEvidenceFactory for admin-email evidence.", nameof(challenge));

        var dns = challenge.Method == VerificationMethod.DnsTxt;
        return new VerificationEvidence
        {
            Id = Guid.NewGuid(),
            DomainId = challenge.DomainId,
            ChallengeId = challenge.Id,
            Method = challenge.Method,
            Assurance = dns ? AssuranceLevel.High : AssuranceLevel.Medium,
            ScopeCeilingType = dns ? ScopeCeilingType.DomainAndSubdomains : ScopeCeilingType.ExactHost,
            Host = challenge.Host,
            EstablishedAt = now,
            LastCheckedAt = now,
            LastValidAt = now,
            Status = EvidenceStatus.Active
        };
    }
}

public sealed record ClaimOutcome(bool Disputed, Guid EvidenceId);

/// <summary>
/// Completes a successful verification. Runs inside the caller's transaction and first takes a
/// transaction-scoped advisory lock on the domain NAME, so two organizations finishing at the same
/// moment are handled one after the other: the first becomes the holder, the second is disputed.
/// The partial unique index on domains stays as the database-level guarantee behind this lock.
/// </summary>
public sealed class ClaimService
{
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;

    public ClaimService(TimeProvider time, AuditLogWriter audit)
    {
        _time = time;
        _audit = audit;
    }

    /// <param name="challenge">Tracked, with its Domain loaded.</param>
    public async Task<ClaimOutcome> CompleteAsync(CipherSurfaceDbContext db, VerificationChallenge challenge, Guid actorUserId, string? ip, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("ClaimService.CompleteAsync must run inside a transaction.");

        var domain = challenge.Domain;
        await DbLocks.AcquireAsync(db, $"domain:{domain.Name}", ct);

        var now = _time.GetUtcNow();
        var evidence = EvidenceFactory.ForObservable(challenge, now);
        db.VerificationEvidence.Add(evidence);
        challenge.Status = ChallengeStatus.Passed;

        // Looked up AFTER the lock, so a claim that committed a moment ago is visible.
        var incumbent = await db.Domains.AsNoTracking()
            .Where(d => d.Name == domain.Name
                        && d.OrganizationId != domain.OrganizationId
                        && (d.Status == DomainStatus.Verified || d.Status == DomainStatus.AtRisk))
            .FirstOrDefaultAsync(ct);

        var disputed = false;
        if (incumbent is not null)
        {
            disputed = true;
            var alreadyOpen = await db.DomainDisputes
                .AnyAsync(d => d.ClaimantDomainId == domain.Id && d.Status == DisputeStatus.Open, ct);
            if (!alreadyOpen)
            {
                db.DomainDisputes.Add(new DomainDispute
                {
                    Id = Guid.NewGuid(),
                    IncumbentDomainId = incumbent.Id,
                    ClaimantDomainId = domain.Id,
                    Status = DisputeStatus.Open,
                    OpenedAt = now
                });
            }
        }

        await db.SaveChangesAsync(ct);                                    // evidence, challenge, dispute
        var status = await DomainStatusService.RecalculateAsync(db, domain, ct); // Verified, or Disputed by precedence

        await _audit.AppendAsync(db, new AuditEntry(domain.OrganizationId, "User", actorUserId,
            disputed ? "domain.disputed" : "domain.verified", "Domain", domain.Id,
            new Dictionary<string, object?>
            {
                ["method"] = challenge.Method.ToString(),
                ["status"] = status.ToString(),
                ["incumbentDomainId"] = incumbent?.Id.ToString("D")
            }, ip), ct);

        return new ClaimOutcome(disputed, evidence.Id);
    }
}
