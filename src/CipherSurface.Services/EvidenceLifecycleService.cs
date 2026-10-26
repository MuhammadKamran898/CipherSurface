using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

public sealed record LifecycleOptions
{
    /// <summary>How long evidence may stay AtRisk (known absence) before it lapses.</summary>
    public TimeSpan GraceWindow { get; init; } = TimeSpan.FromHours(72);
}

public sealed record LifecycleSummary(int ChallengesExpired, int EvidenceLapsed, int EvidenceExpired, int DomainsRecalculated, int Skipped);

/// <summary>
/// Hourly time-based housekeeping: expire old challenges, lapse AtRisk evidence after the grace window,
/// expire email evidence, and recalculate the affected domains. Safe to run repeatedly.
/// Lapsed and Expired evidence is terminal: only a new challenge can replace it.
/// </summary>
public sealed class EvidenceLifecycleService
{
    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;
    private readonly LifecycleOptions _options;

    public EvidenceLifecycleService(IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, AuditLogWriter audit, LifecycleOptions? options = null)
    {
        _factory = factory;
        _time = time;
        _audit = audit;
        _options = options ?? new LifecycleOptions();
    }

    public async Task<LifecycleSummary> RunAsync(CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        var lapseBefore = now - _options.GraceWindow;

        int challengesExpired;
        List<Guid> domainIds;
        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            // A challenge being verified right now will hit its xmin check and report "Busy", so this is safe.
            challengesExpired = await db.VerificationChallenges
                .Where(c => (c.Status == ChallengeStatus.Issued || c.Status == ChallengeStatus.Checking) && c.ExpiresAt <= now)
                .ExecuteUpdateAsync(s => s.SetProperty(c => c.Status, ChallengeStatus.Expired), ct);

            domainIds = await db.VerificationEvidence
                .Where(e => (e.Status == EvidenceStatus.AtRisk && e.FailingSince != null && e.FailingSince <= lapseBefore)
                            || (e.Method == VerificationMethod.AdminEmail && e.Status == EvidenceStatus.Active
                                && e.ExpiresAt != null && e.ExpiresAt <= now))
                .Select(e => e.DomainId).Distinct().ToListAsync(ct);
        }

        int lapsed = 0, expired = 0, recalculated = 0, skipped = 0;
        foreach (var domainId in domainIds)
        {
            try
            {
                var (l, x) = await ProcessDomainAsync(domainId, now, lapseBefore, ct);
                lapsed += l;
                expired += x;
                recalculated++;
            }
            catch (DbUpdateConcurrencyException)
            {
                skipped++;     // changed under us (for example healed by a re-check): the next run decides
            }
        }

        return new LifecycleSummary(challengesExpired, lapsed, expired, recalculated, skipped);
    }

    private async Task<(int Lapsed, int Expired)> ProcessDomainAsync(Guid domainId, DateTimeOffset now, DateTimeOffset lapseBefore, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var domain = await db.Domains.SingleAsync(d => d.Id == domainId, ct);
        var due = await db.VerificationEvidence
            .Where(e => e.DomainId == domainId
                        && ((e.Status == EvidenceStatus.AtRisk && e.FailingSince != null && e.FailingSince <= lapseBefore)
                            || (e.Method == VerificationMethod.AdminEmail && e.Status == EvidenceStatus.Active
                                && e.ExpiresAt != null && e.ExpiresAt <= now)))
            .ToListAsync(ct);

        int lapsed = 0, expired = 0;
        foreach (var evidence in due)
        {
            var from = evidence.Status;
            if (from == EvidenceStatus.AtRisk) { evidence.Status = EvidenceStatus.Lapsed; lapsed++; }
            else { evidence.Status = EvidenceStatus.Expired; expired++; }
            await db.SaveChangesAsync(ct);

            await _audit.AppendAsync(db, new AuditEntry(domain.OrganizationId, "System", null,
                evidence.Status == EvidenceStatus.Lapsed ? "evidence.lapsed" : "evidence.expired",
                "VerificationEvidence", evidence.Id,
                new Dictionary<string, object?>
                {
                    ["method"] = evidence.Method.ToString(),
                    ["from"] = from.ToString(),
                    ["to"] = evidence.Status.ToString()
                }), ct);
        }

        await DomainStatusService.RecalculateAsync(db, domain, ct, _time);
        await tx.CommitAsync(ct);
        return (lapsed, expired);
    }
}
