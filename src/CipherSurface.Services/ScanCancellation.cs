using CipherSurface.Data;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

/// <summary>
/// Flags affected scans for cancellation inside the caller's transaction (spec section 7.5). It is set-based on purpose:
/// no row-version check, so a worker renewing its lease can never make the change that caused the cancellation fail.
/// The continuation check recomputes everything anyway; this flag makes the decision visible at once and is the
/// backstop if a check ever races with the change.
/// </summary>
internal static class ScanCancellation
{
    public static Task<int> RequestForDomainAsync(CipherSurfaceDbContext db, Guid domainId, string reason, DateTimeOffset now, CancellationToken ct) =>
        RequestAsync(db, db.PolicyDecisions.Where(d => d.DomainId == domainId).Select(d => d.Id), reason, now, ct);

    public static Task<int> RequestForOrganizationAsync(CipherSurfaceDbContext db, Guid organizationId, string reason, DateTimeOffset now, CancellationToken ct) =>
        RequestAsync(db, db.PolicyDecisions.Where(d => d.OrganizationId == organizationId).Select(d => d.Id), reason, now, ct);

    private static async Task<int> RequestAsync(CipherSurfaceDbContext db, IQueryable<Guid> decisionIds, string reason, DateTimeOffset now, CancellationToken ct)
    {
        var at = (DateTimeOffset?)now;

        // A scan that never started is simply cancelled.
        var queued = await db.ScanRuns
            .Where(r => r.Status == ScanRunStatus.Queued && decisionIds.Contains(r.PolicyDecisionId))
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, ScanRunStatus.Cancelled)
                .SetProperty(r => r.CancelRequestedAt, at)
                .SetProperty(r => r.CancelReason, reason)
                .SetProperty(r => r.FinishedAt, at), ct);

        // A running scan is asked to stop; its next continuation check ends it.
        var running = await db.ScanRuns
            .Where(r => r.Status == ScanRunStatus.Running && decisionIds.Contains(r.PolicyDecisionId))
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, ScanRunStatus.CancelRequested)
                .SetProperty(r => r.CancelRequestedAt, at)
                .SetProperty(r => r.CancelReason, reason), ct);

        return queued + running;
    }
}
