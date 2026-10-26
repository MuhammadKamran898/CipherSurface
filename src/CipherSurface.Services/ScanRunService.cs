using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

public sealed record ScanRunOptions
{
    /// <summary>How long a started scan may go without a successful continuation check before it is considered dead.</summary>
    public TimeSpan InitialLease { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Evidence last proven valid more recently than this is not re-checked on every batch.</summary>
    public TimeSpan EvidenceFreshness { get; init; } = TimeSpan.FromHours(24);
}

public sealed record ContinuationResult(
    ContinuationOutcome Outcome, string? ReasonCode, IReadOnlyList<string> AllowedTargets, IReadOnlyList<string> BlockedTargets,
    DateTimeOffset? LeaseExpiresAt, ScanRunStatus RunStatus);

/// <summary>
/// Everything that happens to a scan after it was allowed to start (spec section 7.5): handing it to a worker,
/// the continuation checks between batches, completion, and cleanup of dead scans. The start decision stays immutable.
/// </summary>
public sealed class ScanRunService
{
    private const int MaxSnapshotRetries = 3;

    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;
    private readonly ScanPayloadSigner _signer;
    private readonly ScanContinuationGate _gate;
    private readonly ScanRunOptions _options;
    private readonly LiveEvidenceChecker _checker;

    public ScanRunService(
        IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, VerifierRegistry registry, AuditLogWriter audit,
        ScanPayloadSigner signer, ScanContinuationGate? gate = null, ScanRunOptions? options = null)
    {
        _factory = factory;
        _time = time;
        _audit = audit;
        _signer = signer;
        _gate = gate ?? new ScanContinuationGate();
        _options = options ?? new ScanRunOptions();
        _checker = new LiveEvidenceChecker(registry);
    }

    // ------------------------------------------------------------------ begin

    /// <summary>Moves a queued scan to Running and returns the signed work order for the worker.</summary>
    public async Task<ScanWorkOrder> BeginAsync(Guid scanRunId, CancellationToken ct)
    {
        ServiceException? rejection = null;
        ScanWorkOrder? order = null;

        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(db, $"scanrun:{scanRunId:D}", ct);

            var run = await db.ScanRuns.Include(r => r.PolicyDecision).SingleOrDefaultAsync(r => r.Id == scanRunId, ct)
                      ?? throw new ServiceException("NotFound", "Scan not found.");
            if (run.Status != ScanRunStatus.Queued)
                throw new ServiceException("RunNotQueued", "This scan is not waiting to start.");

            var now = _time.GetUtcNow();
            var decision = run.PolicyDecision;
            if (now >= decision.ExpiresAt)
            {
                // The start decision is only good for a short time. A late start must be authorized again.
                run.Status = ScanRunStatus.Cancelled;
                run.CancelRequestedAt = now;
                run.CancelReason = "StartDeadlineExpired";
                run.FinishedAt = now;
                await db.SaveChangesAsync(ct);
                await _audit.AppendAsync(db, new AuditEntry(decision.OrganizationId, "System", null, "scan.start_expired", "ScanRun", run.Id,
                    new Dictionary<string, object?> { ["decisionId"] = decision.Id.ToString("D") }), ct);
                rejection = new ServiceException("StartDeadlineExpired", "The start authorization expired. Start the scan again.");
            }
            else
            {
                var lease = now + _options.InitialLease;
                run.Status = ScanRunStatus.Running;
                run.StartedAt = now;
                run.LeaseExpiresAt = lease;
                await db.SaveChangesAsync(ct);
                await _audit.AppendAsync(db, new AuditEntry(decision.OrganizationId, "System", null, "scan.started", "ScanRun", run.Id,
                    new Dictionary<string, object?> { ["decisionId"] = decision.Id.ToString("D"), ["targets"] = run.Targets.Length }), ct);

                var signature = _signer.Sign(run.Id, decision.Id, run.Targets, decision.EffectiveScopeSnapshot, decision.ExpiresAt);
                order = new ScanWorkOrder(run.Id, decision.Id, run.Targets, decision.EffectiveScopeSnapshot, decision.ExpiresAt, lease, signature);
            }

            await tx.CommitAsync(ct);
        }

        if (rejection is not null) throw rejection;
        return order!;
    }

    // ------------------------------------------------------------------ continue

    private sealed record RunSnapshot(
        ScanRun Run, PolicyDecision Decision, Organization? Organization, Domain? Domain, AuthorizationGrant? Grant,
        List<VerificationEvidence> Evidence, List<ScopeRule> Rules);

    /// <summary>
    /// Called by the worker before each stage and bounded batch. Continue and Restrict renew the lease; Cancel ends the scan.
    /// The result lists exactly which of the remaining targets may still be touched.
    /// </summary>
    public async Task<ContinuationResult> ContinueAsync(Guid scanRunId, IReadOnlyCollection<string> remainingTargets, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(remainingTargets);
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await TryContinueAsync(scanRunId, remainingTargets, ct);
            }
            catch (Exception ex) when ((ex is StaleSnapshotException || ex is DbUpdateConcurrencyException) && attempt < MaxSnapshotRetries)
            {
                // The scan or its evidence changed while we were checking. Read again.
            }
            catch (Exception ex) when (ex is StaleSnapshotException || ex is DbUpdateConcurrencyException)
            {
                throw new ServiceException("Busy", "The scan is changing right now. Ask again in a moment.");
            }
        }
    }

    private async Task<ContinuationResult> TryContinueAsync(Guid scanRunId, IReadOnlyCollection<string> remainingTargets, CancellationToken ct)
    {
        var snapshot = await LoadAsync(scanRunId, ct);
        var run = snapshot.Run;
        var requested = remainingTargets.Select(TargetNames.Normalize).Where(t => t.Length > 0).Distinct().ToList();

        // A finished scan has nothing to continue and must never be changed by a late or replayed check.
        if (run.Status is not (ScanRunStatus.Running or ScanRunStatus.CancelRequested))
            return new ContinuationResult(ContinuationOutcome.Cancel, "ScanRunNotRunning", [], requested, null, run.Status);

        // A worker may only ask about hosts this scan was authorized for in the first place.
        var original = run.Targets.ToHashSet(StringComparer.Ordinal);
        var foreign = requested.Where(t => !original.Contains(t)).ToList();
        var candidates = requested.Where(original.Contains).ToList();

        // Evidence proven valid recently is judged from stored state (the evaluator's 24-hour rule);
        // anything older, or already AtRisk, is checked live now.
        var now0 = _time.GetUtcNow();
        var checks = await _checker.CheckAsync(snapshot.Evidence, e =>
            e.Status == EvidenceStatus.AtRisk || e.LastValidAt is null || now0 - e.LastValidAt.Value > _options.EvidenceFreshness, ct);

        var now = _time.GetUtcNow();
        var results = checks.Select(c => new LiveEvidenceResult(c.Evidence, c.Outcome, c.Evidence.Version, now)).ToList();
        var evaluation = _gate.Evaluate(new ScanContinuationRequest(
            run, snapshot.Decision, snapshot.Organization, snapshot.Domain, snapshot.Grant,
            snapshot.Evidence, results, snapshot.Rules, candidates, now));

        var outcome = evaluation.Outcome;
        var reason = evaluation.ReasonCode;
        var blocked = evaluation.BlockedTargets.Concat(foreign).Distinct().ToList();
        if (outcome == ContinuationOutcome.Continue && foreign.Count > 0)
        {
            outcome = ContinuationOutcome.Restrict;
            reason = "TargetNotInScanRequest";
        }

        return await PersistContinuationAsync(snapshot, evaluation, checks, outcome, reason, blocked, now, ct);
    }

    private async Task<RunSnapshot> LoadAsync(Guid scanRunId, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var run = await db.ScanRuns.AsNoTracking().Include(r => r.PolicyDecision).SingleOrDefaultAsync(r => r.Id == scanRunId, ct)
                  ?? throw new ServiceException("NotFound", "Scan not found.");
        var decision = run.PolicyDecision;
        var organization = await db.Organizations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == decision.OrganizationId, ct);
        var domain = await db.Domains.AsNoTracking().SingleOrDefaultAsync(d => d.Id == decision.DomainId, ct);
        var grant = await db.AuthorizationGrants.AsNoTracking()
            .Where(g => g.DomainId == decision.DomainId)
            .OrderBy(g => g.Status == GrantStatus.Active ? 0 : 1).ThenByDescending(g => g.AcceptedAt)
            .FirstOrDefaultAsync(ct);
        var evidence = await db.VerificationEvidence.AsNoTracking().Include(e => e.Challenge)
            .Where(e => e.DomainId == decision.DomainId).ToListAsync(ct);
        var rules = await db.ScopeRules.AsNoTracking().Where(r => r.DomainId == decision.DomainId && r.RemovedAt == null).ToListAsync(ct);
        return new RunSnapshot(run, decision, organization, domain, grant, evidence, rules);
    }

    private async Task<ContinuationResult> PersistContinuationAsync(
        RunSnapshot snapshot, ContinuationEvaluation evaluation, IReadOnlyList<CheckedEvidence> checks,
        ContinuationOutcome outcome, string? reason, IReadOnlyList<string> blocked, DateTimeOffset now, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DbLocks.AcquireAsync(db, $"scanrun:{snapshot.Run.Id:D}", ct);

        var run = await db.ScanRuns.SingleAsync(r => r.Id == snapshot.Run.Id, ct);
        if (run.Version != snapshot.Run.Version) throw new StaleSnapshotException();   // for example it was flagged for cancellation

        var changed = await EvidenceApplication.ApplyAsync(db, checks, evaluation.EvidenceChanges, now, $"continuation:{run.Id:D}", ct);
        await db.SaveChangesAsync(ct);
        if (changed.Count > 0 && snapshot.Domain is not null)
        {
            var domain = await db.Domains.SingleAsync(d => d.Id == snapshot.Domain.Id, ct);
            await DomainStatusService.RecalculateAsync(db, domain, ct, _time);
        }

        var sequence = (await db.ScanRunAuthorizationChecks.Where(c => c.ScanRunId == run.Id)
                            .MaxAsync(c => (int?)c.Sequence, ct) ?? 0) + 1;
        db.ScanRunAuthorizationChecks.Add(new ScanRunAuthorizationCheck
        {
            Id = Guid.NewGuid(),
            ScanRunId = run.Id,
            Sequence = sequence,
            CheckedAt = now,
            Outcome = outcome,
            ReasonCode = reason,
            ScopeHash = evaluation.ScopeHash,
            TargetsRemaining = evaluation.AllowedTargets.Count
        });

        if (outcome == ContinuationOutcome.Cancel)
        {
            run.Status = ScanRunStatus.Cancelled;
            run.CancelRequestedAt ??= now;
            run.CancelReason ??= reason;
            run.FinishedAt = now;
        }
        else
        {
            run.LeaseExpiresAt = evaluation.NewLeaseExpiresAt;
        }
        await db.SaveChangesAsync(ct);

        foreach (var entry in EvidenceApplication.AuditEntries(snapshot.Decision.OrganizationId, changed))
            await _audit.AppendAsync(db, entry, ct);
        if (outcome != ContinuationOutcome.Continue)
        {
            await _audit.AppendAsync(db, new AuditEntry(snapshot.Decision.OrganizationId, "System", null,
                outcome == ContinuationOutcome.Cancel ? "scan.cancelled" : "scan.restricted", "ScanRun", run.Id,
                new Dictionary<string, object?>
                {
                    ["reason"] = reason,
                    ["sequence"] = sequence,
                    ["blockedTargets"] = blocked.Count,
                    ["allowedTargets"] = evaluation.AllowedTargets.Count
                }), ct);
        }

        await tx.CommitAsync(ct);
        return new ContinuationResult(outcome, reason, evaluation.AllowedTargets, blocked,
            outcome == ContinuationOutcome.Cancel ? null : evaluation.NewLeaseExpiresAt, run.Status);
    }

    // ------------------------------------------------------------------ complete, cleanup, coverage

    /// <summary>The worker reports it is done (or crashed). A scan that was told to stop ends as Cancelled.</summary>
    public async Task<ScanRunStatus> CompleteAsync(Guid scanRunId, bool succeeded, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DbLocks.AcquireAsync(db, $"scanrun:{scanRunId:D}", ct);

        var run = await db.ScanRuns.Include(r => r.PolicyDecision).SingleOrDefaultAsync(r => r.Id == scanRunId, ct)
                  ?? throw new ServiceException("NotFound", "Scan not found.");
        if (run.Status is not (ScanRunStatus.Running or ScanRunStatus.CancelRequested))
            throw new ServiceException("RunNotRunning", "This scan is not running.");

        var now = _time.GetUtcNow();
        run.Status = run.Status == ScanRunStatus.CancelRequested ? ScanRunStatus.Cancelled
                   : succeeded ? ScanRunStatus.Completed : ScanRunStatus.Failed;
        run.FinishedAt = now;
        await db.SaveChangesAsync(ct);

        await _audit.AppendAsync(db, new AuditEntry(run.PolicyDecision.OrganizationId, "System", null,
            run.Status == ScanRunStatus.Completed ? "scan.completed" : run.Status == ScanRunStatus.Cancelled ? "scan.cancelled" : "scan.failed",
            "ScanRun", run.Id, new Dictionary<string, object?> { ["status"] = run.Status.ToString() }), ct);
        await tx.CommitAsync(ct);
        return run.Status;
    }

    /// <summary>
    /// Housekeeping for scans that died or never started: a running scan whose lease ran out is Failed, and a queued scan
    /// whose start decision expired is Cancelled. Safe to run repeatedly.
    /// </summary>
    public async Task<(int LeasesExpired, int StartsExpired)> SweepAsync(CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        var at = (DateTimeOffset?)now;
        await using var db = await _factory.CreateDbContextAsync(ct);

        var leases = await db.ScanRuns
            .Where(r => r.Status == ScanRunStatus.Running && r.LeaseExpiresAt != null && r.LeaseExpiresAt <= now)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, ScanRunStatus.Failed)
                .SetProperty(r => r.CancelRequestedAt, at)
                .SetProperty(r => r.CancelReason, "LeaseExpired")
                .SetProperty(r => r.FinishedAt, at), ct);

        var expiredDecisions = db.PolicyDecisions.Where(d => d.ExpiresAt <= now).Select(d => d.Id);
        var starts = await db.ScanRuns
            .Where(r => r.Status == ScanRunStatus.Queued && expiredDecisions.Contains(r.PolicyDecisionId))
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, ScanRunStatus.Cancelled)
                .SetProperty(r => r.CancelRequestedAt, at)
                .SetProperty(r => r.CancelReason, "StartDeadlineExpired")
                .SetProperty(r => r.FinishedAt, at), ct);

        return (leases, starts);
    }

    /// <summary>
    /// True only for a scan that completed with every continuation check returning Continue. A scan that was ever
    /// restricted or cancelled is partial, and a finding missing from it proves nothing (pipeline step 7 must use this).
    /// </summary>
    public async Task<bool> WasFullyCoveredAsync(Guid scanRunId, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var status = await db.ScanRuns.Where(r => r.Id == scanRunId).Select(r => (ScanRunStatus?)r.Status).SingleOrDefaultAsync(ct);
        if (status != ScanRunStatus.Completed) return false;
        return !await db.ScanRunAuthorizationChecks.AnyAsync(c => c.ScanRunId == scanRunId && c.Outcome != ContinuationOutcome.Continue, ct);
    }
}
