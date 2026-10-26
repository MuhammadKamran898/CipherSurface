using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace CipherSurface.Services;

public sealed record ScanStartResult(
    bool Allowed, Guid DecisionId, string? FailedCheckCode, Guid? ScanRunId, DateTimeOffset DecisionExpiresAt, bool AlreadyStarted);

/// <summary>
/// The one entry point for starting a scan, manual or scheduled. It loads a consistent snapshot, runs the cheap checks
/// first (no network when they already fail), performs the live ownership checks, calls the pure gate, and then saves
/// EVERYTHING in one transaction: the evidence changes the checks caused, the immutable decision (allow OR deny),
/// the scan run if allowed, and the audit trail. A scan can only exist with an Allow decision behind it.
/// </summary>
public sealed class ScanStartService
{
    private const int MaxSnapshotRetries = 3;

    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;
    private readonly ScanPolicyGate _gate;
    private readonly LiveEvidenceChecker _checker;

    public ScanStartService(
        IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, VerifierRegistry registry,
        AuditLogWriter audit, ScanPolicyGate? gate = null)
    {
        _factory = factory;
        _time = time;
        _audit = audit;
        _gate = gate ?? new ScanPolicyGate();
        _checker = new LiveEvidenceChecker(registry);
    }

    private sealed record Snapshot(
        User? User, Membership? Membership, Organization? Organization, AuthorizationGrant? Grant,
        Domain Domain, List<VerificationEvidence> Evidence, List<ScopeRule> Rules);

    /// <param name="actor">For a scheduled scan, the user who owns the schedule. Their role is checked every time.</param>
    /// <param name="scheduleId">With scheduledFor, makes a retried scheduled job harmless: one run per occurrence.</param>
    public async Task<ScanStartResult> StartAsync(
        Actor actor, Guid domainId, IReadOnlyCollection<string> targets,
        DecisionTrigger trigger, Guid? scheduleId, DateTimeOffset? scheduledFor, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(targets);
        if ((scheduleId is null) != (scheduledFor is null))
            throw new ServiceException("InvalidSchedule", "A scheduled scan needs both a schedule and an occurrence time.");
        if (trigger == DecisionTrigger.Scheduled && scheduleId is null)
            throw new ServiceException("InvalidSchedule", "A scheduled scan needs a schedule.");

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await TryStartAsync(actor, domainId, targets, trigger, scheduleId, scheduledFor, ct);
            }
            catch (Exception ex) when ((ex is StaleSnapshotException || ex is DbUpdateConcurrencyException) && attempt < MaxSnapshotRetries)
            {
                // Evidence changed while we were checking it. Read again and redo the checks.
            }
            catch (Exception ex) when (ex is StaleSnapshotException || ex is DbUpdateConcurrencyException)
            {
                throw new ServiceException("Busy", "The domain's proof is changing right now. Try again in a moment.");
            }
        }
    }

    private async Task<ScanStartResult> TryStartAsync(
        Actor actor, Guid domainId, IReadOnlyCollection<string> targets,
        DecisionTrigger trigger, Guid? scheduleId, DateTimeOffset? scheduledFor, CancellationToken ct)
    {
        if (scheduleId is not null)
        {
            var existing = await FindScheduledAsync(scheduleId.Value, scheduledFor!.Value, ct);
            if (existing is not null) return existing;
        }

        var snapshot = await LoadSnapshotAsync(actor, domainId, ct);
        var decisionId = Guid.NewGuid();
        var normalizedTargets = targets.Select(TargetNames.Normalize).Where(t => t.Length > 0).Distinct().OrderBy(t => t, StringComparer.Ordinal).ToList();

        // Cheapest checks first: if they already fail there is no reason to touch the network.
        var firstLook = BuildRequest(decisionId, actor, snapshot, trigger, normalizedTargets, Array.Empty<LiveEvidenceResult>(), _time.GetUtcNow());
        IReadOnlyList<CheckedEvidence> checks = Array.Empty<CheckedEvidence>();
        if (_gate.CheckPreflight(firstLook).MayPerformLiveChecks)
            checks = await _checker.CheckAsync(snapshot.Evidence, _ => true, ct);

        var now = _time.GetUtcNow();
        var results = checks.Select(c => new LiveEvidenceResult(c.Evidence, c.Outcome, c.Evidence.Version, now)).ToList();
        var evaluation = _gate.Evaluate(BuildRequest(decisionId, actor, snapshot, trigger, normalizedTargets, results, now));

        return await PersistAsync(actor, snapshot, evaluation, checks, normalizedTargets, scheduleId, scheduledFor, now, ct);
    }

    private static ScanGateRequest BuildRequest(
        Guid decisionId, Actor actor, Snapshot s, DecisionTrigger trigger, IReadOnlyCollection<string> targets,
        IReadOnlyCollection<LiveEvidenceResult> results, DateTimeOffset now) =>
        new(decisionId, actor.OrganizationId, s.Domain.Id, s.User is not null, s.User, s.Membership, s.Organization, s.Grant, s.Domain,
            trigger, targets, s.Evidence, results, s.Rules, now);

    private async Task<Snapshot> LoadSnapshotAsync(Actor actor, Guid domainId, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var domain = await db.Domains.AsNoTracking().SingleOrDefaultAsync(d => d.Id == domainId, ct)
                     ?? throw new ServiceException("NotFound", "Domain not found.");
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == actor.UserId, ct);
        var membership = await db.Memberships.AsNoTracking()
            .SingleOrDefaultAsync(m => m.UserId == actor.UserId && m.OrganizationId == actor.OrganizationId, ct);
        var organization = await db.Organizations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == actor.OrganizationId, ct);
        var grant = await db.AuthorizationGrants.AsNoTracking()
            .Where(g => g.DomainId == domainId)
            .OrderBy(g => g.Status == GrantStatus.Active ? 0 : 1).ThenByDescending(g => g.AcceptedAt)
            .FirstOrDefaultAsync(ct);
        var evidence = await db.VerificationEvidence.AsNoTracking().Include(e => e.Challenge)
            .Where(e => e.DomainId == domainId).ToListAsync(ct);
        var rules = await db.ScopeRules.AsNoTracking().Where(r => r.DomainId == domainId && r.RemovedAt == null).ToListAsync(ct);
        return new Snapshot(user, membership, organization, grant, domain, evidence, rules);
    }

    private async Task<ScanStartResult> PersistAsync(
        Actor actor, Snapshot snapshot, GateEvaluation evaluation, IReadOnlyList<CheckedEvidence> checks,
        IReadOnlyList<string> targets, Guid? scheduleId, DateTimeOffset? scheduledFor, DateTimeOffset now, CancellationToken ct)
    {
        var decision = evaluation.Decision;
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);

            var changed = await EvidenceApplication.ApplyAsync(db, checks, evaluation.EvidenceChanges, now, $"gate:{decision.Id:D}", ct);
            await db.SaveChangesAsync(ct);
            if (changed.Count > 0)
            {
                var domain = await db.Domains.SingleAsync(d => d.Id == snapshot.Domain.Id, ct);
                await DomainStatusService.RecalculateAsync(db, domain, ct, _time);
            }

            db.PolicyDecisions.Add(decision);
            ScanRun? run = null;
            if (evaluation.Allowed)
            {
                run = new ScanRun
                {
                    Id = Guid.NewGuid(),
                    PolicyDecisionId = decision.Id,
                    ScheduleId = scheduleId,
                    ScheduledFor = scheduledFor,
                    Targets = targets.ToArray(),
                    Status = ScanRunStatus.Queued,
                    CreatedAt = now
                };
                db.ScanRuns.Add(run);
            }
            await db.SaveChangesAsync(ct);

            foreach (var entry in EvidenceApplication.AuditEntries(actor.OrganizationId, changed))
                await _audit.AppendAsync(db, entry, ct);

            var scheduled = decision.Trigger == DecisionTrigger.Scheduled;
            await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, scheduled ? "System" : "User", scheduled ? null : actor.UserId,
                evaluation.Allowed ? "scan.allowed" : "scan.denied", "PolicyDecision", decision.Id,
                new Dictionary<string, object?>
                {
                    ["domainId"] = decision.DomainId.ToString("D"),
                    ["trigger"] = decision.Trigger.ToString(),
                    ["targets"] = targets.Count,
                    ["failedCheck"] = decision.FailedCheckCode,
                    ["scanRunId"] = run?.Id.ToString("D")
                }, actor.Ip), ct);

            await tx.CommitAsync(ct);
            return new ScanStartResult(evaluation.Allowed, decision.Id, decision.FailedCheckCode, run?.Id, decision.ExpiresAt, false);
        }
        catch (DbUpdateException ex) when (scheduleId is not null && ex.InnerException is PostgresException { SqlState: "23505" })
        {
            // Another worker started this schedule occurrence first. Everything above was rolled back.
            var existing = await FindScheduledAsync(scheduleId.Value, scheduledFor!.Value, ct);
            return existing ?? throw new ServiceException("Busy", "This scheduled scan is being started elsewhere.");
        }
    }

    private async Task<ScanStartResult?> FindScheduledAsync(Guid scheduleId, DateTimeOffset scheduledFor, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var run = await db.ScanRuns.AsNoTracking().Include(r => r.PolicyDecision)
            .SingleOrDefaultAsync(r => r.ScheduleId == scheduleId && r.ScheduledFor == scheduledFor, ct);
        return run is null ? null : new ScanStartResult(true, run.PolicyDecisionId, null, run.Id, run.PolicyDecision.ExpiresAt, true);
    }
}
