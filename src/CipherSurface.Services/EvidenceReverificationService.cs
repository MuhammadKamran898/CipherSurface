using System.Text.Json;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace CipherSurface.Services;

public static class EvidenceChangeApplier
{
    /// <summary>Persists a state change computed by the Policy evaluator. One place, shared by every caller.</summary>
    public static void Apply(VerificationEvidence evidence, EvidenceStateChange change)
    {
        evidence.Status = change.Status;
        evidence.LastCheckedAt = change.LastCheckedAt;
        evidence.LastValidAt = change.LastValidAt;
        evidence.FailingSince = change.FailingSince;
    }
}

public enum ReverifyStatus { Applied, AlreadyProcessed, Skipped }

public sealed record ReverifyResult(
    ReverifyStatus Status, CheckOutcome? Outcome, EvidenceStatus? EvidenceStatus, DomainStatus? DomainStatus, string? Reason);

/// <summary>
/// Re-checks the proof of one evidence row (DNS, HTTP file or meta tag; email has nothing to observe).
/// The state rules come from Policy's EvidenceUsabilityEvaluator, so the gate and this job cannot
/// disagree. The idempotency key is (checkRunId, retryNumber): a retried Hangfire job reuses its key
/// and is recognised, while a new daily or pre-scan check gets a new checkRunId.
/// </summary>
public sealed class EvidenceReverificationService
{
    private static readonly TimeSpan InconclusiveAllowance = TimeSpan.FromHours(24);

    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly VerifierRegistry _registry;
    private readonly AuditLogWriter _audit;
    private readonly EvidenceUsabilityEvaluator _evaluator;

    public EvidenceReverificationService(
        IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, VerifierRegistry registry,
        AuditLogWriter audit, EvidenceUsabilityEvaluator? evaluator = null)
    {
        _factory = factory;
        _time = time;
        _registry = registry;
        _audit = audit;
        _evaluator = evaluator ?? new EvidenceUsabilityEvaluator();
    }

    public async Task<ReverifyResult> ReverifyAsync(Guid evidenceId, Guid checkRunId, int retryNumber, CancellationToken ct)
    {
        // ---- 1. Snapshot (no network, no lock) ----
        VerificationMethod method;
        string host, token;
        uint version;
        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            if (await db.VerificationChecks.AnyAsync(c => c.CheckRunId == checkRunId && c.RetryNumber == retryNumber, ct))
                return Skip(ReverifyStatus.AlreadyProcessed, "AlreadyProcessed");

            var snapshot = await db.VerificationEvidence.AsNoTracking().Include(e => e.Challenge)
                .SingleOrDefaultAsync(e => e.Id == evidenceId, ct);
            if (snapshot is null) return Skip(ReverifyStatus.Skipped, "NotFound");
            if (!MethodTraits.IsObservable(snapshot.Method)) return Skip(ReverifyStatus.Skipped, "NotObservable");
            if (snapshot.Status is not (EvidenceStatus.Active or EvidenceStatus.AtRisk)) return Skip(ReverifyStatus.Skipped, "TerminalEvidence");

            method = snapshot.Method;
            host = snapshot.Host;
            token = snapshot.Challenge.Token;
            version = snapshot.Version;
        }

        // ---- 2. Observe ----
        if (!_registry.TryGet(method, out var verifier)) return Skip(ReverifyStatus.Skipped, "NoVerifier");
        var observation = await verifier.CheckAsync(new VerificationRequest(method, host, token), ct);

        // ---- 3. Record and apply (one transaction) ----
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);

            var evidence = await db.VerificationEvidence.Include(e => e.Domain).SingleAsync(e => e.Id == evidenceId, ct);
            if (evidence.Version != version || evidence.Status is not (EvidenceStatus.Active or EvidenceStatus.AtRisk))
                return Skip(ReverifyStatus.Skipped, "ChangedDuringCheck");

            var now = _time.GetUtcNow();
            db.VerificationChecks.Add(new VerificationCheck
            {
                Id = Guid.NewGuid(),
                EvidenceId = evidence.Id,
                CheckRunId = checkRunId,
                RetryNumber = retryNumber,
                CheckedAt = now,
                Outcome = observation.Outcome,
                TriggeredBy = CheckTrigger.System,
                Detail = JsonSerializer.Serialize(new { reason = observation.Reason })
            });

            var before = evidence.Status;
            var evaluation = _evaluator.Evaluate(
                evidence.DomainId,
                new[] { evidence },
                new[] { new LiveEvidenceResult(evidence, observation.Outcome, version, now) },
                now, InconclusiveAllowance);
            if (!evaluation.Succeeded)
                throw new InvalidOperationException($"Evidence evaluation failed: {evaluation.ErrorCode}");

            var change = evaluation.StateChanges.SingleOrDefault();
            if (change is not null)
                EvidenceChangeApplier.Apply(evidence, change);
            else
                evidence.LastCheckedAt = now;                       // Inconclusive: record the check, change no state
            await db.SaveChangesAsync(ct);

            var domainStatus = await DomainStatusService.RecalculateAsync(db, evidence.Domain, ct);

            if (evidence.Status != before)
            {
                await _audit.AppendAsync(db, new AuditEntry(evidence.Domain.OrganizationId, "System", null,
                    evidence.Status == EvidenceStatus.AtRisk ? "evidence.at_risk" : "evidence.healed",
                    "VerificationEvidence", evidence.Id,
                    new Dictionary<string, object?>
                    {
                        ["method"] = evidence.Method.ToString(),
                        ["from"] = before.ToString(),
                        ["to"] = evidence.Status.ToString(),
                        ["domainStatus"] = domainStatus.ToString()
                    }), ct);
            }

            await tx.CommitAsync(ct);
            return new ReverifyResult(ReverifyStatus.Applied, observation.Outcome, evidence.Status, domainStatus, observation.Reason);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: "23505" })
        {
            return Skip(ReverifyStatus.AlreadyProcessed, "AlreadyProcessed");   // a duplicate run won the race
        }
        catch (DbUpdateConcurrencyException)
        {
            return Skip(ReverifyStatus.Skipped, "ChangedDuringCheck");
        }
    }

    private static ReverifyResult Skip(ReverifyStatus status, string reason) => new(status, null, null, null, reason);
}
