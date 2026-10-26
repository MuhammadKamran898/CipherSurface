using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace CipherSurface.Services;

/// <summary>One evidence row and what the control plane learned about it just now.</summary>
internal sealed record CheckedEvidence(VerificationEvidence Evidence, CheckOutcome Outcome, string Reason, bool WasLive);

/// <summary>The evidence changed between reading it and acting on the result. The caller re-reads and starts again.</summary>
internal sealed class StaleSnapshotException : Exception
{
    public StaleSnapshotException() : base("The data changed while it was being checked.") { }
}

/// <summary>
/// Runs the live ownership checks the pure gates need. Active and AtRisk evidence of an observable method is
/// either checked now or, when the caller says it is fresh enough, reported as Inconclusive so the evaluator's
/// 24-hour rule decides from the stored state. Email evidence has nothing to observe and is skipped.
/// </summary>
internal sealed class LiveEvidenceChecker
{
    private readonly VerifierRegistry _registry;

    public LiveEvidenceChecker(VerifierRegistry registry) => _registry = registry;

    public async Task<IReadOnlyList<CheckedEvidence>> CheckAsync(
        IEnumerable<VerificationEvidence> evidence, Func<VerificationEvidence, bool> needsLiveCheck, CancellationToken ct)
    {
        var due = evidence
            .Where(e => e.Status is EvidenceStatus.Active or EvidenceStatus.AtRisk && MethodTraits.IsObservable(e.Method))
            .ToList();
        return await Task.WhenAll(due.Select(e => CheckOneAsync(e, needsLiveCheck(e), ct)));
    }

    private async Task<CheckedEvidence> CheckOneAsync(VerificationEvidence evidence, bool live, CancellationToken ct)
    {
        if (!live)
            return new CheckedEvidence(evidence, CheckOutcome.Inconclusive, "NotRechecked", WasLive: false);
        if (!_registry.TryGet(evidence.Method, out var verifier))
            return new CheckedEvidence(evidence, CheckOutcome.Inconclusive, "NoVerifier", WasLive: true);

        try
        {
            var observation = await verifier.CheckAsync(new VerificationRequest(evidence.Method, evidence.Host, evidence.Challenge.Token), ct);
            return new CheckedEvidence(evidence, observation.Outcome, observation.Reason, WasLive: true);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // A crashing verifier is "could not tell", never "proof is absent" and never "proof is valid".
            return new CheckedEvidence(evidence, CheckOutcome.Inconclusive, Reasons.VerifierError, WasLive: true);
        }
    }
}

internal static class EvidenceApplication
{
    /// <summary>
    /// Records the live checks and applies the evaluator's state changes to freshly loaded rows, inside the caller's
    /// transaction. Throws StaleSnapshotException if any checked row was modified since it was read.
    /// Returns the rows whose status changed, for auditing.
    ///
    /// A check run key identifies ONE evidence-check cycle of ONE evidence row (the unique index is
    /// (check_run_id, retry_number)), exactly as in EvidenceReverificationService. A single gate evaluation or
    /// continuation check often looks at several evidence rows, so each live check gets its own run key.
    /// "source" ties the checks back to the decision or scan run that caused them.
    /// </summary>
    public static async Task<List<(VerificationEvidence Evidence, EvidenceStatus Before)>> ApplyAsync(
        CipherSurfaceDbContext db, IReadOnlyList<CheckedEvidence> checks, IReadOnlyList<EvidenceStateChange> changes,
        DateTimeOffset now, string source, CancellationToken ct)
    {
        var ids = checks.Select(c => c.Evidence.Id).ToList();
        var tracked = await db.VerificationEvidence.Where(e => ids.Contains(e.Id)).ToDictionaryAsync(e => e.Id, ct);

        foreach (var check in checks)
        {
            if (!tracked.TryGetValue(check.Evidence.Id, out var row) || row.Version != check.Evidence.Version)
                throw new StaleSnapshotException();
        }

        foreach (var check in checks.Where(c => c.WasLive))
        {
            db.VerificationChecks.Add(new VerificationCheck
            {
                Id = Guid.NewGuid(),
                EvidenceId = check.Evidence.Id,
                CheckRunId = Guid.NewGuid(),   // one run key per evidence row, never shared
                RetryNumber = 0,
                CheckedAt = now,
                Outcome = check.Outcome,
                TriggeredBy = CheckTrigger.System,
                Detail = JsonSerializer.Serialize(new { reason = check.Reason, source })
            });
        }

        var changed = new List<(VerificationEvidence, EvidenceStatus)>();
        foreach (var change in changes)
        {
            if (!tracked.TryGetValue(change.EvidenceId, out var row)) throw new StaleSnapshotException();
            var before = row.Status;
            EvidenceChangeApplier.Apply(row, change);
            if (row.Status != before) changed.Add((row, before));
        }
        return changed;
    }

    public static IEnumerable<AuditEntry> AuditEntries(Guid organizationId, IEnumerable<(VerificationEvidence Evidence, EvidenceStatus Before)> changed)
    {
        foreach (var (evidence, before) in changed)
        {
            yield return new AuditEntry(organizationId, "System", null,
                evidence.Status == EvidenceStatus.AtRisk ? "evidence.at_risk" : "evidence.healed",
                "VerificationEvidence", evidence.Id,
                new Dictionary<string, object?>
                {
                    ["method"] = evidence.Method.ToString(),
                    ["from"] = before.ToString(),
                    ["to"] = evidence.Status.ToString()
                });
        }
    }
}
