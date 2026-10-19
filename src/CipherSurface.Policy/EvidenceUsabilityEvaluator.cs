using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;

namespace CipherSurface.Policy;

/// <summary>
/// Applies the spec's ProofAbsent / ProofValid / Inconclusive precedence without network or persistence.
/// The separately loaded current evidence set is required so omission of an active row cannot be
/// mistaken for there being no such evidence. Returned changes must be persisted atomically by caller.
/// </summary>
public sealed class EvidenceUsabilityEvaluator
{
    public EvidenceEvaluation Evaluate(
        Guid domainId,
        IReadOnlyCollection<VerificationEvidence> currentEvidence,
        IReadOnlyCollection<LiveEvidenceResult> evidenceResults,
        DateTimeOffset now,
        TimeSpan inconclusiveAllowance)
    {
        ArgumentNullException.ThrowIfNull(currentEvidence);
        ArgumentNullException.ThrowIfNull(evidenceResults);
        if (inconclusiveAllowance <= TimeSpan.Zero)
            return new EvidenceEvaluation([], [], "InvalidInconclusiveAllowance");

        if (currentEvidence.Select(e => e.Id).Distinct().Count() != currentEvidence.Count)
            return new EvidenceEvaluation([], [], "DuplicateCurrentEvidence");
        if (evidenceResults.Select(r => r.Evidence.Id).Distinct().Count() != evidenceResults.Count)
            return new EvidenceEvaluation([], [], "DuplicateEvidenceResult");

        var currentById = currentEvidence.ToDictionary(e => e.Id);
        var resultById = evidenceResults.ToDictionary(r => r.Evidence.Id);
        var usable = new List<UsableEvidence>();
        var changes = new List<EvidenceStateChange>();
        string? errorCode = null;

        // Reject stale/foreign result sets. Hard deletes are prohibited, so a result whose row
        // is absent from the freshly loaded set indicates a race or bad caller snapshot.
        if (resultById.Keys.Any(id => !currentById.ContainsKey(id)))
            errorCode = "EvidenceResultNotInCurrentSnapshot";

        foreach (var evidence in currentEvidence)
        {
            if (evidence.DomainId != domainId)
            {
                errorCode ??= "EvidenceDomainMismatch";
                continue;
            }

            switch (evidence.Status)
            {
                case EvidenceStatus.Lapsed:
                case EvidenceStatus.Expired:
                case EvidenceStatus.Revoked:
                    // Terminal rows never revive and do not need a live check.
                    continue;

                case EvidenceStatus.Active:
                case EvidenceStatus.AtRisk:
                    break;

                default:
                    errorCode ??= "InvalidEvidenceStatus";
                    continue;
            }

            if (evidence.Method == VerificationMethod.AdminEmail && evidence.ExpiresAt is null)
            {
                errorCode ??= "EmailEvidenceExpiryMissing";
                continue;
            }
            if (evidence.Method != VerificationMethod.AdminEmail && evidence.ExpiresAt is not null)
            {
                errorCode ??= "UnexpectedEvidenceExpiry";
                continue;
            }

            // The email proof expires at the gate boundary even if the lifecycle job has not run.
            if (evidence.ExpiresAt is not null && evidence.ExpiresAt.Value <= now)
            {
                changes.Add(new EvidenceStateChange(
                    evidence.Id,
                    EvidenceStatus.Expired,
                    now,
                    evidence.LastValidAt,
                    null));
                continue;
            }

            if ((evidence.Status == EvidenceStatus.Active && evidence.FailingSince is not null) ||
                (evidence.Status == EvidenceStatus.AtRisk && evidence.FailingSince is null))
            {
                errorCode ??= "EvidenceStateInvariantViolation";
                continue;
            }

            // Admin-email proof is a one-time human confirmation that expires on its own. There is
            // nothing to observe live, so it is usable while Active and unexpired (checked above),
            // and any live result supplied for it is ignored. Observable methods continue below.
            if (evidence.Method == VerificationMethod.AdminEmail)
            {
                if (evidence.Status == EvidenceStatus.Active)
                    usable.Add(ToUsableEvidence(evidence));
                continue;
            }

            // Critical fail-closed check: every current Active/AtRisk row needs its own live result.
            if (!resultById.TryGetValue(evidence.Id, out var result))
            {
                errorCode ??= "LiveCheckMissing";
                continue;
            }

            if (result.Evidence.DomainId != evidence.DomainId)
            {
                errorCode ??= "EvidenceDomainMismatch";
                continue;
            }
            if (result.CheckedVersion != evidence.Version)
            {
                errorCode ??= "EvidenceChangedDuringLiveCheck";
                continue;
            }
            if (result.CheckedAt > now)
            {
                errorCode ??= "InvalidCheckTimestamp";
                continue;
            }
            if (result.Outcome is null)
            {
                errorCode ??= "LiveCheckMissing";
                continue;
            }

            switch (result.Outcome.Value)
            {
                case CheckOutcome.ProofAbsent:
                {
                    var failingSince = evidence.FailingSince ?? result.CheckedAt;
                    changes.Add(new EvidenceStateChange(
                        evidence.Id,
                        EvidenceStatus.AtRisk,
                        result.CheckedAt,
                        evidence.LastValidAt,
                        failingSince));
                    // A known absence excludes this row immediately, regardless of last_valid_at.
                    break;
                }
                case CheckOutcome.ProofValid:
                {
                    changes.Add(new EvidenceStateChange(
                        evidence.Id,
                        EvidenceStatus.Active,
                        result.CheckedAt,
                        result.CheckedAt,
                        null));
                    usable.Add(ToUsableEvidence(evidence));
                    break;
                }
                case CheckOutcome.Inconclusive:
                {
                    // The 24h fallback is unavailable to AtRisk rows or rows with a known failure.
                    if (evidence.Status == EvidenceStatus.Active &&
                        evidence.FailingSince is null &&
                        IsWithinAllowance(evidence.LastValidAt, now, inconclusiveAllowance))
                    {
                        usable.Add(ToUsableEvidence(evidence));
                    }
                    // Inconclusive records a check, but changes no evidence state by itself.
                    break;
                }
                default:
                    errorCode ??= "InvalidCheckOutcome";
                    break;
            }
        }

        if (errorCode is not null)
            return new EvidenceEvaluation([], changes, errorCode);

        return new EvidenceEvaluation(usable, changes, null);
    }

    private static bool IsWithinAllowance(DateTimeOffset? lastValidAt, DateTimeOffset now, TimeSpan allowance) =>
        lastValidAt is not null && lastValidAt.Value <= now && now - lastValidAt.Value <= allowance;

    private static UsableEvidence ToUsableEvidence(VerificationEvidence evidence) => new(
        evidence.Id,
        evidence.DomainId,
        evidence.Method,
        evidence.ScopeCeilingType,
        evidence.Host);
}
