using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;

namespace CipherSurface.Policy;

/// <summary>
/// Pure execution-time authorization for section 7.5. A Continue/Restrict result renews the
/// Run lease; the caller persists the check record, lease and proposed evidence changes atomically.
/// The start decision's expiry is intentionally not checked here: it is a start-by deadline only.
/// </summary>
public sealed class ScanContinuationGate
{
    private static readonly HashSet<DomainStatus> DomainStatusesThatStopExecution =
        [DomainStatus.Pending, DomainStatus.Failed, DomainStatus.Lapsed, DomainStatus.Revoked, DomainStatus.Disputed];

    private readonly ScopeCalculator _scopeCalculator;
    private readonly EvidenceUsabilityEvaluator _evidenceEvaluator;
    private readonly ScanContinuationOptions _options;

    public ScanContinuationGate(
        ScopeCalculator? scopeCalculator = null,
        EvidenceUsabilityEvaluator? evidenceEvaluator = null,
        ScanContinuationOptions? options = null)
    {
        _scopeCalculator = scopeCalculator ?? new ScopeCalculator();
        _evidenceEvaluator = evidenceEvaluator ?? new EvidenceUsabilityEvaluator();
        _options = options ?? new ScanContinuationOptions();
        _options.Validate();
    }

    public ContinuationEvaluation Evaluate(ScanContinuationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            return EvaluateCore(request);
        }
        catch (Exception)
        {
            return Cancel(request, "ContinuationEvaluationError");
        }
    }

    private ContinuationEvaluation EvaluateCore(ScanContinuationRequest request)
    {
        var run = request.Run;
        var decision = request.StartDecision;
        var remaining = request.RemainingTargets;

        if (run.CancelRequestedAt is not null || run.Status == ScanRunStatus.CancelRequested || run.Status == ScanRunStatus.Cancelled)
            return Cancel(request, "CancellationRequested");
        if (run.Status != ScanRunStatus.Running)
            return Cancel(request, "ScanRunNotRunning");
        if (decision.Outcome != DecisionOutcome.Allow)
            return Cancel(request, "StartDecisionNotAllowed");
        if (run.PolicyDecisionId != decision.Id)
            return Cancel(request, "StartDecisionMismatch");
        if (request.Organization is null || request.Domain is null)
            return Cancel(request, "OrganizationOrDomainMissing");
        if (request.Organization.Status != OrganizationStatus.Active)
            return Cancel(request, "OrganizationSuspended");
        if (request.Domain.OrganizationId != request.Organization.Id ||
            request.Domain.Id != decision.DomainId ||
            decision.OrganizationId != request.Organization.Id)
            return Cancel(request, "ScanOwnershipMismatch");
        if (request.AuthorizationGrant is null || request.AuthorizationGrant.Status != GrantStatus.Active)
            return Cancel(request, "AuthorizationGrantInactive");
        if (request.AuthorizationGrant.DomainId != request.Domain.Id ||
            request.AuthorizationGrant.OrganizationId != request.Organization.Id)
            return Cancel(request, "AuthorizationGrantMismatch");
        if (!Enum.IsDefined(request.Domain.Status) || DomainStatusesThatStopExecution.Contains(request.Domain.Status))
            return Cancel(request, "DomainNotScannable");
        if (request.CurrentEvidence is null || request.EvidenceResults is null || request.ScopeRules is null || remaining is null)
            return Cancel(request, "RequiredContinuationDataMissing");

        // Re-check all eligible evidence. Known ProofAbsent rows are dropped before any
        // Inconclusive fallback; Lapsed/Expired/Revoked rows are terminal and never revive.
        var evidence = _evidenceEvaluator.Evaluate(
            request.Domain.Id,
            request.CurrentEvidence,
            request.EvidenceResults,
            request.Now,
            _options.InconclusiveEvidenceLifetime);
        if (!evidence.Succeeded)
            return Cancel(request, evidence.ErrorCode!, evidence.StateChanges);

        var scopeResult = _scopeCalculator.Calculate(
            request.Domain.Id,
            request.Domain.Name,
            evidence.UsableEvidence,
            request.ScopeRules);
        if (!scopeResult.Succeeded)
            return Cancel(request, scopeResult.ErrorCode ?? "InvalidScopeData", evidence.StateChanges);

        var scope = scopeResult.Scope!;
        if (scope.IsEmpty)
            return Cancel(request, "NoEffectiveScope", evidence.StateChanges, scope);

        // The scan may continue for the still-authorized subset. Out-of-scope targets are
        // returned as blocked; callers must not dispatch them to a worker.
        var allowed = new List<string>();
        var blocked = new List<string>();
        foreach (var target in remaining)
        {
            if (scope.ContainsHost(target) && TryNormalizeTarget(target, out var normalized))
                allowed.Add(normalized);
            else
                blocked.Add(target);
        }

        if (allowed.Count == 0)
            return Cancel(request, "NoAuthorizedTargetsRemain", evidence.StateChanges, scope, blocked);

        var outcome = blocked.Count == 0 ? ContinuationOutcome.Continue : ContinuationOutcome.Restrict;
        return new ContinuationEvaluation(
            outcome,
            outcome == ContinuationOutcome.Restrict ? "TargetsOutsideCurrentScope" : null,
            scope,
            allowed,
            blocked,
            evidence.StateChanges,
            request.Now + _options.LeaseDuration,
            scope.Hash);
    }

    private static ContinuationEvaluation Cancel(
        ScanContinuationRequest request,
        string reasonCode,
        IReadOnlyList<EvidenceStateChange>? changes = null,
        EffectiveScope? scope = null,
        IReadOnlyList<string>? alreadyBlocked = null)
    {
        var blocked = alreadyBlocked ?? request.RemainingTargets?.ToArray() ?? [];
        return new ContinuationEvaluation(
            ContinuationOutcome.Cancel,
            reasonCode,
            scope,
            [],
            blocked,
            changes ?? [],
            null,
            scope?.Hash ?? ScopeCalculator.ComputeScopeHash(string.Empty, Array.Empty<string>(), Array.Empty<string>()));
    }

    private static bool TryNormalizeTarget(string host, out string normalized)
    {
        var candidate = host.Trim();
        if (candidate.EndsWith(".", StringComparison.Ordinal))
            candidate = candidate[..^1];
        try
        {
            normalized = new System.Globalization.IdnMapping { UseStd3AsciiRules = true }
                .GetAscii(candidate).ToLowerInvariant();
            return true;
        }
        catch (ArgumentException)
        {
            normalized = string.Empty;
            return false;
        }
    }
}
