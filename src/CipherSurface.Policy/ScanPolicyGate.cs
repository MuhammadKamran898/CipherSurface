using System.Security.Cryptography;
using System.Text;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;

namespace CipherSurface.Policy;

/// <summary>
/// Pure start-authorization gate. The caller loads a consistent snapshot and obtains every
/// required live evidence result before evaluating this object. This class performs no I/O.
/// </summary>
public sealed class ScanPolicyGate
{
    private static readonly HashSet<MembershipRole> RolesAllowedToScan =
        [MembershipRole.Owner, MembershipRole.Admin, MembershipRole.Analyst];

    private static readonly HashSet<DomainStatus> DomainStatusesBlockedAtStart =
        [DomainStatus.Pending, DomainStatus.Failed, DomainStatus.Revoked, DomainStatus.Disputed, DomainStatus.Lapsed];

    private readonly ScopeCalculator _scopeCalculator;
    private readonly EvidenceUsabilityEvaluator _evidenceEvaluator;
    private readonly ScanGateOptions _options;

    public ScanPolicyGate(
        ScopeCalculator? scopeCalculator = null,
        EvidenceUsabilityEvaluator? evidenceEvaluator = null,
        ScanGateOptions? options = null)
    {
        _scopeCalculator = scopeCalculator ?? new ScopeCalculator();
        _evidenceEvaluator = evidenceEvaluator ?? new EvidenceUsabilityEvaluator();
        _options = options ?? new ScanGateOptions();
        _options.Validate();
    }

    /// <summary>
    /// Run before doing outbound verifier calls. A failure means no live evidence requests are
    /// needed; the caller can call Evaluate with empty results to produce the immutable Deny decision.
    /// This preserves the spec's cheap-first gate order.
    /// </summary>
    public GatePreflightResult CheckPreflight(ScanGateRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            var code = GetPreflightFailureCode(request);
            return new GatePreflightResult(code is null, code);
        }
        catch (Exception)
        {
            return new GatePreflightResult(false, "GatePreflightError");
        }
    }

    public GateEvaluation Evaluate(ScanGateRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            return EvaluateCore(request);
        }
        catch (Exception)
        {
            // The specification requires fail-closed behavior for any gate exception.
            // Do not include exception text in API/audit responses; it may contain sensitive data.
            return BuildResult(request, DecisionOutcome.Deny, "GateEvaluationError", null, [], []);
        }
    }

    private GateEvaluation EvaluateCore(ScanGateRequest request)
    {
        var rulesHash = SafeRulesHash(request.ScopeRules);
        var preflightFailure = GetPreflightFailureCode(request);
        if (preflightFailure is not null)
            return BuildResult(request, DecisionOutcome.Deny, preflightFailure, null, [], [], rulesHash: rulesHash);

        if (request.CurrentEvidence is null || request.EvidenceResults is null || request.ScopeRules is null || request.TargetHosts is null)
            return BuildResult(request, DecisionOutcome.Deny, "RequiredGateDataMissing", null, [], [], rulesHash: rulesHash);

        var domain = request.Domain;
        if (domain is null)
            return BuildResult(request, DecisionOutcome.Deny, "DomainMissing", null, [], [], rulesHash: rulesHash);

        // 5. Apply all live evidence outcomes only after they have been collected.
        var evidence = _evidenceEvaluator.Evaluate(
            domain.Id,
            request.CurrentEvidence,
            request.EvidenceResults,
            request.Now,
            _options.InconclusiveEvidenceLifetime);
        if (!evidence.Succeeded)
            return Deny(evidence.ErrorCode! , evidence.StateChanges, evidence.UsableEvidence.Select(x => x.Id));

        // 6. Calculate the effective scope from usable evidence and current scope rules.
        var scopeResult = _scopeCalculator.Calculate(
            domain.Id,
            domain.Name,
            evidence.UsableEvidence,
            request.ScopeRules);
        if (!scopeResult.Succeeded)
            return Deny(scopeResult.ErrorCode ?? "InvalidScopeData", evidence.StateChanges, evidence.UsableEvidence.Select(x => x.Id));

        var scope = scopeResult.Scope!;
        if (scope.IsEmpty)
            return Deny("NoEffectiveScope", evidence.StateChanges, evidence.UsableEvidence.Select(x => x.Id), scope);

        // 7. Every host this scan will touch must fall inside the current effective scope.
        if (request.TargetHosts.Count == 0)
            return Deny("NoTargetsProvided", evidence.StateChanges, evidence.UsableEvidence.Select(x => x.Id), scope);

        // Do not short-circuit after the first target: the persisted snapshot represents the
        // complete effective scope, and every requested host must be authorized.
        if (request.TargetHosts.Any(host => !scope.ContainsHost(host)))
            return Deny("TargetOutsideEffectiveScope", evidence.StateChanges, evidence.UsableEvidence.Select(x => x.Id), scope);

        return BuildResult(
            request,
            DecisionOutcome.Allow,
            null,
            scope,
            evidence.StateChanges,
            evidence.UsableEvidence.Select(x => x.Id),
            rulesHash: rulesHash);

        GateEvaluation Deny(
            string code,
            IReadOnlyList<EvidenceStateChange>? changes = null,
            IEnumerable<Guid>? evidenceIds = null,
            EffectiveScope? effectiveScope = null) =>
            BuildResult(request, DecisionOutcome.Deny, code, effectiveScope, changes ?? [], evidenceIds ?? [], rulesHash);
    }

    private static string? GetPreflightFailureCode(ScanGateRequest request)
    {
        // 1. Authenticated principal and a role allowed to scan.
        if (!request.IsAuthenticated || request.Principal is null)
            return "AuthenticationRequired";
        if (request.Principal.Status != UserStatus.Active)
            return "UserInactive";
        if (request.Membership is null)
            return "MembershipMissing";
        if (!RolesAllowedToScan.Contains(request.Membership.Role))
            return "RoleNotPermitted";
        if (request.Membership.UserId != request.Principal.Id ||
            request.Membership.OrganizationId != request.RequestedOrganizationId)
            return "MembershipMismatch";
        if (!Enum.IsDefined(request.Trigger))
            return "InvalidTrigger";

        // 2. Organization and active membership context.
        if (request.Organization is null || request.Organization.Id != request.RequestedOrganizationId)
            return "OrganizationMissing";
        if (request.Organization.Status != OrganizationStatus.Active)
            return "OrganizationSuspended";

        // 3. Authorization grant must be active and match the organization/domain.
        if (request.AuthorizationGrant is null)
            return "AuthorizationGrantMissing";
        if (request.AuthorizationGrant.OrganizationId != request.Organization.Id)
            return "GrantOrganizationMismatch";
        if (request.AuthorizationGrant.DomainId != request.RequestedDomainId)
            return "GrantDomainMismatch";
        if (request.AuthorizationGrant.Status != GrantStatus.Active)
            return "AuthorizationGrantInactive";

        // 4. Domain status and ownership checks.
        if (request.Domain is null || request.Domain.Id != request.RequestedDomainId)
            return "DomainMissing";
        if (request.Domain.OrganizationId != request.Organization.Id)
            return "DomainOrganizationMismatch";
        if (!Enum.IsDefined(request.Domain.Status) || DomainStatusesBlockedAtStart.Contains(request.Domain.Status))
            return "DomainNotScannable";

        return null;
    }

    private GateEvaluation BuildResult(
        ScanGateRequest request,
        DecisionOutcome outcome,
        string? failedCode,
        EffectiveScope? scope,
        IReadOnlyList<EvidenceStateChange> evidenceChanges,
        IEnumerable<Guid> evidenceIds,
        string? rulesHash = null)
    {
        var now = request.Now;
        var hash = rulesHash ?? SafeRulesHash(request.ScopeRules);
        var snapshot = scope is null
            ? "{}"
            : scope.ToSnapshotJson();
        var decision = new PolicyDecision
        {
            Id = request.PolicyDecisionId,
            OrganizationId = request.RequestedOrganizationId,
            DomainId = request.RequestedDomainId,
            UserId = request.Trigger == DecisionTrigger.Scheduled ? null : request.Principal?.Id,
            Trigger = request.Trigger,
            Outcome = outcome,
            FailedCheckCode = outcome == DecisionOutcome.Deny ? failedCode ?? "GateDenied" : null,
            EffectiveScopeSnapshot = snapshot,
            EvidenceIds = evidenceIds.Distinct().OrderBy(x => x).ToArray(),
            ScopeRulesHash = hash,
            DecidedAt = now,
            ExpiresAt = now + _options.DecisionLifetime
        };
        return new GateEvaluation(decision, scope, evidenceChanges);
    }

    private static string SafeRulesHash(IReadOnlyCollection<ScopeRule>? rules)
    {
        try
        {
            if (rules is null)
                return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("missing-scope-rules"))).ToLowerInvariant();
            return ScopeCalculator.ComputeScopeRulesHash(rules);
        }
        catch (Exception)
        {
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("invalid-scope-rules"))).ToLowerInvariant();
        }
    }

}
