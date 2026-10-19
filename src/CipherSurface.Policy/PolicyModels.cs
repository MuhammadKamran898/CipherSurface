using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;

namespace CipherSurface.Policy;

/// <summary>
/// Result of a live check performed by the control plane before calling the pure gate.
/// A null outcome is permitted only for terminal evidence that is not checked again.
/// Active and AtRisk evidence must have an outcome; absence is a fail-closed condition.
/// </summary>
public sealed record LiveEvidenceResult(
    VerificationEvidence Evidence,
    CheckOutcome? Outcome,
    uint CheckedVersion,
    DateTimeOffset CheckedAt);

/// <summary>A proof ceiling passed to the scope calculator after the evidence gate has qualified it.</summary>
public sealed record UsableEvidence(
    Guid Id,
    Guid DomainId,
    VerificationMethod Method,
    ScopeCeilingType ScopeCeilingType,
    string Host);

/// <summary>Proposed persistence update. The pure gate never mutates an EF entity.</summary>
public sealed record EvidenceStateChange(
    Guid EvidenceId,
    EvidenceStatus Status,
    DateTimeOffset? LastCheckedAt,
    DateTimeOffset? LastValidAt,
    DateTimeOffset? FailingSince);

public sealed record EvidenceEvaluation(
    IReadOnlyList<UsableEvidence> UsableEvidence,
    IReadOnlyList<EvidenceStateChange> StateChanges,
    string? ErrorCode)
{
    public bool Succeeded => ErrorCode is null;
}

public sealed record ScanGateRequest(
    Guid PolicyDecisionId,
    Guid RequestedOrganizationId,
    Guid RequestedDomainId,
    bool IsAuthenticated,
    User? Principal,
    Membership? Membership,
    Organization? Organization,
    AuthorizationGrant? AuthorizationGrant,
    Domain? Domain,
    DecisionTrigger Trigger,
    IReadOnlyCollection<string> TargetHosts,
    IReadOnlyCollection<VerificationEvidence> CurrentEvidence,
    IReadOnlyCollection<LiveEvidenceResult> EvidenceResults,
    IReadOnlyCollection<ScopeRule> ScopeRules,
    DateTimeOffset Now);

public sealed record ScanGateOptions
{
    public TimeSpan DecisionLifetime { get; init; } = TimeSpan.FromMinutes(15);
    public TimeSpan InconclusiveEvidenceLifetime { get; init; } = TimeSpan.FromHours(24);

    internal void Validate()
    {
        if (DecisionLifetime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(DecisionLifetime), "Decision lifetime must be positive.");
        if (InconclusiveEvidenceLifetime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(InconclusiveEvidenceLifetime), "Inconclusive allowance must be positive.");
    }
}

public sealed record GatePreflightResult(bool MayPerformLiveChecks, string? FailedCheckCode);

public sealed record GateEvaluation(
    PolicyDecision Decision,
    EffectiveScope? Scope,
    IReadOnlyList<EvidenceStateChange> EvidenceChanges)
{
    public bool Allowed => Decision.Outcome == DecisionOutcome.Allow;
    public string? FailedCheckCode => Decision.FailedCheckCode;
}

public sealed record ScanContinuationRequest(
    ScanRun Run,
    PolicyDecision StartDecision,
    Organization? Organization,
    Domain? Domain,
    AuthorizationGrant? AuthorizationGrant,
    IReadOnlyCollection<VerificationEvidence> CurrentEvidence,
    IReadOnlyCollection<LiveEvidenceResult> EvidenceResults,
    IReadOnlyCollection<ScopeRule> ScopeRules,
    IReadOnlyCollection<string> RemainingTargets,
    DateTimeOffset Now);

public sealed record ScanContinuationOptions
{
    public TimeSpan LeaseDuration { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan InconclusiveEvidenceLifetime { get; init; } = TimeSpan.FromHours(24);

    internal void Validate()
    {
        if (LeaseDuration <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(LeaseDuration), "Lease duration must be positive.");
        if (InconclusiveEvidenceLifetime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(InconclusiveEvidenceLifetime), "Inconclusive allowance must be positive.");
    }
}

public sealed record ContinuationEvaluation(
    ContinuationOutcome Outcome,
    string? ReasonCode,
    EffectiveScope? Scope,
    IReadOnlyList<string> AllowedTargets,
    IReadOnlyList<string> BlockedTargets,
    IReadOnlyList<EvidenceStateChange> EvidenceChanges,
    DateTimeOffset? NewLeaseExpiresAt,
    string ScopeHash)
{
    public bool MayProceed => Outcome is ContinuationOutcome.Continue or ContinuationOutcome.Restrict;
}
