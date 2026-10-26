using CipherSurface.Data.Enums;

namespace CipherSurface.Data.Entities;

public class ScopeRule
{
    public Guid Id { get; set; }
    public Guid DomainId { get; set; }
    public ScopeRuleType RuleType { get; set; }
    /// <summary>Lower-case host or wildcard under the domain, e.g. "*.brightcart.com".</summary>
    public string Pattern { get; set; } = "";
    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RemovedAt { get; set; }   // soft delete

    public Domain Domain { get; set; } = null!;
}

/// <summary>Immutable record of one gate evaluation. Never updated after insert.</summary>
public class PolicyDecision
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DomainId { get; set; }
    public Guid? UserId { get; set; }                 // null for scheduled scans
    public DecisionTrigger Trigger { get; set; }
    public DecisionOutcome Outcome { get; set; }
    public string? FailedCheckCode { get; set; }      // required when Deny
    /// <summary>jsonb snapshot of the effective scope at decision time.</summary>
    public string EffectiveScopeSnapshot { get; set; } = "{}";
    public Guid[] EvidenceIds { get; set; } = [];
    public string ScopeRulesHash { get; set; } = "";
    public DateTimeOffset DecidedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }

    public ScanRun? ScanRun { get; set; }
}

public class ScanRun
{
    public Guid Id { get; set; }
    public Guid PolicyDecisionId { get; set; }        // NOT NULL + unique: one decision, one scan
    public Guid? ScheduleId { get; set; }
    public DateTimeOffset? ScheduledFor { get; set; }
    /// <summary>The normalized hosts this scan was authorized for. Never empty. A worker may only ever ask about these.</summary>
    public string[] Targets { get; set; } = [];
    public ScanRunStatus Status { get; set; } = ScanRunStatus.Queued;
    public DateTimeOffset? LeaseExpiresAt { get; set; }
    public DateTimeOffset? CancelRequestedAt { get; set; }
    public string? CancelReason { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public uint Version { get; set; }

    public PolicyDecision PolicyDecision { get; set; } = null!;
    public List<ScanRunAuthorizationCheck> AuthorizationChecks { get; set; } = [];
}

/// <summary>Execution-time continuation check (spec section 7.5). Append-only.</summary>
public class ScanRunAuthorizationCheck
{
    public Guid Id { get; set; }
    public Guid ScanRunId { get; set; }
    public int Sequence { get; set; }
    public DateTimeOffset CheckedAt { get; set; }
    public ContinuationOutcome Outcome { get; set; }
    public string? ReasonCode { get; set; }
    public string ScopeHash { get; set; } = "";
    public int TargetsRemaining { get; set; }

    public ScanRun ScanRun { get; set; } = null!;
}

/// <summary>Hash-chained, one chain per organization. Append-only.</summary>
public class AuditLog
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public long Sequence { get; set; }                // 1, 2, 3... per organization
    public DateTimeOffset OccurredAt { get; set; }
    public string ActorType { get; set; } = "";       // User | System | Worker | PlatformAdmin
    public Guid? ActorId { get; set; }
    public string Action { get; set; } = "";
    public string EntityType { get; set; } = "";
    public Guid? EntityId { get; set; }
    public string Data { get; set; } = "{}";          // jsonb, tokens redacted
    public string? Ip { get; set; }
    public byte[]? PrevHash { get; set; }             // null only for Sequence = 1
    public byte[] Hash { get; set; } = [];
}
