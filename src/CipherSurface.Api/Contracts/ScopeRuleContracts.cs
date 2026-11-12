using CipherSurface.Data.Enums;

namespace CipherSurface.Api.Contracts;

/// <summary>RuleType is "Include" or "Exclude" (any letter case, nothing else). The pattern is normalized by the server.</summary>
public sealed record ScopeRuleRequest(string? RuleType, string? Pattern);

public sealed record ScopeRuleResponse(
    Guid Id, Guid DomainId, ScopeRuleType RuleType, string Pattern, Guid CreatedByUserId, DateTimeOffset CreatedAt, DateTimeOffset? RemovedAt);

public sealed record ScopeRuleListResponse(IReadOnlyList<ScopeRuleResponse> Items);
