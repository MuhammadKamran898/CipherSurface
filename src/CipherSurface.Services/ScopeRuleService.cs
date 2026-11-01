using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

/// <summary>
/// Creates, changes and soft-removes the include and exclude rules of a domain (FR-B7, FR-B8).
///
/// Nothing here stores an effective scope. The scan gate and the continuation check recalculate it from the live rules
/// every time, so a change made here applies to the next start decision and to the next check of a running scan.
///
/// Every change to one domain runs under a transaction-scoped advisory lock on that domain's rules, so the duplicate
/// check and the rule limit cannot be raced. The lock is taken before the audit lock (taken inside AuditLogWriter),
/// and nothing takes them in the other order.
/// </summary>
public sealed class ScopeRuleService
{
    public const int DefaultMaxLiveRulesPerDomain = 100;

    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;
    private readonly int _maxLiveRules;

    public ScopeRuleService(
        IDbContextFactory<CipherSurfaceDbContext> factory,
        TimeProvider time,
        AuditLogWriter audit,
        int maxLiveRulesPerDomain = DefaultMaxLiveRulesPerDomain)
    {
        if (maxLiveRulesPerDomain < 1)
            throw new ArgumentOutOfRangeException(nameof(maxLiveRulesPerDomain), "At least one rule must be allowed.");

        _factory = factory;
        _time = time;
        _audit = audit;
        _maxLiveRules = maxLiveRulesPerDomain;
    }

    /// <summary>Adds a rule to one of the actor's own domains. Returns the new rule's id.</summary>
    public async Task<Guid> CreateAsync(Actor actor, Guid domainId, ScopeRuleType type, string? pattern, CancellationToken ct)
    {
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            await Access.RequireManagerAsync(db, actor, ct);
            var domain = await Access.LoadOwnDomainAsync(db, actor, domainId, ct);
            RequireDefined(type);
            var normalized = Normalize(pattern, domain.Name);

            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(db, LockKey(domain.Id), ct);

            var live = await db.ScopeRules.AsNoTracking()
                .Where(r => r.DomainId == domain.Id && r.RemovedAt == null)
                .ToListAsync(ct);

            if (live.Any(r => r.RuleType == type && r.Pattern == normalized))
                throw new ServiceException("RuleExists", "This rule already exists for the domain.");
            if (live.Count >= _maxLiveRules)
                throw new ServiceException("TooManyRules", $"A domain can have at most {_maxLiveRules} scope rules. Remove one first.");

            var rule = new ScopeRule
            {
                Id = Guid.NewGuid(),
                DomainId = domain.Id,
                RuleType = type,
                Pattern = normalized,
                CreatedByUserId = actor.UserId,
                CreatedAt = _time.GetUtcNow()
            };
            db.ScopeRules.Add(rule);
            await db.SaveChangesAsync(ct);

            await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "scope.rule.created", "ScopeRule", rule.Id,
                new Dictionary<string, object?>
                {
                    ["domainId"] = domain.Id.ToString("D"),
                    ["ruleType"] = type.ToString(),
                    ["pattern"] = normalized,
                    ["scopeRulesHash"] = ScopeCalculator.ComputeScopeRulesHash(live.Append(rule))
                }, actor.Ip), ct);

            await tx.CommitAsync(ct);
            return rule.Id;
        }
        catch (DbUpdateConcurrencyException)
        {
            throw Busy();
        }
    }

    /// <summary>
    /// Changes the type and pattern of a live rule. Saying the same thing again changes nothing and writes no audit entry.
    /// A removed rule cannot be changed: create a new rule instead.
    /// </summary>
    public async Task UpdateAsync(Actor actor, Guid ruleId, ScopeRuleType type, string? pattern, CancellationToken ct)
    {
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            await Access.RequireManagerAsync(db, actor, ct);
            var domain = await FindOwnDomainOfRuleAsync(db, actor, ruleId, ct);
            RequireDefined(type);
            var normalized = Normalize(pattern, domain.Name);

            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(db, LockKey(domain.Id), ct);

            // Read again under the lock: the rule may have been changed or removed while this call waited.
            var rule = await db.ScopeRules.SingleAsync(r => r.Id == ruleId, ct);
            if (rule.RemovedAt is not null)
                throw RuleRemoved();

            if (rule.RuleType == type && rule.Pattern == normalized)
                return;

            var others = await LiveRulesExceptAsync(db, domain.Id, rule.Id, ct);
            if (others.Any(r => r.RuleType == type && r.Pattern == normalized))
                throw new ServiceException("RuleExists", "This rule already exists for the domain.");

            var previousType = rule.RuleType;
            var previousPattern = rule.Pattern;
            rule.RuleType = type;
            rule.Pattern = normalized;
            await db.SaveChangesAsync(ct);

            await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "scope.rule.updated", "ScopeRule", rule.Id,
                new Dictionary<string, object?>
                {
                    ["domainId"] = domain.Id.ToString("D"),
                    ["previousRuleType"] = previousType.ToString(),
                    ["previousPattern"] = previousPattern,
                    ["ruleType"] = type.ToString(),
                    ["pattern"] = normalized,
                    ["scopeRulesHash"] = ScopeCalculator.ComputeScopeRulesHash(others.Append(rule))
                }, actor.Ip), ct);

            await tx.CommitAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw Busy();
        }
    }

    /// <summary>Soft-removes a rule: the row and its history stay, it just stops counting.</summary>
    public async Task RemoveAsync(Actor actor, Guid ruleId, CancellationToken ct)
    {
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            await Access.RequireManagerAsync(db, actor, ct);
            var domain = await FindOwnDomainOfRuleAsync(db, actor, ruleId, ct);

            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(db, LockKey(domain.Id), ct);

            var rule = await db.ScopeRules.SingleAsync(r => r.Id == ruleId, ct);
            if (rule.RemovedAt is not null)
                throw RuleRemoved();

            rule.RemovedAt = _time.GetUtcNow();
            await db.SaveChangesAsync(ct);

            var remaining = await LiveRulesExceptAsync(db, domain.Id, rule.Id, ct);
            await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "scope.rule.removed", "ScopeRule", rule.Id,
                new Dictionary<string, object?>
                {
                    ["domainId"] = domain.Id.ToString("D"),
                    ["ruleType"] = rule.RuleType.ToString(),
                    ["pattern"] = rule.Pattern,
                    ["scopeRulesHash"] = ScopeCalculator.ComputeScopeRulesHash(remaining)
                }, actor.Ip), ct);

            await tx.CommitAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw Busy();
        }
    }

    // ------------------------------------------------------------------ helpers

    private static string LockKey(Guid domainId) => $"scope:{domainId:D}";

    /// <summary>
    /// Finds the domain of a rule, but only inside the actor's organization. A rule of another organization
    /// gets the same answer as a rule that does not exist.
    /// </summary>
    private static async Task<Domain> FindOwnDomainOfRuleAsync(CipherSurfaceDbContext db, Actor actor, Guid ruleId, CancellationToken ct)
    {
        var domain = await db.Domains.AsNoTracking()
            .Where(d => d.OrganizationId == actor.OrganizationId && d.ScopeRules.Any(r => r.Id == ruleId))
            .SingleOrDefaultAsync(ct);
        return domain ?? throw new ServiceException("NotFound", "Scope rule not found.");
    }

    private static Task<List<ScopeRule>> LiveRulesExceptAsync(CipherSurfaceDbContext db, Guid domainId, Guid exceptRuleId, CancellationToken ct) =>
        db.ScopeRules.AsNoTracking()
            .Where(r => r.DomainId == domainId && r.RemovedAt == null && r.Id != exceptRuleId)
            .ToListAsync(ct);

    private static void RequireDefined(ScopeRuleType type)
    {
        if (!Enum.IsDefined(type))
            throw new ServiceException("InvalidRuleType", "The rule type must be Include or Exclude.");
    }

    private static string Normalize(string? pattern, string domainName)
    {
        if (ScopePatterns.TryNormalize(pattern, domainName, out var normalized, out var error))
            return normalized;

        throw error == ScopePatterns.OutsideDomain
            ? new ServiceException("PatternOutsideDomain", $"The pattern must be {domainName} or a host under it.")
            : new ServiceException("PatternInvalid", "Enter a host name such as www.example.com, or a wildcard such as *.example.com.");
    }

    private static ServiceException RuleRemoved() => new("RuleRemoved", "This scope rule was already removed.");

    private static ServiceException Busy() => new("Busy", "This scope rule was changed at the same time. Reload it and try again.");
}
