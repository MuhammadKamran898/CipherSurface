using CipherSurface.Api.Contracts;
using CipherSurface.Api.RateLimiting;
using CipherSurface.Api.Security;
using CipherSurface.Data.Enums;
using CipherSurface.Services;

namespace CipherSurface.Api.Endpoints;

/// <summary>
/// Scope rules over ScopeRuleService. All rule semantics (normalization, wildcards, the limit, duplicate and conflict
/// handling) stay in the service and the policy engine; these endpoints only authorize, parse and shape the answer.
/// Reading is open to every member, also while the organization is suspended. Every write needs an Owner or Admin of an
/// active organization (checked first, see ManagerAccess) and counts against the governance rate limits. A rule or domain
/// of another organization answers NotFound, exactly like one that does not exist.
/// </summary>
public static class ScopeRuleEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/domains/{domainId:guid}/scope-rules", async (OrganizationContext org, Guid domainId, bool? includeRemoved,
            DomainQueryService queries, CancellationToken ct) =>
        {
            var rules = await queries.ListScopeRulesAsync(org.Actor, domainId, includeRemoved ?? false, ct);
            return Results.Ok(new ScopeRuleListResponse(rules.Select(ToResponse).ToList()));
        });

        api.MapGet("/scope-rules/{ruleId:guid}", async (OrganizationContext org, Guid ruleId, DomainQueryService queries, CancellationToken ct) =>
            Results.Ok(ToResponse(await queries.GetScopeRuleAsync(org.Actor, ruleId, ct))));

        api.MapPost("/domains/{domainId:guid}/scope-rules", async (OrganizationContext org, Guid domainId, ScopeRuleRequest request,
            ScopeRuleService rules, DomainQueryService queries, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);
            var type = ParseRuleType(request.RuleType);
            var id = await rules.CreateAsync(org.Actor, domainId, type, request.Pattern, ct);
            var created = await queries.GetScopeRuleAsync(org.Actor, id, ct);
            return Results.Created($"/api/v1/scope-rules/{id}", ToResponse(created));
        }).RequireGovernanceLimits();

        api.MapPut("/scope-rules/{ruleId:guid}", async (OrganizationContext org, Guid ruleId, ScopeRuleRequest request,
            ScopeRuleService rules, DomainQueryService queries, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);
            var type = ParseRuleType(request.RuleType);
            await rules.UpdateAsync(org.Actor, ruleId, type, request.Pattern, ct);
            return Results.Ok(ToResponse(await queries.GetScopeRuleAsync(org.Actor, ruleId, ct)));
        }).RequireGovernanceLimits();

        // A soft delete: the rule stays in the history. Removing it again is a conflict (RuleRemoved), not a silent success.
        api.MapDelete("/scope-rules/{ruleId:guid}", async (OrganizationContext org, Guid ruleId, ScopeRuleService rules, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);
            await rules.RemoveAsync(org.Actor, ruleId, ct);
            return Results.NoContent();
        }).RequireGovernanceLimits();
    }

    /// <summary>Exact name only. Numbers and comma lists, which Enum.TryParse would accept, are refused.</summary>
    private static ScopeRuleType ParseRuleType(string? raw)
    {
        var text = raw?.Trim();
        foreach (var candidate in Enum.GetValues<ScopeRuleType>())
            if (string.Equals(candidate.ToString(), text, StringComparison.OrdinalIgnoreCase)) return candidate;
        throw new ServiceException("InvalidRuleType", "The rule type must be Include or Exclude.");
    }

    private static ScopeRuleResponse ToResponse(ScopeRuleView r) =>
        new(r.Id, r.DomainId, r.RuleType, r.Pattern, r.CreatedByUserId, r.CreatedAt, r.RemovedAt);
}
