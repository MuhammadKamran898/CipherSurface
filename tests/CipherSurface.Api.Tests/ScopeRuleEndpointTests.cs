using System.Net;
using System.Text.Json;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using CipherSurface.Services.Tests;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static CipherSurface.Api.Tests.DomainKit;

namespace CipherSurface.Api.Tests;

/// <summary>
/// Scope rule endpoints over HTTP, against a real database. How patterns are normalized, how wildcards and exclusions
/// work and how a rule set becomes a scan scope is tested in the service and policy tests; these tests cover who may do
/// what, tenant isolation, the error contract, the audit trail, and that the HTTP layer adds no rules of its own.
/// </summary>
[Collection("postgres")]
public class ScopeRuleEndpointTests
{
    private readonly PostgresFixture _postgres;
    public ScopeRuleEndpointTests(PostgresFixture postgres) => _postgres = postgres;

    private static Task<HttpResponseMessage> CreateAsync(ApiHost host, string bearer, Guid domainId, string? ruleType, string? pattern, Guid? org = null) =>
        host.SendAsync(HttpMethod.Post, $"{V1}/domains/{domainId}/scope-rules", new { ruleType, pattern }, bearer, org);

    private static Task<HttpResponseMessage> UpdateAsync(ApiHost host, string bearer, Guid ruleId, string? ruleType, string? pattern, Guid? org = null) =>
        host.SendAsync(HttpMethod.Put, $"{V1}/scope-rules/{ruleId}", new { ruleType, pattern }, bearer, org);

    private static Task<HttpResponseMessage> DeleteAsync(ApiHost host, string bearer, Guid ruleId, Guid? org = null) =>
        host.SendAsync(HttpMethod.Delete, $"{V1}/scope-rules/{ruleId}", null, bearer, org);

    private static Task<HttpResponseMessage> ListAsync(ApiHost host, string bearer, Guid domainId, string query = "", Guid? org = null) =>
        host.GetAsync($"{V1}/domains/{domainId}/scope-rules{query}", bearer, org);

    private static Task<HttpResponseMessage> GetAsync(ApiHost host, string bearer, Guid ruleId, Guid? org = null) =>
        host.GetAsync($"{V1}/scope-rules/{ruleId}", bearer, org);

    private static async Task<Guid> AddRuleAsync(ApiHost host, string bearer, Guid domainId, string ruleType, string pattern, Guid? org = null)
    {
        var body = await BodyAsync(await CreateAsync(host, bearer, domainId, ruleType, pattern, org), HttpStatusCode.Created);
        return body.GetProperty("id").GetGuid();
    }

    private static string[] Patterns(JsonElement list) =>
        list.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("pattern").GetString()!).ToArray();

    private static async Task<List<JsonElement>> AuditAsync(ApiHost host, string action)
    {
        await using var db = host.Database.CreateDbContext();
        var rows = await db.AuditLogs.Where(a => a.Action == action).OrderBy(a => a.Sequence).ToListAsync();
        return rows.Select(r => JsonDocument.Parse(r.Data).RootElement.Clone()).ToList();
    }

    // ------------------------------------------------------------------ create and read

    [Fact]
    public async Task AnOwnerCreatesARule_TheServerNormalizesIt_AndTheAuditCarriesTheRulesHash()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        var response = await CreateAsync(host, org.Owner.Access, domainId, "include", "  WWW.Example.COM. ");
        var body = await BodyAsync(response, HttpStatusCode.Created);
        var id = body.GetProperty("id").GetGuid();

        Assert.Equal($"/api/v1/scope-rules/{id}", response.Headers.Location!.ToString());
        Assert.Equal("Include", body.GetProperty("ruleType").GetString());
        Assert.Equal("www.example.com", body.GetProperty("pattern").GetString());
        Assert.Equal(domainId, body.GetProperty("domainId").GetGuid());
        Assert.Equal(org.OwnerId, body.GetProperty("createdByUserId").GetGuid());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("removedAt").ValueKind);

        var fetched = await Check.JsonAsync(await GetAsync(host, org.Owner.Access, id));
        Assert.Equal("www.example.com", fetched.GetProperty("pattern").GetString());

        // The audit entry records who, from where, and the hash the policy engine computes for the live rule set.
        await using var db = host.Database.CreateDbContext();
        var entry = await db.AuditLogs.SingleAsync(a => a.Action == "scope.rule.created");
        Assert.Equal(org.OwnerId, entry.ActorId);
        Assert.Equal("127.0.0.1", entry.Ip);
        var live = await db.ScopeRules.Where(r => r.DomainId == domainId && r.RemovedAt == null).ToListAsync();
        var data = JsonDocument.Parse(entry.Data).RootElement;
        Assert.Equal(ScopeCalculator.ComputeScopeRulesHash(live), data.GetProperty("scopeRulesHash").GetString());
        Assert.Equal("www.example.com", data.GetProperty("pattern").GetString());
    }

    [Fact]
    public async Task TheListShowsLiveRulesOldestFirst_AndWildcardsAndExclusionsAreAcceptedAsTheyAre()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "*.example.com");
        await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "example.com");
        await AddRuleAsync(host, org.Owner.Access, domainId, "Exclude", "admin.example.com");

        var list = await Check.JsonAsync(await ListAsync(host, org.Owner.Access, domainId));

        Assert.Equal(new[] { "*.example.com", "example.com", "admin.example.com" }, Patterns(list));
        Assert.Equal(
            new[] { "Include", "Include", "Exclude" },
            list.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("ruleType").GetString()!).ToArray());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("*.*.example.com")]
    [InlineData("https://shop.example.com")]
    [InlineData("sho p.example.com")]
    [InlineData("192.0.2.10")]
    [InlineData("shop..example.com")]
    public async Task AnInvalidPatternIsRefused(string? pattern)
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        await Check.ProblemAsync(await CreateAsync(host, org.Owner.Access, domainId, "Include", pattern), HttpStatusCode.BadRequest, "PatternInvalid");

        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.ScopeRules);
    }

    [Theory]
    [InlineData("other.com")]
    [InlineData("evilexample.com")]
    [InlineData("example.com.evil.com")]
    public async Task APatternOutsideTheDomainIsRefused(string pattern)
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        await Check.ProblemAsync(await CreateAsync(host, org.Owner.Access, domainId, "Include", pattern), HttpStatusCode.BadRequest, "PatternOutsideDomain");

        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.ScopeRules);
    }

    [Theory]
    [InlineData("Allow")]
    [InlineData("1")]
    [InlineData("0")]
    [InlineData("Include,Exclude")]
    [InlineData("")]
    [InlineData(null)]
    public async Task OnlyIncludeAndExcludeAreRuleTypes(string? ruleType)
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        await Check.ProblemAsync(await CreateAsync(host, org.Owner.Access, domainId, ruleType, "www.example.com"), HttpStatusCode.BadRequest, "InvalidRuleType");

        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.ScopeRules);
    }

    [Fact]
    public async Task ADuplicateConflicts_ButTheSamePatternMayBeIncludedAndExcluded()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "www.example.com");

        await Check.ProblemAsync(await CreateAsync(host, org.Owner.Access, domainId, "Include", "WWW.example.com"), HttpStatusCode.Conflict, "RuleExists");

        // The policy engine decides what a conflict means (an exclusion always wins); the API does not forbid it.
        Assert.Equal(HttpStatusCode.Created, (await CreateAsync(host, org.Owner.Access, domainId, "Exclude", "www.example.com")).StatusCode);
    }

    [Fact]
    public async Task ADomainHoldsAtMostOneHundredLiveRules_AndRemovingOneMakesRoom()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        Guid first = default;
        for (var i = 1; i <= 100; i++)
        {
            var id = await AddRuleAsync(host, org.Owner.Access, domainId, "Include", $"h{i}.example.com");
            if (i == 1) first = id;
        }

        await Check.ProblemAsync(await CreateAsync(host, org.Owner.Access, domainId, "Include", "h101.example.com"), HttpStatusCode.Conflict, "TooManyRules");

        Assert.Equal(HttpStatusCode.NoContent, (await DeleteAsync(host, org.Owner.Access, first)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await CreateAsync(host, org.Owner.Access, domainId, "Include", "h101.example.com")).StatusCode);
    }

    // ------------------------------------------------------------------ update

    [Fact]
    public async Task UpdatingARuleChangesItInPlace_AndAnUnchangedUpdateWritesNoAudit()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var id = await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "www.example.com");

        var changed = await Check.JsonAsync(await UpdateAsync(host, org.Owner.Access, id, "exclude", "*.Example.com"));

        Assert.Equal(id, changed.GetProperty("id").GetGuid());
        Assert.Equal("Exclude", changed.GetProperty("ruleType").GetString());
        Assert.Equal("*.example.com", changed.GetProperty("pattern").GetString());
        Assert.Single(await AuditAsync(host, "scope.rule.updated"));

        // The same values again: still 200, but nothing changed, so nothing is recorded.
        Assert.Equal(HttpStatusCode.OK, (await UpdateAsync(host, org.Owner.Access, id, "Exclude", "*.example.com")).StatusCode);
        Assert.Single(await AuditAsync(host, "scope.rule.updated"));

        var list = await Check.JsonAsync(await ListAsync(host, org.Owner.Access, domainId));
        Assert.Equal(new[] { "*.example.com" }, Patterns(list));
    }

    [Fact]
    public async Task AnUpdateCannotCreateADuplicate_OrBreakTheRules()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "a.example.com");
        var second = await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "b.example.com");

        await Check.ProblemAsync(await UpdateAsync(host, org.Owner.Access, second, "Include", "a.example.com"), HttpStatusCode.Conflict, "RuleExists");
        await Check.ProblemAsync(await UpdateAsync(host, org.Owner.Access, second, "Include", "other.com"), HttpStatusCode.BadRequest, "PatternOutsideDomain");
        await Check.ProblemAsync(await UpdateAsync(host, org.Owner.Access, second, "Include", "sho p.example.com"), HttpStatusCode.BadRequest, "PatternInvalid");
        await Check.ProblemAsync(await UpdateAsync(host, org.Owner.Access, second, "Allow", "b.example.com"), HttpStatusCode.BadRequest, "InvalidRuleType");

        var rule = await Check.JsonAsync(await GetAsync(host, org.Owner.Access, second));
        Assert.Equal("b.example.com", rule.GetProperty("pattern").GetString());
        Assert.Equal("Include", rule.GetProperty("ruleType").GetString());
    }

    // ------------------------------------------------------------------ remove

    [Fact]
    public async Task RemovingARuleIsASoftDelete_ShownOnlyInTheHistory_AndRemovingItAgainConflicts()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var keep = await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "keep.example.com");
        var gone = await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "gone.example.com");

        Assert.Equal(HttpStatusCode.NoContent, (await DeleteAsync(host, org.Owner.Access, gone)).StatusCode);

        var live = await Check.JsonAsync(await ListAsync(host, org.Owner.Access, domainId));
        Assert.Equal(new[] { "keep.example.com" }, Patterns(live));

        var history = await Check.JsonAsync(await ListAsync(host, org.Owner.Access, domainId, "?includeRemoved=true"));
        var items = history.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(2, items.Count);
        Assert.Equal("gone.example.com", items[0].GetProperty("pattern").GetString());   // newest first
        Assert.NotEqual(JsonValueKind.Null, items[0].GetProperty("removedAt").ValueKind);
        Assert.Equal(keep, items[1].GetProperty("id").GetGuid());
        Assert.Equal(JsonValueKind.Null, items[1].GetProperty("removedAt").ValueKind);

        // A removed rule can still be read, cannot be changed or removed again, and its pattern can be added afresh.
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(host, org.Owner.Access, gone)).StatusCode);
        await Check.ProblemAsync(await DeleteAsync(host, org.Owner.Access, gone), HttpStatusCode.Conflict, "RuleRemoved");
        await Check.ProblemAsync(await UpdateAsync(host, org.Owner.Access, gone, "Include", "gone.example.com"), HttpStatusCode.Conflict, "RuleRemoved");
        Assert.Equal(HttpStatusCode.Created, (await CreateAsync(host, org.Owner.Access, domainId, "Include", "gone.example.com")).StatusCode);

        Assert.Single(await AuditAsync(host, "scope.rule.removed"));
    }

    [Fact]
    public async Task AnUnknownFlagOnTheListIsRefused()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        await Check.ProblemAsync(await ListAsync(host, org.Owner.Access, domainId, "?includeRemoved=maybe"), HttpStatusCode.BadRequest, "InvalidRequest");
    }

    // ------------------------------------------------------------------ who may do what

    [Fact]
    public async Task OnlyOwnersAndAdminsWrite_AndAuthorizationComesBeforeTheContent()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var ruleId = await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "www.example.com");
        var admin = await MemberAsync(host, org.OrganizationId, "admin@acme.example", MembershipRole.Admin);
        var analyst = await MemberAsync(host, org.OrganizationId, "analyst@acme.example", MembershipRole.Analyst);
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);

        Assert.Equal(HttpStatusCode.Created, (await CreateAsync(host, admin.Access, domainId, "Include", "admin-added.example.com", org.OrganizationId)).StatusCode);

        foreach (var person in new[] { analyst, viewer })
        {
            // The type and the pattern are invalid too, yet the answer is "not allowed": the role is checked first.
            await Check.ProblemAsync(await CreateAsync(host, person.Access, domainId, "Allow", "other.com", org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
            await Check.ProblemAsync(await UpdateAsync(host, person.Access, ruleId, "Allow", "other.com", org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
            await Check.ProblemAsync(await DeleteAsync(host, person.Access, ruleId, org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");

            // Reading is open to every member.
            Assert.Equal(HttpStatusCode.OK, (await ListAsync(host, person.Access, domainId, "", org.OrganizationId)).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await GetAsync(host, person.Access, ruleId, org.OrganizationId)).StatusCode);
        }

        var list = await Check.JsonAsync(await ListAsync(host, org.Owner.Access, domainId));
        Assert.Equal(new[] { "www.example.com", "admin-added.example.com" }, Patterns(list));
    }

    [Fact]
    public async Task EveryScopeRuleEndpointRequiresALogin()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var id = Guid.NewGuid();

        var calls = new (HttpMethod Method, string Path)[]
        {
            (HttpMethod.Get, $"{V1}/domains/{id}/scope-rules"),
            (HttpMethod.Post, $"{V1}/domains/{id}/scope-rules"),
            (HttpMethod.Get, $"{V1}/scope-rules/{id}"),
            (HttpMethod.Put, $"{V1}/scope-rules/{id}"),
            (HttpMethod.Delete, $"{V1}/scope-rules/{id}")
        };
        foreach (var (method, path) in calls)
            await Check.ProblemAsync(await host.SendAsync(method, path), HttpStatusCode.Unauthorized, "Unauthorized");
    }

    // ------------------------------------------------------------------ tenant isolation

    [Fact]
    public async Task AnotherOrganizationCannotReadOrChangeTheRules_AndGetsTheSameAnswerAsForAMissingId()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var ruleId = await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "www.example.com");
        var other = await OtherOrgAsync(host);
        var otherDomain = await AddDomainAsync(host, other.Owner.Access, "other-corp.example.com");   // so they hold a domain and a role of their own

        var crossList = await Check.ProblemAsync(await ListAsync(host, other.Owner.Access, domainId), HttpStatusCode.NotFound, "NotFound");
        var missingList = await Check.ProblemAsync(await ListAsync(host, other.Owner.Access, Guid.NewGuid()), HttpStatusCode.NotFound, "NotFound");
        Assert.Equal(missingList.GetProperty("detail").GetString(), crossList.GetProperty("detail").GetString());

        var crossGet = await Check.ProblemAsync(await GetAsync(host, other.Owner.Access, ruleId), HttpStatusCode.NotFound, "NotFound");
        var missingGet = await Check.ProblemAsync(await GetAsync(host, other.Owner.Access, Guid.NewGuid()), HttpStatusCode.NotFound, "NotFound");
        Assert.Equal(missingGet.GetProperty("detail").GetString(), crossGet.GetProperty("detail").GetString());

        await Check.ProblemAsync(await CreateAsync(host, other.Owner.Access, domainId, "Include", "evil.example.com"), HttpStatusCode.NotFound, "NotFound");
        await Check.ProblemAsync(await UpdateAsync(host, other.Owner.Access, ruleId, "Exclude", "www.example.com"), HttpStatusCode.NotFound, "NotFound");
        await Check.ProblemAsync(await DeleteAsync(host, other.Owner.Access, ruleId), HttpStatusCode.NotFound, "NotFound");

        // Nothing changed, and their own domain is unaffected.
        var rule = await Check.JsonAsync(await GetAsync(host, org.Owner.Access, ruleId));
        Assert.Equal("Include", rule.GetProperty("ruleType").GetString());
        Assert.Equal(JsonValueKind.Null, rule.GetProperty("removedAt").ValueKind);
        Assert.Empty((await Check.JsonAsync(await ListAsync(host, other.Owner.Access, otherDomain))).GetProperty("items").EnumerateArray().ToList());
        Assert.Empty(await AuditAsync(host, "scope.rule.updated"));
        Assert.Empty(await AuditAsync(host, "scope.rule.removed"));
    }

    // ------------------------------------------------------------------ suspension

    [Fact]
    public async Task ASuspendedOrganizationCanReadItsRules_ButNotChangeThem()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var ruleId = await AddRuleAsync(host, org.Owner.Access, domainId, "Include", "www.example.com");

        await SuspendAsync(host, org.OrganizationId);

        Assert.Equal(HttpStatusCode.OK, (await ListAsync(host, org.Owner.Access, domainId)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(host, org.Owner.Access, ruleId)).StatusCode);
        await Check.ProblemAsync(await CreateAsync(host, org.Owner.Access, domainId, "Include", "new.example.com"), HttpStatusCode.Forbidden, "OrganizationSuspended");
        await Check.ProblemAsync(await UpdateAsync(host, org.Owner.Access, ruleId, "Exclude", "www.example.com"), HttpStatusCode.Forbidden, "OrganizationSuspended");
        await Check.ProblemAsync(await DeleteAsync(host, org.Owner.Access, ruleId), HttpStatusCode.Forbidden, "OrganizationSuspended");

        var list = await Check.JsonAsync(await ListAsync(host, org.Owner.Access, domainId));
        Assert.Equal(new[] { "www.example.com" }, Patterns(list));
    }
}
