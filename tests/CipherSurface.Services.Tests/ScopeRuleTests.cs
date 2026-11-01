using System.Text.Json;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class ScopeRuleTests
{
    private readonly PostgresFixture _postgres;
    public ScopeRuleTests(PostgresFixture postgres) => _postgres = postgres;

    private static readonly CancellationToken Ct = CancellationToken.None;

    // ------------------------------------------------------------------ helpers

    private async Task<(TestWorld World, Actor Owner, Guid DomainId)> SetupAsync(string domain = "example.com")
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, domain);
        return (world, owner, domainId);
    }

    private static async Task<List<ScopeRule>> RulesAsync(TestWorld world, Guid domainId)
    {
        await using var db = world.Db.CreateDbContext();
        return await db.ScopeRules.AsNoTracking().Where(r => r.DomainId == domainId).OrderBy(r => r.CreatedAt).ThenBy(r => r.Pattern).ToListAsync();
    }

    private static async Task<List<ScopeRule>> LiveRulesAsync(TestWorld world, Guid domainId) =>
        (await RulesAsync(world, domainId)).Where(r => r.RemovedAt is null).ToList();

    private static async Task<List<AuditLog>> ScopeAuditsAsync(TestWorld world, Guid organizationId)
    {
        await using var db = world.Db.CreateDbContext();
        return await db.AuditLogs.AsNoTracking()
            .Where(a => a.OrganizationId == organizationId && a.Action.StartsWith("scope.rule."))
            .OrderBy(a => a.Sequence)
            .ToListAsync();
    }

    private static string Field(AuditLog entry, string name) =>
        JsonDocument.Parse(entry.Data).RootElement.GetProperty(name).GetString()!;

    private static async Task<string?> CodeOfAsync(Func<Task> action)
    {
        try
        {
            await action();
            return null;
        }
        catch (ServiceException ex)
        {
            return ex.Code;
        }
    }

    private static async Task AssertFailsAsync(string code, Func<Task> action)
    {
        var ex = await Assert.ThrowsAsync<ServiceException>(action);
        Assert.Equal(code, ex.Code);
    }

    /// <summary>The effective scope as the gate would calculate it right now: DNS proof ceiling, live rules from the database.</summary>
    private static async Task<EffectiveScope> ScopeOfAsync(TestWorld world, Guid domainId, Guid evidenceId, string domainName = "example.com")
    {
        await using var db = world.Db.CreateDbContext();
        var evidence = await db.VerificationEvidence.AsNoTracking().SingleAsync(e => e.Id == evidenceId);
        var rules = await db.ScopeRules.AsNoTracking().Where(r => r.DomainId == domainId).ToListAsync();
        var result = new ScopeCalculator().Calculate(
            domainId, domainName,
            [new UsableEvidence(evidence.Id, evidence.DomainId, evidence.Method, evidence.ScopeCeilingType, evidence.Host)],
            rules);
        Assert.True(result.Succeeded, result.ErrorCode);
        return result.Scope!;
    }

    // ------------------------------------------------------------------ create

    [Fact]
    public async Task Create_StoresTheNormalizedRule()
    {
        var (world, owner, domainId) = await SetupAsync();

        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "  WWW.Example.COM. ", Ct);

        var rule = Assert.Single(await RulesAsync(world, domainId));
        Assert.Equal(id, rule.Id);
        Assert.Equal(domainId, rule.DomainId);
        Assert.Equal(ScopeRuleType.Include, rule.RuleType);
        Assert.Equal("www.example.com", rule.Pattern);
        Assert.Equal(owner.UserId, rule.CreatedByUserId);
        Assert.Equal(TestWorld.Start, rule.CreatedAt);
        Assert.Null(rule.RemovedAt);
    }

    [Fact]
    public async Task Create_ConvertsInternationalizedNamesToAscii()
    {
        var (world, owner, domainId) = await SetupAsync();

        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "b\u00fccher.example.com", Ct);

        Assert.Equal("xn--bcher-kva.example.com", Assert.Single(await RulesAsync(world, domainId)).Pattern);
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("*.example.com", "*.example.com")]
    [InlineData("*.EXAMPLE.com", "*.example.com")]
    [InlineData("a.b.example.com", "a.b.example.com")]
    [InlineData("*.dev.example.com", "*.dev.example.com")]
    public async Task Create_AcceptsTheDomainItself_AWildcard_AndHostsBelowIt(string input, string expected)
    {
        var (world, owner, domainId) = await SetupAsync();

        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, input, Ct);

        Assert.Equal(expected, Assert.Single(await RulesAsync(world, domainId)).Pattern);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("*")]
    [InlineData("*.")]
    [InlineData("*.*.example.com")]
    [InlineData("shop*.example.com")]
    [InlineData("*shop.example.com")]
    [InlineData("https://shop.example.com")]
    [InlineData("shop.example.com/admin")]
    [InlineData("shop.example.com:8443")]
    [InlineData("user@example.com")]
    [InlineData("192.0.2.10")]
    [InlineData("shop..example.com")]
    [InlineData("-shop.example.com")]
    [InlineData("shop-.example.com")]
    [InlineData("sho p.example.com")]
    [InlineData("example")]
    [InlineData("*.com")]
    public async Task Create_RejectsMalformedPatterns(string? pattern)
    {
        var (world, owner, domainId) = await SetupAsync();

        await AssertFailsAsync("PatternInvalid", () => world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, pattern, Ct));

        Assert.Empty(await RulesAsync(world, domainId));
        Assert.Empty(await ScopeAuditsAsync(world, owner.OrganizationId));
    }

    [Fact]
    public async Task Create_RejectsALabelLongerThan63Characters()
    {
        var (world, owner, domainId) = await SetupAsync();

        await AssertFailsAsync("PatternInvalid", () => world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, new string('a', 64) + ".example.com", Ct));
    }

    [Theory]
    [InlineData("other.com")]
    [InlineData("example.org")]
    [InlineData("evilexample.com")]
    [InlineData("*.evilexample.com")]
    [InlineData("notexample.com")]
    [InlineData("example.com.evil.com")]
    [InlineData("*.example.org")]
    public async Task Create_RejectsPatternsOutsideTheDomain(string pattern)
    {
        var (world, owner, domainId) = await SetupAsync();

        await AssertFailsAsync("PatternOutsideDomain", () => world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, pattern, Ct));

        Assert.Empty(await RulesAsync(world, domainId));
        Assert.Empty(await ScopeAuditsAsync(world, owner.OrganizationId));
    }

    [Fact]
    public async Task Create_RejectsAnUnknownRuleType()
    {
        var (world, owner, domainId) = await SetupAsync();

        await AssertFailsAsync("InvalidRuleType", () => world.Scope.CreateAsync(owner, domainId, (ScopeRuleType)99, "www.example.com", Ct));

        Assert.Empty(await RulesAsync(world, domainId));
    }

    [Fact]
    public async Task Create_RejectsAnIdenticalLiveRule_EvenWhenWrittenDifferently()
    {
        var (world, owner, domainId) = await SetupAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);

        await AssertFailsAsync("RuleExists", () => world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct));
        await AssertFailsAsync("RuleExists", () => world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, " WWW.EXAMPLE.COM. ", Ct));

        Assert.Single(await RulesAsync(world, domainId));
        Assert.Single(await ScopeAuditsAsync(world, owner.OrganizationId));
    }

    [Fact]
    public async Task Create_AllowsTheSamePatternAsInclude_AndAsExclude()
    {
        var (world, owner, domainId) = await SetupAsync();

        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "www.example.com", Ct);

        Assert.Equal(2, (await LiveRulesAsync(world, domainId)).Count);
    }

    [Fact]
    public async Task Create_AllowsARuleAgain_AfterItWasRemoved()
    {
        var (world, owner, domainId) = await SetupAsync();
        var first = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        await world.Scope.RemoveAsync(owner, first, Ct);

        var second = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);

        Assert.NotEqual(first, second);
        var rules = await RulesAsync(world, domainId);
        Assert.Equal(2, rules.Count);
        Assert.Single(rules, r => r.RemovedAt is null);
    }

    [Fact]
    public async Task Create_EnforcesTheLimitOfLiveRules_AndRemovedRulesDoNotCount()
    {
        var (world, owner, domainId) = await SetupAsync();
        var small = new ScopeRuleService(world.Db, world.Time, world.Audit, maxLiveRulesPerDomain: 2);
        var first = await small.CreateAsync(owner, domainId, ScopeRuleType.Include, "a.example.com", Ct);
        await small.CreateAsync(owner, domainId, ScopeRuleType.Include, "b.example.com", Ct);

        await AssertFailsAsync("TooManyRules", () => small.CreateAsync(owner, domainId, ScopeRuleType.Include, "c.example.com", Ct));

        await small.RemoveAsync(owner, first, Ct);
        await small.CreateAsync(owner, domainId, ScopeRuleType.Include, "c.example.com", Ct);
        Assert.Equal(2, (await LiveRulesAsync(world, domainId)).Count);
    }

    [Fact]
    public void Constructor_RejectsALimitBelowOne()
    {
        var time = new FakeTime(TestWorld.Start);
        Assert.Throws<ArgumentOutOfRangeException>(() => new ScopeRuleService(null!, time, new AuditLogWriter(time), maxLiveRulesPerDomain: 0));
    }

    // ------------------------------------------------------------------ update

    [Fact]
    public async Task Update_ChangesTypeAndPattern_AndKeepsTheSameRow()
    {
        var (world, owner, domainId) = await SetupAsync();
        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);

        await world.Scope.UpdateAsync(owner, id, ScopeRuleType.Exclude, "API.example.com", Ct);

        var rule = Assert.Single(await RulesAsync(world, domainId));
        Assert.Equal(id, rule.Id);
        Assert.Equal(ScopeRuleType.Exclude, rule.RuleType);
        Assert.Equal("api.example.com", rule.Pattern);
        Assert.Null(rule.RemovedAt);
    }

    [Fact]
    public async Task Update_ToAPatternOutsideTheDomain_IsRejected_AndNothingChanges()
    {
        var (world, owner, domainId) = await SetupAsync();
        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);

        await AssertFailsAsync("PatternOutsideDomain", () => world.Scope.UpdateAsync(owner, id, ScopeRuleType.Include, "www.evil.com", Ct));
        await AssertFailsAsync("PatternInvalid", () => world.Scope.UpdateAsync(owner, id, ScopeRuleType.Include, "*.*.example.com", Ct));
        await AssertFailsAsync("InvalidRuleType", () => world.Scope.UpdateAsync(owner, id, (ScopeRuleType)7, "www.example.com", Ct));

        Assert.Equal("www.example.com", Assert.Single(await RulesAsync(world, domainId)).Pattern);
        Assert.Single(await ScopeAuditsAsync(world, owner.OrganizationId));   // only the creation
    }

    [Fact]
    public async Task Update_ToAnotherLiveRulesValues_IsRejected()
    {
        var (world, owner, domainId) = await SetupAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        var second = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "api.example.com", Ct);

        await AssertFailsAsync("RuleExists", () => world.Scope.UpdateAsync(owner, second, ScopeRuleType.Include, "www.example.com", Ct));

        Assert.Equal("api.example.com", (await RulesAsync(world, domainId)).Single(r => r.Id == second).Pattern);
    }

    [Fact]
    public async Task Update_WithTheSameValues_ChangesNothingAndWritesNoAuditEntry()
    {
        var (world, owner, domainId) = await SetupAsync();
        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);

        await world.Scope.UpdateAsync(owner, id, ScopeRuleType.Include, " WWW.example.com ", Ct);

        Assert.Single(await ScopeAuditsAsync(world, owner.OrganizationId));
    }

    [Fact]
    public async Task Update_OfARemovedRule_IsRejected()
    {
        var (world, owner, domainId) = await SetupAsync();
        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        await world.Scope.RemoveAsync(owner, id, Ct);

        await AssertFailsAsync("RuleRemoved", () => world.Scope.UpdateAsync(owner, id, ScopeRuleType.Exclude, "api.example.com", Ct));

        var rule = Assert.Single(await RulesAsync(world, domainId));
        Assert.Equal("www.example.com", rule.Pattern);
        Assert.NotNull(rule.RemovedAt);
    }

    [Fact]
    public async Task Update_OfAnUnknownRule_IsNotFound()
    {
        var (world, owner, _) = await SetupAsync();

        await AssertFailsAsync("NotFound", () => world.Scope.UpdateAsync(owner, Guid.NewGuid(), ScopeRuleType.Include, "www.example.com", Ct));
    }

    // ------------------------------------------------------------------ remove

    [Fact]
    public async Task Remove_IsASoftDelete_TheRowAndItsHistoryStay()
    {
        var (world, owner, domainId) = await SetupAsync();
        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "admin.example.com", Ct);
        world.Time.Advance(TimeSpan.FromHours(2));

        await world.Scope.RemoveAsync(owner, id, Ct);

        var rule = Assert.Single(await RulesAsync(world, domainId));
        Assert.Equal(id, rule.Id);
        Assert.Equal(TestWorld.Start.AddHours(2), rule.RemovedAt);
        Assert.Equal("admin.example.com", rule.Pattern);
        Assert.Equal(ScopeRuleType.Exclude, rule.RuleType);
    }

    [Fact]
    public async Task Remove_Twice_IsRejected_AndAuditedOnce()
    {
        var (world, owner, domainId) = await SetupAsync();
        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        await world.Scope.RemoveAsync(owner, id, Ct);

        await AssertFailsAsync("RuleRemoved", () => world.Scope.RemoveAsync(owner, id, Ct));

        Assert.Single(await ScopeAuditsAsync(world, owner.OrganizationId), a => a.Action == "scope.rule.removed");
    }

    [Fact]
    public async Task Remove_OfAnUnknownRule_IsNotFound()
    {
        var (world, owner, _) = await SetupAsync();

        await AssertFailsAsync("NotFound", () => world.Scope.RemoveAsync(owner, Guid.NewGuid(), Ct));
    }

    // ------------------------------------------------------------------ roles and tenant isolation

    [Theory]
    [InlineData(MembershipRole.Owner)]
    [InlineData(MembershipRole.Admin)]
    public async Task OwnersAndAdmins_CanManageScope(MembershipRole role)
    {
        var (world, owner, domainId) = await SetupAsync();
        var member = role == MembershipRole.Owner ? owner : await world.AddMemberAsync(owner.OrganizationId, role);

        var id = await world.Scope.CreateAsync(member, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        await world.Scope.UpdateAsync(member, id, ScopeRuleType.Include, "api.example.com", Ct);
        await world.Scope.RemoveAsync(member, id, Ct);

        Assert.Equal(3, (await ScopeAuditsAsync(world, owner.OrganizationId)).Count);
    }

    [Theory]
    [InlineData(MembershipRole.Analyst)]
    [InlineData(MembershipRole.Viewer)]
    public async Task AnalystsAndViewers_CannotManageScope(MembershipRole role)
    {
        var (world, owner, domainId) = await SetupAsync();
        var existing = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        var member = await world.AddMemberAsync(owner.OrganizationId, role);

        await AssertFailsAsync("NotAllowed", () => world.Scope.CreateAsync(member, domainId, ScopeRuleType.Include, "api.example.com", Ct));
        await AssertFailsAsync("NotAllowed", () => world.Scope.UpdateAsync(member, existing, ScopeRuleType.Include, "api.example.com", Ct));
        await AssertFailsAsync("NotAllowed", () => world.Scope.RemoveAsync(member, existing, Ct));

        var rule = Assert.Single(await RulesAsync(world, domainId));
        Assert.Equal("www.example.com", rule.Pattern);
        Assert.Null(rule.RemovedAt);
        Assert.Single(await ScopeAuditsAsync(world, owner.OrganizationId));
    }

    [Fact]
    public async Task ASuspendedOrganization_CannotChangeScope()
    {
        var (world, owner, domainId) = await SetupAsync();
        var existing = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        await world.SuspendAsync(owner.OrganizationId);

        await AssertFailsAsync("OrganizationSuspended", () => world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "api.example.com", Ct));
        await AssertFailsAsync("OrganizationSuspended", () => world.Scope.UpdateAsync(owner, existing, ScopeRuleType.Include, "api.example.com", Ct));
        await AssertFailsAsync("OrganizationSuspended", () => world.Scope.RemoveAsync(owner, existing, Ct));

        Assert.Single(await ScopeAuditsAsync(world, owner.OrganizationId));
    }

    [Fact]
    public async Task AnotherOrganization_CannotSeeOrChangeTheRulesOfADomain()
    {
        var (world, ownerA, domainA) = await SetupAsync();
        var ownerB = await world.NewOrgAsync("Other org");
        var ruleA = await world.Scope.CreateAsync(ownerA, domainA, ScopeRuleType.Include, "www.example.com", Ct);

        await AssertFailsAsync("NotFound", () => world.Scope.CreateAsync(ownerB, domainA, ScopeRuleType.Include, "api.example.com", Ct));
        await AssertFailsAsync("NotFound", () => world.Scope.UpdateAsync(ownerB, ruleA, ScopeRuleType.Exclude, "api.example.com", Ct));
        await AssertFailsAsync("NotFound", () => world.Scope.RemoveAsync(ownerB, ruleA, Ct));

        var rule = Assert.Single(await RulesAsync(world, domainA));
        Assert.Equal(ScopeRuleType.Include, rule.RuleType);
        Assert.Equal("www.example.com", rule.Pattern);
        Assert.Null(rule.RemovedAt);
        Assert.Single(await ScopeAuditsAsync(world, ownerA.OrganizationId));
        Assert.Empty(await ScopeAuditsAsync(world, ownerB.OrganizationId));
    }

    [Fact]
    public async Task AUserCannotActInAnOrganizationTheyDoNotBelongTo_EvenWithAForgedActor()
    {
        var (world, ownerA, domainA) = await SetupAsync();
        var ownerB = await world.NewOrgAsync("Other org");
        var ruleA = await world.Scope.CreateAsync(ownerA, domainA, ScopeRuleType.Include, "www.example.com", Ct);
        var forged = new Actor(ownerB.UserId, ownerA.OrganizationId, ownerB.Ip);

        await AssertFailsAsync("NotAllowed", () => world.Scope.CreateAsync(forged, domainA, ScopeRuleType.Include, "api.example.com", Ct));
        await AssertFailsAsync("NotAllowed", () => world.Scope.UpdateAsync(forged, ruleA, ScopeRuleType.Exclude, "api.example.com", Ct));
        await AssertFailsAsync("NotAllowed", () => world.Scope.RemoveAsync(forged, ruleA, Ct));

        Assert.Single(await RulesAsync(world, domainA));
        Assert.Single(await ScopeAuditsAsync(world, ownerA.OrganizationId));
    }

    [Fact]
    public async Task TheSameDomainNameInTwoOrganizations_KeepsSeparateRules()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var ownerA = await world.NewOrgAsync("A");
        var ownerB = await world.NewOrgAsync("B");
        var domainA = await world.AddDomainAsync(ownerA, "example.com");
        var domainB = await world.AddDomainAsync(ownerB, "example.com");

        await world.Scope.CreateAsync(ownerA, domainA, ScopeRuleType.Include, "www.example.com", Ct);
        await world.Scope.CreateAsync(ownerB, domainB, ScopeRuleType.Exclude, "www.example.com", Ct);

        Assert.Equal(ScopeRuleType.Include, Assert.Single(await RulesAsync(world, domainA)).RuleType);
        Assert.Equal(ScopeRuleType.Exclude, Assert.Single(await RulesAsync(world, domainB)).RuleType);
    }

    // ------------------------------------------------------------------ audit

    [Fact]
    public async Task EveryChange_WritesOneAuditEntry_WithActorIpAndTheRulesHash()
    {
        var (world, owner, domainId) = await SetupAsync();

        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
        await world.Scope.UpdateAsync(owner, id, ScopeRuleType.Exclude, "api.example.com", Ct);
        await world.Scope.RemoveAsync(owner, id, Ct);

        var entries = await ScopeAuditsAsync(world, owner.OrganizationId);
        Assert.Equal(new[] { "scope.rule.created", "scope.rule.updated", "scope.rule.removed" }, entries.Select(e => e.Action).ToArray());
        Assert.All(entries, e =>
        {
            Assert.Equal("ScopeRule", e.EntityType);
            Assert.Equal(id, e.EntityId);
            Assert.Equal("User", e.ActorType);
            Assert.Equal(owner.UserId, e.ActorId);
            Assert.Equal(owner.Ip, e.Ip);
            Assert.Equal(domainId.ToString("D"), Field(e, "domainId"));
        });

        var created = entries[0];
        Assert.Equal("Include", Field(created, "ruleType"));
        Assert.Equal("www.example.com", Field(created, "pattern"));

        var updated = entries[1];
        Assert.Equal("Include", Field(updated, "previousRuleType"));
        Assert.Equal("www.example.com", Field(updated, "previousPattern"));
        Assert.Equal("Exclude", Field(updated, "ruleType"));
        Assert.Equal("api.example.com", Field(updated, "pattern"));

        var removed = entries[2];
        Assert.Equal("Exclude", Field(removed, "ruleType"));
        Assert.Equal("api.example.com", Field(removed, "pattern"));

        // The hash after the last change is the hash of the rules that are live now (none), the same hash a decision would store.
        Assert.Equal(ScopeCalculator.ComputeScopeRulesHash([]), Field(removed, "scopeRulesHash"));

        await using var db = world.Db.CreateDbContext();
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, owner.OrganizationId, Ct)).Intact);
    }

    [Fact]
    public async Task TheAuditHash_MatchesTheRulesHashStoredInTheNextDecision()
    {
        var (world, owner, domainId) = await SetupAsync();
        var challenge = await world.Challenges.IssueAsync(owner, domainId, VerificationMethod.DnsTxt, null, Ct);
        await world.Verification.VerifyAsync(owner, challenge.ChallengeId, Ct);
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "admin.example.com", Ct);
        var lastChange = (await ScopeAuditsAsync(world, owner.OrganizationId)).Last();

        var started = await world.StartScanAsync(owner, domainId, "www.example.com");

        Assert.True(started.Allowed, started.FailedCheckCode);
        await using var db = world.Db.CreateDbContext();
        var decision = await db.PolicyDecisions.SingleAsync(d => d.Id == started.DecisionId);
        Assert.Equal(Field(lastChange, "scopeRulesHash"), decision.ScopeRulesHash);
    }

    // ------------------------------------------------------------------ effective scope is recalculated from live rules

    [Fact]
    public async Task AWildcardInclude_CoversSubdomainsAtAnyDepth_ButNotTheApex()
    {
        var (world, owner, domainId, evidenceId) = await SetupVerifiedAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);

        var scope = await ScopeOfAsync(world, domainId, evidenceId);

        Assert.True(scope.ContainsHost("a.example.com"));
        Assert.True(scope.ContainsHost("a.b.example.com"));
        Assert.False(scope.ContainsHost("example.com"));
        Assert.False(scope.ContainsHost("notexample.com"));
    }

    [Fact]
    public async Task AnApexInclude_CoversOnlyTheApex()
    {
        var (world, owner, domainId, evidenceId) = await SetupVerifiedAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "example.com", Ct);

        var scope = await ScopeOfAsync(world, domainId, evidenceId);

        Assert.True(scope.ContainsHost("example.com"));
        Assert.False(scope.ContainsHost("www.example.com"));
    }

    [Fact]
    public async Task AnExactExclusion_CoversTheHostAndEverythingBeneathIt()
    {
        var (world, owner, domainId, evidenceId) = await SetupVerifiedAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "admin.example.com", Ct);

        var scope = await ScopeOfAsync(world, domainId, evidenceId);

        Assert.False(scope.ContainsHost("admin.example.com"));
        Assert.False(scope.ContainsHost("deep.admin.example.com"));
        Assert.False(scope.ContainsHost("a.b.admin.example.com"));
        Assert.True(scope.ContainsHost("adminx.example.com"));
        Assert.True(scope.ContainsHost("www.example.com"));
    }

    [Fact]
    public async Task AWildcardExclusion_CoversSubdomainsButNotItsOwnApex()
    {
        var (world, owner, domainId, evidenceId) = await SetupVerifiedAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "*.internal.example.com", Ct);

        var scope = await ScopeOfAsync(world, domainId, evidenceId);

        Assert.False(scope.ContainsHost("a.internal.example.com"));
        Assert.False(scope.ContainsHost("a.b.internal.example.com"));
        Assert.True(scope.ContainsHost("internal.example.com"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Exclusions_AlwaysWin_WhateverTheCreationOrder(bool excludeFirst)
    {
        var (world, owner, domainId, evidenceId) = await SetupVerifiedAsync();
        if (excludeFirst)
        {
            await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "www.example.com", Ct);
            await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
            await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
        }
        else
        {
            await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
            await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);
            await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "www.example.com", Ct);
        }

        var scope = await ScopeOfAsync(world, domainId, evidenceId);

        Assert.False(scope.ContainsHost("www.example.com"));
        Assert.True(scope.ContainsHost("api.example.com"));
    }

    [Fact]
    public async Task RemovingAnExclusion_BringsTheHostBack_AndRemovingAnIncludeTakesItAway()
    {
        var (world, owner, domainId, evidenceId) = await SetupVerifiedAsync();
        var include = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
        var exclude = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "www.example.com", Ct);
        Assert.False((await ScopeOfAsync(world, domainId, evidenceId)).ContainsHost("www.example.com"));

        await world.Scope.RemoveAsync(owner, exclude, Ct);
        Assert.True((await ScopeOfAsync(world, domainId, evidenceId)).ContainsHost("www.example.com"));

        await world.Scope.RemoveAsync(owner, include, Ct);
        var scope = await ScopeOfAsync(world, domainId, evidenceId);
        Assert.True(scope.IsEmpty);
        Assert.False(scope.ContainsHost("www.example.com"));
    }

    [Fact]
    public async Task UpdatingARule_ChangesTheScopeAtOnce()
    {
        var (world, owner, domainId, evidenceId) = await SetupVerifiedAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
        var exclude = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "a.example.com", Ct);

        await world.Scope.UpdateAsync(owner, exclude, ScopeRuleType.Exclude, "b.example.com", Ct);

        var scope = await ScopeOfAsync(world, domainId, evidenceId);
        Assert.True(scope.ContainsHost("a.example.com"));
        Assert.False(scope.ContainsHost("b.example.com"));
    }

    [Fact]
    public async Task TheScanGate_UsesTheRulesThatAreLiveAtDecisionTime()
    {
        var (world, owner, domainId, _) = await SetupVerifiedAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
        Assert.True((await world.StartScanAsync(owner, domainId, "www.example.com")).Allowed);

        var exclude = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "www.example.com", Ct);
        var denied = await world.StartScanAsync(owner, domainId, "www.example.com");
        Assert.False(denied.Allowed);
        Assert.Equal("TargetOutsideEffectiveScope", denied.FailedCheckCode);

        await world.Scope.RemoveAsync(owner, exclude, Ct);
        Assert.True((await world.StartScanAsync(owner, domainId, "www.example.com")).Allowed);
    }

    [Fact]
    public async Task ARunningScan_IsRestrictedAtItsNextCheck_WhenATargetIsExcluded()
    {
        var (world, owner, domainId, _) = await SetupVerifiedAsync();
        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "*.example.com", Ct);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "a.example.com", "b.example.com");

        await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Exclude, "b.example.com", Ct);
        var check = await world.Runs.ContinueAsync(runId, new[] { "a.example.com", "b.example.com" }, Ct);

        Assert.Equal(ContinuationOutcome.Restrict, check.Outcome);
        Assert.Equal(new[] { "a.example.com" }, check.AllowedTargets);
        Assert.Equal(new[] { "b.example.com" }, check.BlockedTargets);
    }

    private async Task<(TestWorld World, Actor Owner, Guid DomainId, Guid EvidenceId)> SetupVerifiedAsync()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        return (world, owner, domainId, evidenceId);
    }

    // ------------------------------------------------------------------ concurrency

    [Fact]
    public async Task RuleRow_HasAConcurrencyToken()
    {
        var (world, owner, domainId) = await SetupAsync();
        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);

        await using var first = world.Db.CreateDbContext();
        await using var second = world.Db.CreateDbContext();
        var a = await first.ScopeRules.SingleAsync(r => r.Id == id);
        var b = await second.ScopeRules.SingleAsync(r => r.Id == id);
        a.RemovedAt = TestWorld.Start;
        await first.SaveChangesAsync();
        b.Pattern = "api.example.com";

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
    }

    [Fact]
    public async Task ParallelIdenticalCreates_ProduceExactlyOneRule()
    {
        var (world, owner, domainId) = await SetupAsync();

        for (var round = 0; round < 5; round++)
        {
            var pattern = $"round{round}.example.com";
            var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
                CodeOfAsync(() => world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, pattern, Ct))));

            Assert.Single(results, r => r is null);
            Assert.Equal(7, results.Count(r => r == "RuleExists"));
        }

        Assert.Equal(5, (await LiveRulesAsync(world, domainId)).Count);
        Assert.Equal(5, (await ScopeAuditsAsync(world, owner.OrganizationId)).Count);
    }

    [Fact]
    public async Task ParallelCreates_CannotExceedTheRuleLimit()
    {
        var (world, owner, domainId) = await SetupAsync();
        var small = new ScopeRuleService(world.Db, world.Time, world.Audit, maxLiveRulesPerDomain: 3);

        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(i =>
            CodeOfAsync(() => small.CreateAsync(owner, domainId, ScopeRuleType.Include, $"host{i}.example.com", Ct))));

        Assert.Equal(3, results.Count(r => r is null));
        Assert.Equal(7, results.Count(r => r == "TooManyRules"));
        Assert.Equal(3, (await LiveRulesAsync(world, domainId)).Count);
    }

    [Fact]
    public async Task ParallelRemovesOfOneRule_SucceedOnce()
    {
        var (world, owner, domainId) = await SetupAsync();
        var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, "www.example.com", Ct);

        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => CodeOfAsync(() => world.Scope.RemoveAsync(owner, id, Ct))));

        Assert.Single(results, r => r is null);
        Assert.Equal(5, results.Count(r => r == "RuleRemoved"));
        Assert.Single(await ScopeAuditsAsync(world, owner.OrganizationId), a => a.Action == "scope.rule.removed");
    }

    [Fact]
    public async Task AnUpdateRacingARemoval_NeverLeavesAnInconsistentRule_OrABrokenAuditChain()
    {
        var (world, owner, domainId) = await SetupAsync();

        for (var i = 0; i < 5; i++)
        {
            var id = await world.Scope.CreateAsync(owner, domainId, ScopeRuleType.Include, $"old{i}.example.com", Ct);

            var results = await Task.WhenAll(
                CodeOfAsync(() => world.Scope.UpdateAsync(owner, id, ScopeRuleType.Exclude, $"new{i}.example.com", Ct)),
                CodeOfAsync(() => world.Scope.RemoveAsync(owner, id, Ct)));

            Assert.Null(results[1]);                                   // the removal always wins or follows the update
            Assert.True(results[0] is null or "RuleRemoved");          // the update either ran first or found the rule removed
        }

        Assert.Empty(await LiveRulesAsync(world, domainId));
        var entries = await ScopeAuditsAsync(world, owner.OrganizationId);
        Assert.Equal(5, entries.Count(e => e.Action == "scope.rule.created"));
        Assert.Equal(5, entries.Count(e => e.Action == "scope.rule.removed"));
        await using var db = world.Db.CreateDbContext();
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, owner.OrganizationId, Ct)).Intact);
    }

    [Fact]
    public async Task ParallelCreatesOfDifferentRules_AllSucceed_AndKeepTheAuditChainIntact()
    {
        var (world, owner, domainId) = await SetupAsync();

        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(i =>
            CodeOfAsync(() => world.Scope.CreateAsync(owner, domainId, i % 2 == 0 ? ScopeRuleType.Include : ScopeRuleType.Exclude, $"host{i}.example.com", Ct))));

        Assert.All(results, Assert.Null);
        Assert.Equal(12, (await LiveRulesAsync(world, domainId)).Count);
        Assert.Equal(12, (await ScopeAuditsAsync(world, owner.OrganizationId)).Count);
        await using var db = world.Db.CreateDbContext();
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, owner.OrganizationId, Ct)).Intact);
    }
}
