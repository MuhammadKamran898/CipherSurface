using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class ScanStartTests
{
    private readonly PostgresFixture _postgres;
    public ScanStartTests(PostgresFixture postgres) => _postgres = postgres;

    private static VerificationObservation Absent => VerificationObservation.Absent(Reasons.TxtRecordMissing);

    // ------------------------------------------------------------------ the happy path

    [Fact]
    public async Task VerifiedDomainWithScope_IsAllowed_AndEverythingIsRecorded()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.ScannableByDnsAsync(world, owner);
        world.Time.Advance(TimeSpan.FromHours(1));

        var result = await world.StartScanAsync(owner, domainId, "www.example.com", "Example.com.");

        Assert.True(result.Allowed);
        Assert.Null(result.FailedCheckCode);
        Assert.NotNull(result.ScanRunId);
        Assert.False(result.AlreadyStarted);
        Assert.Equal(TestWorld.Start.AddHours(1).AddMinutes(15), result.DecisionExpiresAt);

        await using var db = world.Db.CreateDbContext();
        var decision = await db.PolicyDecisions.SingleAsync(d => d.Id == result.DecisionId);
        Assert.Equal(DecisionOutcome.Allow, decision.Outcome);
        Assert.Equal(owner.UserId, decision.UserId);
        Assert.Contains(evidenceId, decision.EvidenceIds);

        var run = await db.ScanRuns.SingleAsync(r => r.Id == result.ScanRunId);
        Assert.Equal(ScanRunStatus.Queued, run.Status);
        Assert.Equal(decision.Id, run.PolicyDecisionId);
        Assert.Equal(new[] { "example.com", "www.example.com" }, run.Targets);   // normalized, sorted

        // The live check was recorded and refreshed the proof.
        var evidence = await world.GetEvidenceAsync(evidenceId);
        Assert.Equal(TestWorld.Start.AddHours(1), evidence.LastValidAt);
        var check = await db.VerificationChecks.SingleAsync(c => c.EvidenceId == evidenceId);
        Assert.Equal(CheckTrigger.System, check.TriggeredBy);

        Assert.Contains("scan.allowed", await db.AuditLogs.Select(a => a.Action).ToListAsync());
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, owner.OrganizationId, CancellationToken.None)).Intact);
    }

    // ------------------------------------------------------------------ denials are decisions too

    [Fact]
    public async Task TargetOutsideTheScope_IsDenied_AndTheDenialIsStored()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        await world.AddRuleAsync(owner, domainId, ScopeRuleType.Exclude, "admin.example.com");

        var result = await world.StartScanAsync(owner, domainId, "www.example.com", "admin.example.com");

        Assert.False(result.Allowed);
        Assert.Equal("TargetOutsideEffectiveScope", result.FailedCheckCode);
        Assert.Null(result.ScanRunId);
        await using var db = world.Db.CreateDbContext();
        var decision = await db.PolicyDecisions.SingleAsync(d => d.Id == result.DecisionId);
        Assert.Equal(DecisionOutcome.Deny, decision.Outcome);
        Assert.Equal(0, await db.ScanRuns.CountAsync());
        Assert.Contains("scan.denied", await db.AuditLogs.Select(a => a.Action).ToListAsync());
    }

    [Fact]
    public async Task NoScopeRules_MeansNothingMayBeScanned()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.VerifiedByDnsAsync(world, owner);

        var result = await world.StartScanAsync(owner, domainId, "www.example.com");

        Assert.False(result.Allowed);
        Assert.Equal("NoEffectiveScope", result.FailedCheckCode);
    }

    [Fact]
    public async Task ViewerCannotScan_AnalystCan_AndAFailedCheapCheckNeverTouchesTheNetwork()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var viewer = await world.AddMemberAsync(owner.OrganizationId, MembershipRole.Viewer);
        var analyst = await world.AddMemberAsync(owner.OrganizationId, MembershipRole.Analyst);
        var callsBefore = world.Dns.Calls;

        var denied = await world.StartScanAsync(viewer, domainId, "www.example.com");
        Assert.False(denied.Allowed);
        Assert.Equal("RoleNotPermitted", denied.FailedCheckCode);
        Assert.Equal(callsBefore, world.Dns.Calls);

        Assert.True((await world.StartScanAsync(analyst, domainId, "www.example.com")).Allowed);
        Assert.True(world.Dns.Calls > callsBefore);
    }

    [Fact]
    public async Task SuspendedOrganization_IsDenied_WithoutLiveChecks()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        await world.SuspendAsync(owner.OrganizationId);
        var callsBefore = world.Dns.Calls;

        var result = await world.StartScanAsync(owner, domainId, "www.example.com");

        Assert.Equal("OrganizationSuspended", result.FailedCheckCode);
        Assert.Equal(callsBefore, world.Dns.Calls);
    }

    [Fact]
    public async Task UnverifiedDomain_CannotBeScanned()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var result = await world.StartScanAsync(owner, domainId, "example.com");

        Assert.Equal("DomainNotScannable", result.FailedCheckCode);
    }

    [Fact]
    public async Task RevokedAuthorization_BlocksScanning()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        await world.Grants.RevokeAsync(owner, domainId, "Contract ended.", CancellationToken.None);

        var result = await world.StartScanAsync(owner, domainId, "www.example.com");

        Assert.Equal("AuthorizationGrantInactive", result.FailedCheckCode);
    }

    [Fact]
    public async Task AnotherOrganizationsDomain_IsDenied_AndLoggedInTheRequestersOwnChain()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Owner");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var stranger = await world.NewOrgAsync("Stranger");
        var callsBefore = world.Dns.Calls;

        var result = await world.StartScanAsync(stranger, domainId, "www.example.com");

        Assert.False(result.Allowed);
        Assert.Equal("GrantOrganizationMismatch", result.FailedCheckCode);
        Assert.Equal(callsBefore, world.Dns.Calls);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(stranger.OrganizationId, (await db.PolicyDecisions.SingleAsync(d => d.Id == result.DecisionId)).OrganizationId);
        Assert.Equal(0, await db.ScanRuns.CountAsync());

        var missing = await Assert.ThrowsAsync<ServiceException>(() => world.StartScanAsync(stranger, Guid.NewGuid(), "x.example.com"));
        Assert.Equal("NotFound", missing.Code);
    }

    // ------------------------------------------------------------------ live proof decides

    [Fact]
    public async Task ProofAbsent_Denies_AndTheAtRiskStateIsSaved()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.ScannableByDnsAsync(world, owner);
        world.Dns.Script = _ => Absent;
        world.Time.Advance(TimeSpan.FromMinutes(5));

        var result = await world.StartScanAsync(owner, domainId, "www.example.com");

        Assert.False(result.Allowed);
        var evidence = await world.GetEvidenceAsync(evidenceId);
        Assert.Equal(EvidenceStatus.AtRisk, evidence.Status);
        Assert.Equal(TestWorld.Start.AddMinutes(5), evidence.FailingSince);
        Assert.Equal(DomainStatus.AtRisk, (await world.GetDomainAsync(domainId)).Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Contains("evidence.at_risk", await db.AuditLogs.Select(a => a.Action).ToListAsync());
        Assert.Equal(0, await db.ScanRuns.CountAsync());
    }

    [Fact]
    public async Task OneProofAbsent_AnotherValid_ScansOnlyWhatTheValidOneCovers()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, dnsEvidence) = await Scenarios.ScannableByDnsAsync(world, owner);
        var httpEvidence = await Scenarios.AddHttpEvidenceAsync(world, owner, domainId);
        world.Http.Script = _ => Absent;

        var result = await world.StartScanAsync(owner, domainId, "www.example.com");

        Assert.True(result.Allowed);                                                       // DNS still covers it
        Assert.Equal(EvidenceStatus.AtRisk, (await world.GetEvidenceAsync(httpEvidence)).Status);
        Assert.Equal(EvidenceStatus.Active, (await world.GetEvidenceAsync(dnsEvidence)).Status);
    }

    [Fact]
    public async Task InconclusiveCheck_IsToleratedForTwentyFourHours_ButNotLonger()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        world.Dns.Script = _ => VerificationObservation.Inconclusive(Reasons.ResolverFailure);

        world.Time.Advance(TimeSpan.FromHours(1));
        Assert.True((await world.StartScanAsync(owner, domainId, "www.example.com")).Allowed);

        world.Time.Advance(TimeSpan.FromHours(24));   // now 25 hours since the proof was last valid
        Assert.False((await world.StartScanAsync(owner, domainId, "www.example.com")).Allowed);
    }

    [Fact]
    public async Task EmailOnlyEvidence_AuthorizesTheRootWithoutALiveCheck_ButNeverASubdomain()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.VerifiedByEmailAsync(world, owner);
        await world.AddRuleAsync(owner, domainId, ScopeRuleType.Include, "example.com");
        await world.AddRuleAsync(owner, domainId, ScopeRuleType.Include, "*.example.com");

        Assert.True((await world.StartScanAsync(owner, domainId, "example.com")).Allowed);
        Assert.False((await world.StartScanAsync(owner, domainId, "www.example.com")).Allowed);
        Assert.Equal(0, world.Dns.Calls);   // there is nothing to observe for email proof
    }

    // ------------------------------------------------------------------ scheduled scans

    [Fact]
    public async Task ScheduledScan_IsDecidedForTheScheduleOwner_AndARetryIsHarmless()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var scheduleId = Guid.NewGuid();
        var occurrence = TestWorld.Start.AddDays(1);

        var first = await world.Scans.StartAsync(owner, domainId, new[] { "www.example.com" }, DecisionTrigger.Scheduled, scheduleId, occurrence, CancellationToken.None);
        var retry = await world.Scans.StartAsync(owner, domainId, new[] { "www.example.com" }, DecisionTrigger.Scheduled, scheduleId, occurrence, CancellationToken.None);

        Assert.True(first.Allowed);
        Assert.False(first.AlreadyStarted);
        Assert.True(retry.AlreadyStarted);
        Assert.Equal(first.ScanRunId, retry.ScanRunId);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(1, await db.ScanRuns.CountAsync());
        var decision = await db.PolicyDecisions.SingleAsync();
        Assert.Equal(DecisionTrigger.Scheduled, decision.Trigger);
        Assert.Null(decision.UserId);

        var next = await world.Scans.StartAsync(owner, domainId, new[] { "www.example.com" }, DecisionTrigger.Scheduled, scheduleId, occurrence.AddDays(1), CancellationToken.None);
        Assert.NotEqual(first.ScanRunId, next.ScanRunId);   // the next occurrence is a new scan
    }

    [Fact]
    public async Task TwoWorkersStartingTheSameOccurrence_ProduceOneScan()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var scheduleId = Guid.NewGuid();
        var occurrence = TestWorld.Start.AddDays(1);

        var results = await Task.WhenAll(
            world.Scans.StartAsync(owner, domainId, new[] { "www.example.com" }, DecisionTrigger.Scheduled, scheduleId, occurrence, CancellationToken.None),
            world.Scans.StartAsync(owner, domainId, new[] { "www.example.com" }, DecisionTrigger.Scheduled, scheduleId, occurrence, CancellationToken.None));

        Assert.Equal(results[0].ScanRunId, results[1].ScanRunId);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(1, await db.ScanRuns.CountAsync());
    }

    [Fact]
    public async Task ScheduledScan_ChecksTheOwnersRoleAgainEveryTime()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var demoted = await world.AddMemberAsync(owner.OrganizationId, MembershipRole.Viewer);

        var result = await world.Scans.StartAsync(demoted, domainId, new[] { "www.example.com" }, DecisionTrigger.Scheduled, Guid.NewGuid(), TestWorld.Start, CancellationToken.None);

        Assert.False(result.Allowed);
        Assert.Equal("RoleNotPermitted", result.FailedCheckCode);
    }

    [Fact]
    public async Task InvalidScheduleArguments_AreRejected()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var targets = new[] { "www.example.com" };

        foreach (var call in new Func<Task>[]
        {
            () => world.Scans.StartAsync(owner, domainId, targets, DecisionTrigger.Manual, Guid.NewGuid(), null, CancellationToken.None),
            () => world.Scans.StartAsync(owner, domainId, targets, DecisionTrigger.Manual, null, TestWorld.Start, CancellationToken.None),
            () => world.Scans.StartAsync(owner, domainId, targets, DecisionTrigger.Scheduled, null, null, CancellationToken.None)
        })
        {
            var ex = await Assert.ThrowsAsync<ServiceException>(call);
            Assert.Equal("InvalidSchedule", ex.Code);
        }
    }

    // ------------------------------------------------------------------ the database backstop

    [Fact]
    public async Task TheDatabaseRefusesAScanWithoutAnAllowDecision_OrAfterTheDecisionExpired()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.VerifiedByDnsAsync(world, owner);
        var denied = await world.StartScanAsync(owner, domainId, "www.example.com");   // no scope rules: a stored Deny
        Assert.False(denied.Allowed);

        await Assert.ThrowsAnyAsync<Exception>(() => world.Db.ExecuteAsync(
            $"INSERT INTO scan_runs (id, policy_decision_id, targets, status, created_at) VALUES ('{Guid.NewGuid()}', '{denied.DecisionId}', ARRAY['example.com'], 'Queued', now())"));

        string Decision(Guid id) =>
            $"INSERT INTO policy_decisions (id, organization_id, domain_id, user_id, trigger, outcome, failed_check_code, effective_scope_snapshot, evidence_ids, scope_rules_hash, decided_at, expires_at) " +
            $"VALUES ('{id}', '{owner.OrganizationId}', '{domainId}', NULL, 'Manual', 'Allow', NULL, '{{}}', '{{}}', 'h', '2026-10-20 12:00:00+00', '2026-10-20 12:15:00+00');";
        string Run(Guid decision, string createdAt) =>
            $"INSERT INTO scan_runs (id, policy_decision_id, targets, status, created_at) VALUES ('{Guid.NewGuid()}', '{decision}', ARRAY['example.com'], 'Queued', '{createdAt}');";

        var late = Guid.NewGuid();
        await Assert.ThrowsAnyAsync<Exception>(() => world.Db.ExecuteAsync(Decision(late) + Run(late, "2026-10-20 12:16:00+00")));

        var onTime = Guid.NewGuid();
        await world.Db.ExecuteAsync(Decision(onTime) + Run(onTime, "2026-10-20 12:14:00+00"));   // control: the same, but in time
    }
}
