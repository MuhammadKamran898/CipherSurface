using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class ScanRunTests
{
    private readonly PostgresFixture _postgres;
    public ScanRunTests(PostgresFixture postgres) => _postgres = postgres;

    private static VerificationObservation Absent => VerificationObservation.Absent(Reasons.TxtRecordMissing);

    private static Task<ContinuationResult> Continue(TestWorld world, Guid runId, params string[] remaining) =>
        world.Runs.ContinueAsync(runId, remaining, CancellationToken.None);

    private static async Task<Domain> Dom(TestWorld world, Guid id) => await world.GetDomainAsync(id);

    private static async Task<CipherSurface.Data.Entities.ScanRun> GetRun(TestWorld world, Guid runId)
    {
        await using var db = world.Db.CreateDbContext();
        return await db.ScanRuns.AsNoTracking().SingleAsync(r => r.Id == runId);
    }

    private static async Task<List<ContinuationOutcome>> Outcomes(TestWorld world, Guid runId)
    {
        await using var db = world.Db.CreateDbContext();
        return await db.ScanRunAuthorizationChecks.Where(c => c.ScanRunId == runId).OrderBy(c => c.Sequence).Select(c => c.Outcome).ToListAsync();
    }

    // ------------------------------------------------------------------ begin

    [Fact]
    public async Task Begin_StartsTheScan_AndHandsOverASignedWorkOrder()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);

        var (runId, order) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com", "example.com");

        var run = await GetRun(world, runId);
        Assert.Equal(ScanRunStatus.Running, run.Status);
        Assert.Equal(TestWorld.Start, run.StartedAt);
        Assert.Equal(TestWorld.Start.AddMinutes(5), run.LeaseExpiresAt);
        Assert.Equal(TestWorld.Start.AddMinutes(5), order.LeaseExpiresAt);
        Assert.Equal(TestWorld.Start.AddMinutes(15), order.ExpiresAt);          // the decision's own start-by deadline
        Assert.Equal(new[] { "example.com", "www.example.com" }, order.Targets);
        Assert.Contains("example.com", order.ScopeSnapshot);
        Assert.True(world.Signer.Verify(order));

        var again = await Assert.ThrowsAsync<ServiceException>(() => world.Runs.BeginAsync(runId, CancellationToken.None));
        Assert.Equal("RunNotQueued", again.Code);
    }

    [Fact]
    public async Task Begin_AfterTheStartDecisionExpired_IsRefused_AndTheScanIsCancelled()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var started = await world.StartScanAsync(owner, domainId, "www.example.com");
        world.Time.Advance(TimeSpan.FromMinutes(16));

        var ex = await Assert.ThrowsAsync<ServiceException>(() => world.Runs.BeginAsync(started.ScanRunId!.Value, CancellationToken.None));

        Assert.Equal("StartDeadlineExpired", ex.Code);
        var run = await GetRun(world, started.ScanRunId!.Value);
        Assert.Equal(ScanRunStatus.Cancelled, run.Status);
        Assert.Equal("StartDeadlineExpired", run.CancelReason);
        await using var db = world.Db.CreateDbContext();
        Assert.Contains("scan.start_expired", await db.AuditLogs.Select(a => a.Action).ToListAsync());
    }

    [Fact]
    public async Task UnknownScan_IsNotFound()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var ex = await Assert.ThrowsAsync<ServiceException>(() => world.Runs.BeginAsync(Guid.NewGuid(), CancellationToken.None));
        Assert.Equal("NotFound", ex.Code);
        var ex2 = await Assert.ThrowsAsync<ServiceException>(() => Continue(world, Guid.NewGuid(), "a.example.com"));
        Assert.Equal("NotFound", ex2.Code);
    }

    // ------------------------------------------------------------------ continuing

    [Fact]
    public async Task Continue_RenewsTheLease_AndRecordsEachCheckInOrder()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com", "example.com");
        var callsBefore = world.Dns.Calls;

        world.Time.Advance(TimeSpan.FromMinutes(2));
        var first = await Continue(world, runId, "www.example.com", "example.com");
        world.Time.Advance(TimeSpan.FromMinutes(2));
        var second = await Continue(world, runId, "example.com");

        Assert.Equal(ContinuationOutcome.Continue, first.Outcome);
        Assert.Equal(new[] { "example.com", "www.example.com" }, first.AllowedTargets.OrderBy(t => t));
        Assert.Empty(first.BlockedTargets);
        Assert.Equal(TestWorld.Start.AddMinutes(7), first.LeaseExpiresAt);
        Assert.Equal(TestWorld.Start.AddMinutes(9), second.LeaseExpiresAt);
        Assert.Equal(TestWorld.Start.AddMinutes(9), (await GetRun(world, runId)).LeaseExpiresAt);
        Assert.Equal(new[] { ContinuationOutcome.Continue, ContinuationOutcome.Continue }, await Outcomes(world, runId));
        Assert.Equal(callsBefore, world.Dns.Calls);   // proof checked a minute ago is judged from stored state, no network
    }

    [Fact]
    public async Task Continue_ChecksOldEvidenceLive()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        var callsBefore = world.Dns.Calls;
        world.Time.Advance(TimeSpan.FromHours(25));

        var result = await Continue(world, runId, "www.example.com");

        Assert.Equal(ContinuationOutcome.Continue, result.Outcome);
        Assert.Equal(callsBefore + 1, world.Dns.Calls);
        Assert.Equal(TestWorld.Start.AddHours(25), (await world.GetEvidenceAsync(evidenceId)).LastValidAt);
    }

    [Fact]
    public async Task Continue_NeverLetsAWorkerWidenItsOwnTargets()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");

        // other.example.com is inside the scope, but this scan was never authorized for it.
        var result = await Continue(world, runId, "www.example.com", "other.example.com");

        Assert.Equal(ContinuationOutcome.Restrict, result.Outcome);
        Assert.Equal("TargetNotInScanRequest", result.ReasonCode);
        Assert.Equal(new[] { "www.example.com" }, result.AllowedTargets);
        Assert.Equal(new[] { "other.example.com" }, result.BlockedTargets);
        Assert.Equal(ScanRunStatus.Running, result.RunStatus);
    }

    [Fact]
    public async Task ScopeNarrowedMidScan_RestrictsOnlyTheAffectedTargets()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com", "shop.example.com");
        await world.AddRuleAsync(owner, domainId, ScopeRuleType.Exclude, "shop.example.com");

        var result = await Continue(world, runId, "www.example.com", "shop.example.com");

        Assert.Equal(ContinuationOutcome.Restrict, result.Outcome);
        Assert.Equal("TargetsOutsideCurrentScope", result.ReasonCode);
        Assert.Equal(new[] { "www.example.com" }, result.AllowedTargets);
        Assert.Equal(new[] { "shop.example.com" }, result.BlockedTargets);
        Assert.NotNull(result.LeaseExpiresAt);                       // the rest of the scan may go on
        Assert.Equal(ScanRunStatus.Running, (await GetRun(world, runId)).Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Contains("scan.restricted", await db.AuditLogs.Select(a => a.Action).ToListAsync());
    }

    [Fact]
    public async Task OneProofLapsing_WhileAnotherStillCovers_RestrictsInsteadOfCancelling()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, dnsEvidence) = await Scenarios.ScannableByDnsAsync(world, owner);
        await Scenarios.AddHttpEvidenceAsync(world, owner, domainId);   // covers exactly example.com
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "example.com", "www.example.com");

        world.Dns.Script = _ => Absent;
        await world.Reverify.ReverifyAsync(dnsEvidence, Guid.NewGuid(), 0, CancellationToken.None);
        world.Time.Advance(TimeSpan.FromHours(73));
        await world.Lifecycle.RunAsync(CancellationToken.None);          // the DNS proof lapses

        Assert.Equal(DomainStatus.Verified, (await Dom(world, domainId)).Status);   // the HTTP proof keeps the domain alive
        var result = await Continue(world, runId, "example.com", "www.example.com");

        Assert.Equal(ContinuationOutcome.Restrict, result.Outcome);
        Assert.Equal(new[] { "example.com" }, result.AllowedTargets);
        Assert.Equal(new[] { "www.example.com" }, result.BlockedTargets);
        Assert.Equal(ScanRunStatus.Running, result.RunStatus);
    }

    // ------------------------------------------------------------------ cancelling

    [Fact]
    public async Task SuspendingTheOrganization_FlagsTheScanAtOnce_AndTheNextCheckEndsIt()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        var admin = await world.NewPlatformAdminAsync();

        await world.Orgs.SuspendAsync(admin, owner.OrganizationId, "Payment dispute.", CancellationToken.None);

        var flagged = await GetRun(world, runId);
        Assert.Equal(ScanRunStatus.CancelRequested, flagged.Status);
        Assert.Equal("OrganizationSuspended", flagged.CancelReason);

        var result = await Continue(world, runId, "www.example.com");
        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Null(result.LeaseExpiresAt);
        Assert.Empty(result.AllowedTargets);
        Assert.Equal(ScanRunStatus.Cancelled, result.RunStatus);

        var finished = await GetRun(world, runId);
        Assert.Equal(ScanRunStatus.Cancelled, finished.Status);
        Assert.Equal("OrganizationSuspended", finished.CancelReason);   // the original reason is kept
        Assert.NotNull(finished.FinishedAt);
        Assert.Equal(ContinuationOutcome.Cancel, (await Outcomes(world, runId)).Last());

        // A late or replayed check on a finished scan changes nothing.
        var late = await Continue(world, runId, "www.example.com");
        Assert.Equal("ScanRunNotRunning", late.ReasonCode);
        Assert.Single(await Outcomes(world, runId));
    }

    [Fact]
    public async Task SuspensionNobodyFlagged_IsStillCaughtByTheCheckItself()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        await world.SuspendAsync(owner.OrganizationId);   // changed directly in the database, no flagging

        var result = await Continue(world, runId, "www.example.com");

        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Equal("OrganizationSuspended", result.ReasonCode);
    }

    [Fact]
    public async Task RevokingTheGrant_StopsARunningScan()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");

        await world.Grants.RevokeAsync(owner, domainId, "Authorization withdrawn.", CancellationToken.None);

        Assert.Equal(ScanRunStatus.CancelRequested, (await GetRun(world, runId)).Status);
        Assert.Equal(ContinuationOutcome.Cancel, (await Continue(world, runId, "www.example.com")).Outcome);
    }

    [Fact]
    public async Task DomainThatLapses_StopsItsRunningScans()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        world.Dns.Script = _ => Absent;
        await world.Reverify.ReverifyAsync(evidenceId, Guid.NewGuid(), 0, CancellationToken.None);
        Assert.Equal(ScanRunStatus.Running, (await GetRun(world, runId)).Status);   // AtRisk alone does not stop a scan

        world.Time.Advance(TimeSpan.FromHours(73));
        await world.Lifecycle.RunAsync(CancellationToken.None);

        var flagged = await GetRun(world, runId);
        Assert.Equal(ScanRunStatus.CancelRequested, flagged.Status);
        Assert.Equal("DomainNotScannable", flagged.CancelReason);
        Assert.Equal(ContinuationOutcome.Cancel, (await Continue(world, runId, "www.example.com")).Outcome);
    }

    [Fact]
    public async Task ProofGoingMissingWhileScanning_DoesNotCancelByItself_ButTheEvidenceIsMarkedAtRisk()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.ScannableByDnsAsync(world, owner);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        world.Dns.Script = _ => Absent;
        world.Time.Advance(TimeSpan.FromHours(25));   // stale, so the check is live

        var result = await Continue(world, runId, "www.example.com");

        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);            // the only proof is known to be absent
        Assert.Equal(EvidenceStatus.AtRisk, (await world.GetEvidenceAsync(evidenceId)).Status);
        Assert.Equal(DomainStatus.AtRisk, (await Dom(world, domainId)).Status);
    }

    // ------------------------------------------------------------------ finishing

    [Fact]
    public async Task Complete_MarksTheScan_AndOnlyAnUntouchedScanCountsAsFullCoverage()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);

        var (clean, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        await Continue(world, clean, "www.example.com");
        Assert.Equal(ScanRunStatus.Completed, await world.Runs.CompleteAsync(clean, true, CancellationToken.None));
        Assert.True(await world.Runs.WasFullyCoveredAsync(clean, CancellationToken.None));

        var (restricted, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com", "shop.example.com");
        await world.AddRuleAsync(owner, domainId, ScopeRuleType.Exclude, "shop.example.com");
        await Continue(world, restricted, "www.example.com", "shop.example.com");
        Assert.Equal(ScanRunStatus.Completed, await world.Runs.CompleteAsync(restricted, true, CancellationToken.None));
        Assert.False(await world.Runs.WasFullyCoveredAsync(restricted, CancellationToken.None));   // partial: missing findings prove nothing
    }

    [Fact]
    public async Task Complete_FailedWorker_AndCancelledScans_AreNeverFullCoverage()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);

        var (failedRun, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        Assert.Equal(ScanRunStatus.Failed, await world.Runs.CompleteAsync(failedRun, false, CancellationToken.None));
        Assert.False(await world.Runs.WasFullyCoveredAsync(failedRun, CancellationToken.None));

        var (cancelled, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        await world.Grants.RevokeAsync(owner, domainId, "Withdrawn.", CancellationToken.None);   // flags the running scan
        Assert.Equal(ScanRunStatus.Cancelled, await world.Runs.CompleteAsync(cancelled, true, CancellationToken.None));   // a told-to-stop scan ends Cancelled
        Assert.False(await world.Runs.WasFullyCoveredAsync(cancelled, CancellationToken.None));

        var ex = await Assert.ThrowsAsync<ServiceException>(() => world.Runs.CompleteAsync(failedRun, true, CancellationToken.None));
        Assert.Equal("RunNotRunning", ex.Code);
    }

    [Fact]
    public async Task Sweep_FailsScansWhoseLeaseRanOut_AndCancelsOnesThatNeverStarted()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);

        var (dead, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "www.example.com");
        var (alive, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "shop.example.com");
        var neverStarted = (await world.StartScanAsync(owner, domainId, "api.example.com")).ScanRunId!.Value;

        world.Time.Advance(TimeSpan.FromMinutes(4));
        await Continue(world, alive, "shop.example.com");     // lease now runs until minute 9
        world.Time.Advance(TimeSpan.FromMinutes(2));          // minute 6: the first lease (minute 5) is over
        var early = await world.Runs.SweepAsync(CancellationToken.None);
        Assert.Equal((1, 0), early);

        world.Time.Advance(TimeSpan.FromMinutes(10));         // minute 16: the unused start decision (minute 15) is over
        var late = await world.Runs.SweepAsync(CancellationToken.None);
        Assert.Equal(1, late.StartsExpired);

        Assert.Equal(ScanRunStatus.Failed, (await GetRun(world, dead)).Status);
        Assert.Equal("LeaseExpired", (await GetRun(world, dead)).CancelReason);
        Assert.Equal(ScanRunStatus.Cancelled, (await GetRun(world, neverStarted)).Status);
        Assert.Equal((0, 0), await world.Runs.SweepAsync(CancellationToken.None));   // idempotent
    }
}
