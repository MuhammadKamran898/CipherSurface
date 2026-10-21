using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class ReverificationTests
{
    private readonly PostgresFixture _postgres;
    public ReverificationTests(PostgresFixture postgres) => _postgres = postgres;

    private static Task<ReverifyResult> Recheck(TestWorld world, Guid evidenceId, Guid? run = null, int retry = 0) =>
        world.Reverify.ReverifyAsync(evidenceId, run ?? Guid.NewGuid(), retry, CancellationToken.None);

    private static VerificationObservation Absent => VerificationObservation.Absent(Reasons.TxtRecordMissing);

    [Fact]
    public async Task ValidCheck_KeepsEvidenceActive_AndRefreshesTheTimestamps()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        world.Time.Advance(TimeSpan.FromHours(5));

        var result = await Recheck(world, evidenceId);

        Assert.Equal(ReverifyStatus.Applied, result.Status);
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
        var evidence = await world.GetEvidenceAsync(evidenceId);
        Assert.Equal(EvidenceStatus.Active, evidence.Status);
        Assert.Equal(TestWorld.Start.AddHours(5), evidence.LastCheckedAt);
        Assert.Equal(TestWorld.Start.AddHours(5), evidence.LastValidAt);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);

        await using var db = world.Db.CreateDbContext();
        var check = await db.VerificationChecks.SingleAsync(c => c.EvidenceId == evidenceId);
        Assert.Equal(CheckTrigger.System, check.TriggeredBy);
        Assert.NotNull(check.CheckRunId);
        Assert.Null(check.AttemptId);
    }

    [Fact]
    public async Task ProofAbsent_MovesEvidenceAndDomainToAtRisk_AndStartsTheClock()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        world.Dns.Script = _ => Absent;
        world.Time.Advance(TimeSpan.FromHours(2));

        var result = await Recheck(world, evidenceId);

        Assert.Equal(EvidenceStatus.AtRisk, result.EvidenceStatus);
        Assert.Equal(DomainStatus.AtRisk, result.DomainStatus);
        var evidence = await world.GetEvidenceAsync(evidenceId);
        Assert.Equal(TestWorld.Start.AddHours(2), evidence.FailingSince);
        Assert.Equal(TestWorld.Start, evidence.LastValidAt);   // the last time it was GOOD does not move

        await using var db = world.Db.CreateDbContext();
        Assert.Contains("evidence.at_risk", await db.AuditLogs.Select(a => a.Action).ToListAsync());
        Assert.Equal(DomainStatus.AtRisk, (await world.GetDomainAsync(domainId)).Status);
    }

    [Fact]
    public async Task RepeatedAbsence_DoesNotRestartTheClock()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        world.Dns.Script = _ => Absent;
        world.Time.Advance(TimeSpan.FromHours(2));
        await Recheck(world, evidenceId);
        world.Time.Advance(TimeSpan.FromHours(10));

        await Recheck(world, evidenceId);

        var evidence = await world.GetEvidenceAsync(evidenceId);
        Assert.Equal(TestWorld.Start.AddHours(2), evidence.FailingSince);
        Assert.Equal(TestWorld.Start.AddHours(12), evidence.LastCheckedAt);
    }

    [Fact]
    public async Task ProofReturning_HealsEvidenceAndDomain()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        world.Dns.Script = _ => Absent;
        await Recheck(world, evidenceId);
        world.Dns.Script = _ => VerificationObservation.Valid();
        world.Time.Advance(TimeSpan.FromHours(3));

        var result = await Recheck(world, evidenceId);

        Assert.Equal(EvidenceStatus.Active, result.EvidenceStatus);
        var evidence = await world.GetEvidenceAsync(evidenceId);
        Assert.Null(evidence.FailingSince);
        Assert.Equal(TestWorld.Start.AddHours(3), evidence.LastValidAt);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Contains("evidence.healed", await db.AuditLogs.Select(a => a.Action).ToListAsync());
    }

    [Fact]
    public async Task Inconclusive_RecordsTheCheck_ButChangesNoState()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        world.Dns.Script = _ => VerificationObservation.Inconclusive(Reasons.ResolverFailure);
        world.Time.Advance(TimeSpan.FromHours(4));

        var result = await Recheck(world, evidenceId);

        Assert.Equal(ReverifyStatus.Applied, result.Status);
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
        var evidence = await world.GetEvidenceAsync(evidenceId);
        Assert.Equal(EvidenceStatus.Active, evidence.Status);
        Assert.Null(evidence.FailingSince);
        Assert.Equal(TestWorld.Start, evidence.LastValidAt);               // not refreshed: nothing was proven
        Assert.Equal(TestWorld.Start.AddHours(4), evidence.LastCheckedAt);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);
    }

    [Fact]
    public async Task RetriedJob_WithTheSameKey_IsRecognised_AndChecksOnlyOnce()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        var callsBefore = world.Dns.Calls;
        var run = Guid.NewGuid();

        var first = await Recheck(world, evidenceId, run);
        var second = await Recheck(world, evidenceId, run);

        Assert.Equal(ReverifyStatus.Applied, first.Status);
        Assert.Equal(ReverifyStatus.AlreadyProcessed, second.Status);
        Assert.Equal(callsBefore + 1, world.Dns.Calls);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(1, await db.VerificationChecks.CountAsync(c => c.CheckRunId == run));
    }

    [Fact]
    public async Task ABackoffRetry_UsesTheSameRunWithANewRetryNumber()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        var run = Guid.NewGuid();
        world.Dns.Script = _ => VerificationObservation.Inconclusive(Reasons.ResolverFailure);

        await Recheck(world, evidenceId, run, retry: 0);
        var retry = await Recheck(world, evidenceId, run, retry: 1);

        Assert.Equal(ReverifyStatus.Applied, retry.Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(new[] { 0, 1 }, await db.VerificationChecks.Where(c => c.CheckRunId == run).OrderBy(c => c.RetryNumber).Select(c => c.RetryNumber).ToListAsync());
    }

    [Fact]
    public async Task ALaterDailyCheck_IsNeverRejectedAsADuplicate()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);

        await Recheck(world, evidenceId);
        world.Time.Advance(TimeSpan.FromDays(1));
        var next = await Recheck(world, evidenceId);

        Assert.Equal(ReverifyStatus.Applied, next.Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(2, await db.VerificationChecks.CountAsync(c => c.EvidenceId == evidenceId));
    }

    [Fact]
    public async Task LapsedEvidence_IsNeverChecked_AndNeverRevives()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        await world.Db.ExecuteAsync("UPDATE verification_evidence SET status = 'Lapsed'");
        var callsBefore = world.Dns.Calls;

        var result = await Recheck(world, evidenceId);   // the script would say "valid"

        Assert.Equal(ReverifyStatus.Skipped, result.Status);
        Assert.Equal("TerminalEvidence", result.Reason);
        Assert.Equal(callsBefore, world.Dns.Calls);
        Assert.Equal(EvidenceStatus.Lapsed, (await world.GetEvidenceAsync(evidenceId)).Status);
    }

    [Fact]
    public async Task EmailEvidence_IsSkipped_BecauseThereIsNothingToObserve()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, evidenceId) = await Scenarios.VerifiedByEmailAsync(world, owner);

        var result = await Recheck(world, evidenceId);

        Assert.Equal(ReverifyStatus.Skipped, result.Status);
        Assert.Equal("NotObservable", result.Reason);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(0, await db.VerificationChecks.CountAsync(c => c.EvidenceId == evidenceId));
    }

    [Fact]
    public async Task EvidenceChangedWhileTheCheckWasRunning_IsNotOverwritten()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        world.Dns.Script = _ =>
        {
            // Someone else touches the row while our network check is in flight.
            world.Db.ExecuteAsync("UPDATE verification_evidence SET last_checked_at = now()").GetAwaiter().GetResult();
            return Absent;
        };

        var result = await Recheck(world, evidenceId);

        Assert.Equal(ReverifyStatus.Skipped, result.Status);
        Assert.Equal("ChangedDuringCheck", result.Reason);
        Assert.Equal(EvidenceStatus.Active, (await world.GetEvidenceAsync(evidenceId)).Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(0, await db.VerificationChecks.CountAsync(c => c.EvidenceId == evidenceId));
    }

    [Fact]
    public async Task UnknownEvidence_IsSkipped()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var result = await Recheck(world, Guid.NewGuid());
        Assert.Equal(ReverifyStatus.Skipped, result.Status);
        Assert.Equal("NotFound", result.Reason);
    }
}
