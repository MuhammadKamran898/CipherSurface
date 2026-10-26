using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>
/// A check run key is one evidence-check cycle of one evidence row. A gate evaluation or a continuation check that
/// looks at several rows must record each of them, and a retried check must still be recognised by its key.
/// </summary>
[Collection("postgres")]
public class CheckRunKeyTests
{
    private readonly PostgresFixture _postgres;
    public CheckRunKeyTests(PostgresFixture postgres) => _postgres = postgres;

    private static async Task<List<CipherSurface.Data.Entities.VerificationCheck>> EvidenceChecks(TestWorld world)
    {
        await using var db = world.Db.CreateDbContext();
        return await db.VerificationChecks.AsNoTracking().Where(c => c.EvidenceId != null).ToListAsync();
    }

    [Fact]
    public async Task OneGateEvaluationLookingAtTwoEvidenceRows_RecordsBoth_EachWithItsOwnRunKey()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, dnsEvidence) = await Scenarios.ScannableByDnsAsync(world, owner);
        var httpEvidence = await Scenarios.AddHttpEvidenceAsync(world, owner, domainId);

        var result = await world.StartScanAsync(owner, domainId, "example.com");

        Assert.True(result.Allowed);
        var checks = await EvidenceChecks(world);
        Assert.Equal(2, checks.Count);
        Assert.Equal(new[] { dnsEvidence, httpEvidence }.OrderBy(i => i), checks.Select(c => c.EvidenceId!.Value).OrderBy(i => i));
        Assert.All(checks, c => Assert.NotNull(c.CheckRunId));
        Assert.Equal(2, checks.Select(c => c.CheckRunId).Distinct().Count());   // never shared between rows
        Assert.All(checks, c => Assert.Equal(0, c.RetryNumber));
        Assert.All(checks, c => Assert.Equal(CheckTrigger.System, c.TriggeredBy));
        Assert.All(checks, c => Assert.Contains($"gate:{result.DecisionId:D}", c.Detail));   // traceable to the decision
    }

    [Fact]
    public async Task MixedOutcomes_AreBothRecorded_AndTheAuthorizationRuleIsUnchanged()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var httpEvidence = await Scenarios.AddHttpEvidenceAsync(world, owner, domainId);
        world.Http.Script = _ => VerificationObservation.Absent(Reasons.NotFound);

        var covered = await world.StartScanAsync(owner, domainId, "www.example.com");   // DNS covers it
        Assert.True(covered.Allowed);
        Assert.Equal(EvidenceStatus.AtRisk, (await world.GetEvidenceAsync(httpEvidence)).Status);

        var outcomes = (await EvidenceChecks(world)).Select(c => c.Outcome).OrderBy(o => o).ToList();
        Assert.Equal(new[] { CheckOutcome.ProofValid, CheckOutcome.ProofAbsent }.OrderBy(o => o), outcomes);

        // The absent HTTP proof still contributes no scope: with DNS gone as well, nothing is allowed.
        world.Dns.Script = _ => VerificationObservation.Absent(Reasons.TxtRecordMissing);
        Assert.False((await world.StartScanAsync(owner, domainId, "www.example.com")).Allowed);
    }

    [Fact]
    public async Task ContinuationCheckWithTwoStaleEvidenceRows_RecordsBoth()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        await Scenarios.AddHttpEvidenceAsync(world, owner, domainId);
        var (runId, _) = await Scenarios.RunningScanAsync(world, owner, domainId, "example.com");
        var dnsBefore = world.Dns.Calls;
        var httpBefore = world.Http.Calls;
        world.Time.Advance(TimeSpan.FromHours(25));   // both proofs are now older than 24 hours, so both are checked live

        var result = await world.Runs.ContinueAsync(runId, new[] { "example.com" }, CancellationToken.None);

        Assert.Equal(ContinuationOutcome.Continue, result.Outcome);
        Assert.Equal(dnsBefore + 1, world.Dns.Calls);
        Assert.Equal(httpBefore + 1, world.Http.Calls);
        var fromContinuation = (await EvidenceChecks(world)).Where(c => c.Detail.Contains($"continuation:{runId:D}")).ToList();
        Assert.Equal(2, fromContinuation.Count);
        Assert.Equal(2, fromContinuation.Select(c => c.CheckRunId).Distinct().Count());
    }

    [Fact]
    public async Task TheDatabaseStillRejectsADuplicateRunKey_ButAllowsANewRetryNumber()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, dnsEvidence) = await Scenarios.ScannableByDnsAsync(world, owner);
        var httpEvidence = await Scenarios.AddHttpEvidenceAsync(world, owner, domainId);
        var run = Guid.NewGuid();

        string Insert(Guid evidence, Guid runKey, int retry) =>
            $"INSERT INTO verification_checks (id, evidence_id, check_run_id, retry_number, checked_at, outcome, triggered_by, detail) " +
            $"VALUES ('{Guid.NewGuid()}', '{evidence}', '{runKey}', {retry}, '2026-10-20 12:00:00+00', 'ProofValid', 'System', '{{}}')";

        await world.Db.ExecuteAsync(Insert(dnsEvidence, run, 0));
        await Assert.ThrowsAnyAsync<Exception>(() => world.Db.ExecuteAsync(Insert(dnsEvidence, run, 0)));     // a retried job is recognised
        await world.Db.ExecuteAsync(Insert(dnsEvidence, run, 1));                                            // a backoff retry is a new row
        await Assert.ThrowsAnyAsync<Exception>(() => world.Db.ExecuteAsync(Insert(httpEvidence, run, 0)));   // one key never spans two evidence rows
    }
}
