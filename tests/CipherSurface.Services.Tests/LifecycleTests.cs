using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class LifecycleTests
{
    private readonly PostgresFixture _postgres;
    public LifecycleTests(PostgresFixture postgres) => _postgres = postgres;

    private static VerificationObservation Absent => VerificationObservation.Absent(Reasons.TxtRecordMissing);

    private static Task<LifecycleSummary> Run(TestWorld world) => world.Lifecycle.RunAsync(CancellationToken.None);

    private static async Task MakeAtRisk(TestWorld world, Guid evidenceId)
    {
        world.Dns.Script = _ => Absent;
        await world.Reverify.ReverifyAsync(evidenceId, Guid.NewGuid(), 0, CancellationToken.None);
    }

    [Fact]
    public async Task AtRiskEvidence_LapsesAfterExactlySeventyTwoHours_AndTheDomainLapses()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        await MakeAtRisk(world, evidenceId);               // failing since Start

        world.Time.Advance(TimeSpan.FromHours(72) - TimeSpan.FromSeconds(1));
        var early = await Run(world);
        Assert.Equal(0, early.EvidenceLapsed);
        Assert.Equal(EvidenceStatus.AtRisk, (await world.GetEvidenceAsync(evidenceId)).Status);
        Assert.Equal(DomainStatus.AtRisk, (await world.GetDomainAsync(domainId)).Status);

        world.Time.Advance(TimeSpan.FromSeconds(1));
        var due = await Run(world);

        Assert.Equal(1, due.EvidenceLapsed);
        Assert.Equal(1, due.DomainsRecalculated);
        Assert.Equal(EvidenceStatus.Lapsed, (await world.GetEvidenceAsync(evidenceId)).Status);
        Assert.Equal(DomainStatus.Lapsed, (await world.GetDomainAsync(domainId)).Status);

        await using var db = world.Db.CreateDbContext();
        Assert.Contains("evidence.lapsed", await db.AuditLogs.Select(a => a.Action).ToListAsync());
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, owner.OrganizationId, CancellationToken.None)).Intact);
    }

    [Fact]
    public async Task EvidenceThatHealedInTime_IsNotLapsed()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        await MakeAtRisk(world, evidenceId);
        world.Time.Advance(TimeSpan.FromHours(40));
        world.Dns.Script = _ => VerificationObservation.Valid();
        await world.Reverify.ReverifyAsync(evidenceId, Guid.NewGuid(), 0, CancellationToken.None);   // healed

        world.Time.Advance(TimeSpan.FromHours(100));
        var summary = await Run(world);

        Assert.Equal(0, summary.EvidenceLapsed);
        Assert.Equal(EvidenceStatus.Active, (await world.GetEvidenceAsync(evidenceId)).Status);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);
    }

    [Fact]
    public async Task OneLapsedProof_DoesNotLapseTheDomain_WhileAnotherIsStillActive()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, dnsEvidence) = await Scenarios.VerifiedByDnsAsync(world, owner);
        var httpEvidence = await Scenarios.AddHttpEvidenceAsync(world, owner, domainId);
        await MakeAtRisk(world, dnsEvidence);

        world.Time.Advance(TimeSpan.FromHours(73));
        await Run(world);

        Assert.Equal(EvidenceStatus.Lapsed, (await world.GetEvidenceAsync(dnsEvidence)).Status);
        Assert.Equal(EvidenceStatus.Active, (await world.GetEvidenceAsync(httpEvidence)).Status);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);
    }

    [Fact]
    public async Task EmailEvidence_ExpiresAfterThirtyDays()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByEmailAsync(world, owner);

        world.Time.Advance(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(1));
        Assert.Equal(0, (await Run(world)).EvidenceExpired);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);

        world.Time.Advance(TimeSpan.FromSeconds(1));
        var summary = await Run(world);

        Assert.Equal(1, summary.EvidenceExpired);
        Assert.Equal(EvidenceStatus.Expired, (await world.GetEvidenceAsync(evidenceId)).Status);
        Assert.Equal(DomainStatus.Lapsed, (await world.GetDomainAsync(domainId)).Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Contains("evidence.expired", await db.AuditLogs.Select(a => a.Action).ToListAsync());
    }

    [Fact]
    public async Task OldChallenges_Expire_ButFreshAndPassedOnesAreUntouched()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var oldDomain = await world.AddDomainAsync(owner, "old.example.com");
        var oldChallenge = await world.Challenges.IssueAsync(owner, oldDomain, VerificationMethod.DnsTxt, null, CancellationToken.None);
        await Scenarios.VerifiedByDnsAsync(world, owner, "passed.example.com");

        world.Time.Advance(TimeSpan.FromHours(47));
        var freshDomain = await world.AddDomainAsync(owner, "fresh.example.com");
        var freshChallenge = await world.Challenges.IssueAsync(owner, freshDomain, VerificationMethod.DnsTxt, null, CancellationToken.None);
        world.Time.Advance(TimeSpan.FromHours(2));        // old: 49h, fresh: 2h

        var summary = await Run(world);

        Assert.True(summary.ChallengesExpired >= 1);
        Assert.Equal(ChallengeStatus.Expired, (await world.GetChallengeAsync(oldChallenge.ChallengeId)).Status);
        Assert.Equal(ChallengeStatus.Issued, (await world.GetChallengeAsync(freshChallenge.ChallengeId)).Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(1, await db.VerificationChallenges.CountAsync(c => c.Status == ChallengeStatus.Passed));
    }

    [Fact]
    public async Task RunningTwice_ChangesNothingTheSecondTime()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, evidenceId) = await Scenarios.VerifiedByDnsAsync(world, owner);
        await MakeAtRisk(world, evidenceId);
        world.Time.Advance(TimeSpan.FromHours(80));

        var first = await Run(world);
        var second = await Run(world);

        Assert.Equal(1, first.EvidenceLapsed);
        Assert.Equal(new LifecycleSummary(0, 0, 0, 0, 0), second);
    }

    [Fact]
    public async Task ALapsedProof_CanOnlyBeReplacedByANewChallenge()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, oldEvidence) = await Scenarios.VerifiedByDnsAsync(world, owner);
        await MakeAtRisk(world, oldEvidence);
        world.Time.Advance(TimeSpan.FromHours(73));
        await Run(world);
        Assert.Equal(DomainStatus.Lapsed, (await world.GetDomainAsync(domainId)).Status);

        world.Dns.Script = _ => VerificationObservation.Valid();
        var challenge = await world.Challenges.IssueAsync(owner, domainId, VerificationMethod.DnsTxt, null, CancellationToken.None);
        var result = await world.Verification.VerifyAsync(owner, challenge.ChallengeId, CancellationToken.None);

        Assert.Equal(DomainStatus.Verified, result.DomainStatus);
        Assert.Equal(EvidenceStatus.Lapsed, (await world.GetEvidenceAsync(oldEvidence)).Status);   // the old row stays dead
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(2, await db.VerificationEvidence.CountAsync(e => e.DomainId == domainId));
    }
}
