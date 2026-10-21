using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class VerificationTests
{
    private readonly PostgresFixture _postgres;
    public VerificationTests(PostgresFixture postgres) => _postgres = postgres;

    private static Task<VerifyResult> Verify(TestWorld world, Actor actor, Guid challengeId) =>
        world.Verification.VerifyAsync(actor, challengeId, CancellationToken.None);

    private static async Task<(Guid DomainId, IssuedChallenge Challenge)> Prepare(TestWorld world, Actor actor, string name, VerificationMethod method = VerificationMethod.DnsTxt)
    {
        var domainId = await world.AddDomainAsync(actor, name);
        var challenge = await world.Challenges.IssueAsync(actor, domainId, method, null, CancellationToken.None);
        return (domainId, challenge);
    }

    // ------------------------------------------------------------------ success

    [Fact]
    public async Task ValidDnsProof_VerifiesTheDomain_AndCreatesStrongEvidence()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, challenge) = await Prepare(world, owner, "example.com");

        var result = await Verify(world, owner, challenge.ChallengeId);

        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
        Assert.Equal(DomainStatus.Verified, result.DomainStatus);
        Assert.Equal(ChallengeStatus.Passed, result.ChallengeStatus);
        Assert.False(result.DisputeOpened);

        await using var db = world.Db.CreateDbContext();
        var evidence = await db.VerificationEvidence.SingleAsync(e => e.DomainId == domainId);
        Assert.Equal(VerificationMethod.DnsTxt, evidence.Method);
        Assert.Equal(AssuranceLevel.High, evidence.Assurance);
        Assert.Equal(ScopeCeilingType.DomainAndSubdomains, evidence.ScopeCeilingType);
        Assert.Equal(EvidenceStatus.Active, evidence.Status);
        Assert.Equal(challenge.ChallengeId, evidence.ChallengeId);
        Assert.Equal(TestWorld.Start, evidence.LastValidAt);
        Assert.Null(evidence.FailingSince);
    }

    [Fact]
    public async Task ValidHttpFileProof_GivesMediumEvidence_ForTheExactHost()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, challenge) = await Prepare(world, owner, "example.com", VerificationMethod.HttpFile);

        await Verify(world, owner, challenge.ChallengeId);

        await using var db = world.Db.CreateDbContext();
        var evidence = await db.VerificationEvidence.SingleAsync(e => e.DomainId == domainId);
        Assert.Equal(AssuranceLevel.Medium, evidence.Assurance);
        Assert.Equal(ScopeCeilingType.ExactHost, evidence.ScopeCeilingType);
    }

    [Fact]
    public async Task EveryAttempt_IsRecorded_WithItsChecks_AndTheAuditChainStaysIntact()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");
        await Verify(world, owner, challenge.ChallengeId);

        await using var db = world.Db.CreateDbContext();
        var attempt = await db.VerificationAttempts.SingleAsync();
        Assert.Equal(CheckOutcome.ProofValid, attempt.Result);
        var check = await db.VerificationChecks.SingleAsync();
        Assert.Equal(attempt.Id, check.AttemptId);
        Assert.Equal(CheckTrigger.User, check.TriggeredBy);
        Assert.Null(check.EvidenceId);

        var actions = await db.AuditLogs.OrderBy(a => a.Sequence).Select(a => a.Action).ToListAsync();
        Assert.Contains("domain.verified", actions);
        Assert.Contains("verification.attempt", actions);
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, owner.OrganizationId, CancellationToken.None)).Intact);
    }

    // ------------------------------------------------------------------ failures and limits

    [Fact]
    public async Task AbsentProof_IsAFailedAttempt_ButTheChallengeStaysUsable()
    {
        var world = await TestWorld.CreateAsync(_postgres, dnsScript: _ => VerificationObservation.Absent(Reasons.TxtRecordMissing));
        var owner = await world.NewOrgAsync("Org");
        var (domainId, challenge) = await Prepare(world, owner, "example.com");

        var result = await Verify(world, owner, challenge.ChallengeId);

        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
        Assert.Equal(1, result.FailedAttempts);
        Assert.Equal(ChallengeStatus.Issued, result.ChallengeStatus);
        Assert.Equal(DomainStatus.Pending, (await world.GetDomainAsync(domainId)).Status);
    }

    [Fact]
    public async Task FiveFailedAttempts_ExpireTheChallenge_AndANewTokenIsRequired()
    {
        var world = await TestWorld.CreateAsync(_postgres, dnsScript: _ => VerificationObservation.Absent(Reasons.TxtRecordMissing));
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");

        VerifyResult last = null!;
        for (var i = 0; i < 5; i++) last = await Verify(world, owner, challenge.ChallengeId);

        Assert.Equal(5, last.FailedAttempts);
        Assert.Equal(ChallengeStatus.Expired, last.ChallengeStatus);

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Verify(world, owner, challenge.ChallengeId));
        Assert.Equal("ChallengeNotActive", ex.Code);
    }

    [Fact]
    public async Task InconclusiveResults_NeverUseUpAttempts()
    {
        var world = await TestWorld.CreateAsync(_postgres, dnsScript: _ => VerificationObservation.Inconclusive(Reasons.ResolverFailure));
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");

        VerifyResult last = null!;
        for (var i = 0; i < 8; i++) last = await Verify(world, owner, challenge.ChallengeId);

        Assert.Equal(CheckOutcome.Inconclusive, last.Outcome);
        Assert.Equal(0, last.FailedAttempts);
        Assert.Equal(ChallengeStatus.Issued, last.ChallengeStatus);
    }

    [Fact]
    public async Task DnsPropagation_IsRetriedInsideOneAttempt()
    {
        // Absent, Absent, then the record appears: one click, three checks, one attempt.
        var world = await TestWorld.CreateAsync(_postgres,
            dnsScript: call => call < 2 ? VerificationObservation.Absent(Reasons.TxtRecordMissing) : VerificationObservation.Valid());
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");

        var result = await Verify(world, owner, challenge.ChallengeId);

        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
        Assert.Equal(3, world.Dns.Calls);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(1, await db.VerificationAttempts.CountAsync());
        var retries = await db.VerificationChecks.OrderBy(c => c.RetryNumber).Select(c => c.RetryNumber).ToListAsync();
        Assert.Equal(new[] { 0, 1, 2 }, retries);
    }

    [Fact]
    public async Task DnsThatNeverAppears_IsOneFailedAttempt_NotThree()
    {
        var world = await TestWorld.CreateAsync(_postgres, dnsScript: _ => VerificationObservation.Absent(Reasons.TxtRecordMissing));
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");

        var result = await Verify(world, owner, challenge.ChallengeId);

        Assert.Equal(1, result.FailedAttempts);
        Assert.Equal(3, world.Dns.Calls);
    }

    [Fact]
    public async Task HttpFile_IsCheckedOnlyOncePerAttempt()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com", VerificationMethod.HttpFile);

        await Verify(world, owner, challenge.ChallengeId);

        Assert.Equal(1, world.Http.Calls);
    }

    [Fact]
    public async Task ExpiredChallenge_IsRejected_AndMarkedExpired()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");
        world.Time.Advance(TimeSpan.FromHours(49));

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Verify(world, owner, challenge.ChallengeId));

        Assert.Equal("ChallengeExpired", ex.Code);
        Assert.Equal(ChallengeStatus.Expired, (await world.GetChallengeAsync(challenge.ChallengeId)).Status);
        Assert.Equal(0, world.Dns.Calls);
    }

    [Fact]
    public async Task SupersededChallenge_CannotBeVerified()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, first) = await Prepare(world, owner, "example.com");
        await world.Challenges.IssueAsync(owner, domainId, VerificationMethod.DnsTxt, null, CancellationToken.None);

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Verify(world, owner, first.ChallengeId));
        Assert.Equal("ChallengeNotActive", ex.Code);
    }

    [Fact]
    public async Task PassedChallenge_CannotBeUsedAgain()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");
        await Verify(world, owner, challenge.ChallengeId);

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Verify(world, owner, challenge.ChallengeId));
        Assert.Equal("ChallengeNotActive", ex.Code);
    }

    [Fact]
    public async Task RateLimit_PerUser_StopsFurtherAttempts()
    {
        var world = await TestWorld.CreateAsync(_postgres,
            dnsScript: _ => VerificationObservation.Inconclusive(Reasons.ResolverFailure),
            options: new VerificationOptions { MaxAttemptsPerUserPerHour = 3 });
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");

        for (var i = 0; i < 3; i++) await Verify(world, owner, challenge.ChallengeId);

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Verify(world, owner, challenge.ChallengeId));
        Assert.Equal("RateLimited", ex.Code);

        world.Time.Advance(TimeSpan.FromMinutes(61));
        await Verify(world, owner, challenge.ChallengeId); // the window has passed
    }

    // ------------------------------------------------------------------ access

    [Fact]
    public async Task AnalystAndOtherOrganizations_CannotVerify()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");
        var stranger = await world.NewOrgAsync("Stranger");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Verify(world, stranger, challenge.ChallengeId));
        Assert.Equal("NotFound", ex.Code);
        Assert.Equal(0, world.Dns.Calls);
    }

    [Fact]
    public async Task SuspendedOrganization_CannotVerify()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (_, challenge) = await Prepare(world, owner, "example.com");
        await world.SuspendAsync(owner.OrganizationId);

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Verify(world, owner, challenge.ChallengeId));
        Assert.Equal("OrganizationSuspended", ex.Code);
    }

    // ------------------------------------------------------------------ competing claims

    [Fact]
    public async Task SecondOrganization_ProvingTheSameName_IsDisputed_AndTheIncumbentKeepsItsRights()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var a = await world.NewOrgAsync("A");
        var b = await world.NewOrgAsync("B");
        var (domainA, challengeA) = await Prepare(world, a, "example.com");
        var (domainB, challengeB) = await Prepare(world, b, "example.com");

        var first = await Verify(world, a, challengeA.ChallengeId);
        var second = await Verify(world, b, challengeB.ChallengeId);

        Assert.Equal(DomainStatus.Verified, first.DomainStatus);
        Assert.False(first.DisputeOpened);
        Assert.Equal(DomainStatus.Disputed, second.DomainStatus);
        Assert.True(second.DisputeOpened);

        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainA)).Status);
        Assert.Equal(DomainStatus.Disputed, (await world.GetDomainAsync(domainB)).Status);

        await using var db = world.Db.CreateDbContext();
        var dispute = await db.DomainDisputes.SingleAsync();
        Assert.Equal(domainA, dispute.IncumbentDomainId);
        Assert.Equal(domainB, dispute.ClaimantDomainId);
        Assert.Equal(DisputeStatus.Open, dispute.Status);

        // The claimant's proof is kept as history, but it does not make the domain Verified.
        Assert.Equal(1, await db.VerificationEvidence.CountAsync(e => e.DomainId == domainB));
        Assert.Equal(ChallengeStatus.Passed, (await world.GetChallengeAsync(challengeB.ChallengeId)).Status);
    }

    [Fact]
    public async Task DisputedDomain_CannotStartANewChallenge()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var a = await world.NewOrgAsync("A");
        var b = await world.NewOrgAsync("B");
        var (_, challengeA) = await Prepare(world, a, "example.com");
        var (domainB, challengeB) = await Prepare(world, b, "example.com");
        await Verify(world, a, challengeA.ChallengeId);
        await Verify(world, b, challengeB.ChallengeId);

        var ex = await Assert.ThrowsAsync<ServiceException>(() =>
            world.Challenges.IssueAsync(b, domainB, VerificationMethod.DnsTxt, null, CancellationToken.None));
        Assert.Equal("DomainNotVerifiable", ex.Code);
    }

    [Fact]
    public async Task TwoOrganizations_FinishingAtTheSameMoment_ProduceExactlyOneHolder()
    {
        var world = await TestWorld.CreateAsync(_postgres);

        for (var round = 0; round < 6; round++)
        {
            var name = $"race{round}.example.com";
            var a = await world.NewOrgAsync($"A{round}");
            var b = await world.NewOrgAsync($"B{round}");
            var (domainA, challengeA) = await Prepare(world, a, name);
            var (domainB, challengeB) = await Prepare(world, b, name);

            var results = await Task.WhenAll(
                Verify(world, a, challengeA.ChallengeId),
                Verify(world, b, challengeB.ChallengeId));

            var statuses = new[] { (await world.GetDomainAsync(domainA)).Status, (await world.GetDomainAsync(domainB)).Status };
            Assert.Equal(1, statuses.Count(s => s == DomainStatus.Verified));
            Assert.Equal(1, statuses.Count(s => s == DomainStatus.Disputed));
            Assert.Equal(1, results.Count(r => r.DisputeOpened));

            await using var db = world.Db.CreateDbContext();
            Assert.Equal(1, await db.DomainDisputes.CountAsync(d => d.IncumbentDomainId == domainA || d.IncumbentDomainId == domainB));
            Assert.Equal(1, await db.Domains.CountAsync(d => d.Name == name && d.Status == DomainStatus.Verified));
        }
    }

    [Fact]
    public async Task TwoSimultaneousClicks_OnOneChallenge_CannotBothSucceed()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, challenge) = await Prepare(world, owner, "example.com");

        var outcomes = await Task.WhenAll(
            Verify(world, owner, challenge.ChallengeId).ContinueWith(t => t.Exception?.GetBaseException()),
            Verify(world, owner, challenge.ChallengeId).ContinueWith(t => t.Exception?.GetBaseException()));

        // Whatever the interleaving, the domain ends up verified exactly once with one evidence row.
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(1, await db.VerificationEvidence.CountAsync(e => e.DomainId == domainId));
        Assert.All(outcomes.Where(e => e is not null), e => Assert.IsType<ServiceException>(e));
    }
}
