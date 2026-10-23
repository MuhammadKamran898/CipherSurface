using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class DisputeTests
{
    private readonly PostgresFixture _postgres;
    public DisputeTests(PostgresFixture postgres) => _postgres = postgres;

    private static VerificationObservation Absent => VerificationObservation.Absent(Reasons.TxtRecordMissing);

    private static Task<DisputeResolutionResult> Resolve(TestWorld world, PlatformAdmin admin, Guid disputeId, DisputeResolution resolution, string note = "Reviewed the ownership evidence.") =>
        world.Disputes.ResolveAsync(admin, disputeId, resolution, note, CancellationToken.None);

    private static async Task<int> VerifiedHolders(TestWorld world, string name)
    {
        await using var db = world.Db.CreateDbContext();
        return await db.Domains.CountAsync(d => d.Name == name && d.Status == DomainStatus.Verified);
    }

    /// <summary>The holder's proof disappears and lapses through the normal re-check and housekeeping path.</summary>
    private static async Task LapseTheHolder(TestWorld world, OpenDispute d)
    {
        world.Dns.Script = _ => Absent;
        await world.Reverify.ReverifyAsync(d.HolderEvidenceId, Guid.NewGuid(), 0, CancellationToken.None);
        world.Time.Advance(TimeSpan.FromHours(73));
        await world.Lifecycle.RunAsync(CancellationToken.None);
        world.Dns.Script = _ => VerificationObservation.Valid();
    }

    // ------------------------------------------------------------------ listing

    [Fact]
    public async Task ListOpen_ShowsTheDisputeWithBothSides()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        var admin = await world.NewPlatformAdminAsync();

        var list = await world.Disputes.ListOpenAsync(admin, CancellationToken.None);

        var item = Assert.Single(list);
        Assert.Equal(d.DisputeId, item.DisputeId);
        Assert.Equal("example.com", item.DomainName);
        Assert.Equal("Holder", item.IncumbentOrganizationName);
        Assert.Equal("Claimant", item.ClaimantOrganizationName);
        Assert.Equal(DomainStatus.Verified, item.IncumbentStatus);
        Assert.Equal(d.HolderDomainId, item.IncumbentDomainId);
        Assert.Equal(d.ClaimantDomainId, item.ClaimantDomainId);
    }

    // ------------------------------------------------------------------ administrator decisions

    [Fact]
    public async Task IncumbentWins_RevokesTheClaimantsProof_AndLeavesTheHolderUntouched()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        var admin = await world.NewPlatformAdminAsync();

        var result = await Resolve(world, admin, d.DisputeId, DisputeResolution.IncumbentWins, "Claimant could not show control.");

        Assert.Equal(DisputeStatus.ResolvedIncumbent, result.Status);
        Assert.Equal(DomainStatus.Verified, result.IncumbentStatus);
        Assert.Equal(DomainStatus.Lapsed, result.ClaimantStatus);
        Assert.Equal(EvidenceStatus.Revoked, (await world.GetEvidenceAsync(d.ClaimantEvidenceId)).Status);
        Assert.Equal(EvidenceStatus.Active, (await world.GetEvidenceAsync(d.HolderEvidenceId)).Status);
        Assert.Equal(1, await VerifiedHolders(world, "example.com"));

        await using var db = world.Db.CreateDbContext();
        var dispute = await db.DomainDisputes.SingleAsync();
        Assert.Equal(admin.UserId, dispute.ResolvedByUserId);
        Assert.Equal("Claimant could not show control.", dispute.Note);
        Assert.NotNull(dispute.ResolvedAt);
    }

    [Fact]
    public async Task ClaimantWins_RevokesTheHoldersProof_AndTheClaimantBecomesTheOnlyHolder()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        var admin = await world.NewPlatformAdminAsync();

        var result = await Resolve(world, admin, d.DisputeId, DisputeResolution.ClaimantWins, "Holder sold the domain.");

        Assert.Equal(DisputeStatus.ResolvedClaimant, result.Status);
        Assert.Equal(DomainStatus.Lapsed, result.IncumbentStatus);
        Assert.Equal(DomainStatus.Verified, result.ClaimantStatus);
        Assert.Equal(EvidenceStatus.Revoked, (await world.GetEvidenceAsync(d.HolderEvidenceId)).Status);
        Assert.Equal(EvidenceStatus.Active, (await world.GetEvidenceAsync(d.ClaimantEvidenceId)).Status);
        Assert.Equal(1, await VerifiedHolders(world, "example.com"));
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(d.ClaimantDomainId)).Status);
        Assert.Equal(DomainStatus.Lapsed, (await world.GetDomainAsync(d.HolderDomainId)).Status);
    }

    [Fact]
    public async Task EveryResolution_IsWrittenToBothOrganizationsAuditChains()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        var admin = await world.NewPlatformAdminAsync();

        await Resolve(world, admin, d.DisputeId, DisputeResolution.ClaimantWins);

        await using var db = world.Db.CreateDbContext();
        foreach (var orgId in new[] { d.Holder.OrganizationId, d.Claimant.OrganizationId })
        {
            var entry = await db.AuditLogs.SingleAsync(a => a.OrganizationId == orgId && a.Action == "dispute.resolved");
            Assert.Equal("PlatformAdmin", entry.ActorType);
            Assert.Equal(admin.UserId, entry.ActorId);
            Assert.Contains("ClaimantWins", entry.Data);
            Assert.True((await new AuditChainVerifier().VerifyAsync(db, orgId, CancellationToken.None)).Intact);
        }
    }

    [Fact]
    public async Task ClaimantWins_IsRefused_WhenTheClaimantHasNoValidProof_AndNothingChanges()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        var admin = await world.NewPlatformAdminAsync();
        await world.Db.ExecuteAsync($"UPDATE verification_evidence SET status = 'Lapsed' WHERE id = '{d.ClaimantEvidenceId}'");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Resolve(world, admin, d.DisputeId, DisputeResolution.ClaimantWins));

        Assert.Equal("ClaimantHasNoValidProof", ex.Code);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(d.HolderDomainId)).Status);
        Assert.Equal(EvidenceStatus.Active, (await world.GetEvidenceAsync(d.HolderEvidenceId)).Status);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(DisputeStatus.Open, (await db.DomainDisputes.SingleAsync()).Status);
    }

    [Fact]
    public async Task ADisputeCanOnlyBeResolvedOnce_AndBadInputIsRejected()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        var admin = await world.NewPlatformAdminAsync();

        var noNote = await Assert.ThrowsAsync<ServiceException>(() => Resolve(world, admin, d.DisputeId, DisputeResolution.IncumbentWins, "  "));
        Assert.Equal("NoteRequired", noNote.Code);
        var longNote = await Assert.ThrowsAsync<ServiceException>(() => Resolve(world, admin, d.DisputeId, DisputeResolution.IncumbentWins, new string('x', 2001)));
        Assert.Equal("NoteTooLong", longNote.Code);
        var unknown = await Assert.ThrowsAsync<ServiceException>(() => Resolve(world, admin, Guid.NewGuid(), DisputeResolution.IncumbentWins));
        Assert.Equal("NotFound", unknown.Code);

        await Resolve(world, admin, d.DisputeId, DisputeResolution.IncumbentWins);
        var again = await Assert.ThrowsAsync<ServiceException>(() => Resolve(world, admin, d.DisputeId, DisputeResolution.ClaimantWins));
        Assert.Equal("DisputeNotOpen", again.Code);
    }

    [Fact]
    public async Task AfterLosing_TheClaimantCanTryAgain_AndANewDisputeOpens()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        var admin = await world.NewPlatformAdminAsync();
        await Resolve(world, admin, d.DisputeId, DisputeResolution.IncumbentWins);

        var challenge = await world.Challenges.IssueAsync(d.Claimant, d.ClaimantDomainId, VerificationMethod.DnsTxt, null, CancellationToken.None);
        var verify = await world.Verification.VerifyAsync(d.Claimant, challenge.ChallengeId, CancellationToken.None);

        Assert.True(verify.DisputeOpened);
        Assert.Equal(DomainStatus.Disputed, verify.DomainStatus);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(2, await db.DomainDisputes.CountAsync(x => x.ClaimantDomainId == d.ClaimantDomainId));
        Assert.Equal(1, await db.DomainDisputes.CountAsync(x => x.ClaimantDomainId == d.ClaimantDomainId && x.Status == DisputeStatus.Open));
    }

    // ------------------------------------------------------------------ automatic takeover

    [Fact]
    public async Task WhenTheHoldersProofLapses_TheClaimantTakesOverAutomatically()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        await LapseTheHolder(world, d);
        Assert.Equal(DomainStatus.Lapsed, (await world.GetDomainAsync(d.HolderDomainId)).Status);

        var resolved = await world.Disputes.AutoResolveAsync(CancellationToken.None);

        Assert.Equal(1, resolved);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(d.ClaimantDomainId)).Status);
        Assert.Equal(1, await VerifiedHolders(world, "example.com"));
        await using var db = world.Db.CreateDbContext();
        var dispute = await db.DomainDisputes.SingleAsync();
        Assert.Equal(DisputeStatus.ResolvedClaimant, dispute.Status);
        Assert.Null(dispute.ResolvedByUserId);
        var entry = await db.AuditLogs.FirstAsync(a => a.OrganizationId == d.Claimant.OrganizationId && a.Action == "dispute.resolved");
        Assert.Equal("System", entry.ActorType);
    }

    [Fact]
    public async Task NoTakeover_WhileTheHolderIsOnlyAtRisk()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        world.Dns.Script = _ => Absent;
        await world.Reverify.ReverifyAsync(d.HolderEvidenceId, Guid.NewGuid(), 0, CancellationToken.None);   // AtRisk, grace window running
        Assert.Equal(DomainStatus.AtRisk, (await world.GetDomainAsync(d.HolderDomainId)).Status);

        Assert.Equal(0, await world.Disputes.AutoResolveAsync(CancellationToken.None));
        Assert.Equal(DomainStatus.Disputed, (await world.GetDomainAsync(d.ClaimantDomainId)).Status);
    }

    [Fact]
    public async Task NoTakeover_WhenTheClaimantsOwnProofIsNotActive()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        await LapseTheHolder(world, d);
        await world.Db.ExecuteAsync($"UPDATE verification_evidence SET status = 'Lapsed' WHERE id = '{d.ClaimantEvidenceId}'");

        Assert.Equal(0, await world.Disputes.AutoResolveAsync(CancellationToken.None));
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(DisputeStatus.Open, (await db.DomainDisputes.SingleAsync()).Status);
        Assert.Equal(0, await VerifiedHolders(world, "example.com"));
    }

    [Fact]
    public async Task AutomaticTakeover_RunsOnlyOnce()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        await LapseTheHolder(world, d);

        Assert.Equal(1, await world.Disputes.AutoResolveAsync(CancellationToken.None));
        Assert.Equal(0, await world.Disputes.AutoResolveAsync(CancellationToken.None));
    }

    // ------------------------------------------------------------------ several claimants and races

    [Fact]
    public async Task WithTwoClaimants_TheLoserOfTheFirstDecisionNowFacesTheNewHolder()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var a = await world.NewOrgAsync("Holder");
        var b = await world.NewOrgAsync("ClaimantB");
        var c = await world.NewOrgAsync("ClaimantC");
        var (domainA, _) = await Scenarios.VerifiedByDnsAsync(world, a);
        var (domainB, _) = await Scenarios.VerifiedByDnsAsync(world, b);
        var (domainC, _) = await Scenarios.VerifiedByDnsAsync(world, c);
        var admin = await world.NewPlatformAdminAsync();

        await using (var db = world.Db.CreateDbContext())
            Assert.Equal(2, await db.DomainDisputes.CountAsync(x => x.Status == DisputeStatus.Open));

        Guid disputeB;
        await using (var db = world.Db.CreateDbContext())
            disputeB = await db.DomainDisputes.Where(x => x.ClaimantDomainId == domainB).Select(x => x.Id).SingleAsync();
        await Resolve(world, admin, disputeB, DisputeResolution.ClaimantWins);

        // C's open dispute now points at B, who is the holder.
        await using (var db = world.Db.CreateDbContext())
        {
            var disputeC = await db.DomainDisputes.SingleAsync(x => x.ClaimantDomainId == domainC);
            Assert.Equal(DisputeStatus.Open, disputeC.Status);
            Assert.Equal(domainB, disputeC.IncumbentDomainId);
        }
        Assert.Equal(1, await VerifiedHolders(world, "example.com"));

        // The change of opponent is visible in the chains of both organizations involved.
        await using (var db = world.Db.CreateDbContext())
        {
            foreach (var org in new[] { b.OrganizationId, c.OrganizationId })
            {
                var entry = await db.AuditLogs.SingleAsync(x => x.OrganizationId == org && x.Action == "dispute.retargeted");
                Assert.Contains(domainA.ToString("D"), entry.Data);   // previous opponent
                Assert.Contains(domainB.ToString("D"), entry.Data);   // new opponent
            }
            foreach (var org in new[] { a.OrganizationId, b.OrganizationId, c.OrganizationId })
                Assert.True((await new AuditChainVerifier().VerifyAsync(db, org, CancellationToken.None)).Intact);
        }

        Assert.Equal(0, await world.Disputes.AutoResolveAsync(CancellationToken.None));   // B holds, so C must wait

        await using (var db = world.Db.CreateDbContext())
        {
            var disputeC = await db.DomainDisputes.SingleAsync(x => x.ClaimantDomainId == domainC);
            await Resolve(world, admin, disputeC.Id, DisputeResolution.ClaimantWins);
        }
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainC)).Status);
        Assert.Equal(DomainStatus.Lapsed, (await world.GetDomainAsync(domainB)).Status);
        Assert.Equal(DomainStatus.Lapsed, (await world.GetDomainAsync(domainA)).Status);
        Assert.Equal(1, await VerifiedHolders(world, "example.com"));
    }

    [Fact]
    public async Task OpposingDecisionsAtTheSameMoment_LeaveExactlyOneConsistentOutcome()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        var admin1 = await world.NewPlatformAdminAsync();
        var admin2 = await world.NewPlatformAdminAsync();

        var outcomes = await Task.WhenAll(
            Resolve(world, admin1, d.DisputeId, DisputeResolution.IncumbentWins).ContinueWith(t => t.Exception?.GetBaseException()),
            Resolve(world, admin2, d.DisputeId, DisputeResolution.ClaimantWins).ContinueWith(t => t.Exception?.GetBaseException()));

        Assert.Equal(1, outcomes.Count(e => e is null));                     // exactly one decision applied
        Assert.All(outcomes.Where(e => e is not null), e => Assert.IsType<ServiceException>(e));
        Assert.Equal(1, await VerifiedHolders(world, "example.com"));        // never two, never zero
        await using var db = world.Db.CreateDbContext();
        Assert.NotEqual(DisputeStatus.Open, (await db.DomainDisputes.SingleAsync()).Status);
        foreach (var orgId in new[] { d.Holder.OrganizationId, d.Claimant.OrganizationId })
            Assert.True((await new AuditChainVerifier().VerifyAsync(db, orgId, CancellationToken.None)).Intact);
    }

    // ------------------------------------------------------------------ a newcomer verifies while a claim is pending

    private static async Task<(OpenDispute Dispute, Guid NewcomerDomain, Actor Newcomer)> NewcomerBecomesHolder(TestWorld world, string name = "example.com")
    {
        var d = await Scenarios.OpenDisputeAsync(world, name);
        await LapseTheHolder(world, d);                              // the original holder is gone
        var newcomer = await world.NewOrgAsync("Newcomer");
        var (domainC, _) = await Scenarios.VerifiedByDnsAsync(world, newcomer, name);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainC)).Status);   // nobody held the name, so C is first
        return (d, domainC, newcomer);
    }

    [Fact]
    public async Task AutomaticTakeover_WhenANewHolderAppearedMeanwhile_RetargetsTheClaimInsteadOfCreatingTwoHolders()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var (d, domainC, newcomer) = await NewcomerBecomesHolder(world);

        var resolved = await world.Disputes.AutoResolveAsync(CancellationToken.None);

        Assert.Equal(0, resolved);
        Assert.Equal(1, await VerifiedHolders(world, "example.com"));
        Assert.Equal(DomainStatus.Disputed, (await world.GetDomainAsync(d.ClaimantDomainId)).Status);
        await using var db = world.Db.CreateDbContext();
        var dispute = await db.DomainDisputes.SingleAsync();
        Assert.Equal(DisputeStatus.Open, dispute.Status);
        Assert.Equal(domainC, dispute.IncumbentDomainId);
        foreach (var org in new[] { d.Claimant.OrganizationId, newcomer.OrganizationId })
        {
            Assert.Equal(1, await db.AuditLogs.CountAsync(a => a.OrganizationId == org && a.Action == "dispute.retargeted"));
            Assert.True((await new AuditChainVerifier().VerifyAsync(db, org, CancellationToken.None)).Intact);
        }
        Assert.Equal(0, await world.Disputes.AutoResolveAsync(CancellationToken.None));   // nothing more to do, nothing logged twice
        Assert.Equal(1, await db.AuditLogs.CountAsync(a => a.Action == "dispute.retargeted" && a.OrganizationId == newcomer.OrganizationId));
    }

    [Fact]
    public async Task AdminClaimantWins_AlsoRemovesAHolderThatAppearedAfterTheDisputeOpened()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var (d, domainC, _) = await NewcomerBecomesHolder(world);
        var admin = await world.NewPlatformAdminAsync();

        var result = await Resolve(world, admin, d.DisputeId, DisputeResolution.ClaimantWins);

        Assert.Equal(DomainStatus.Verified, result.ClaimantStatus);
        Assert.Equal(DomainStatus.Lapsed, (await world.GetDomainAsync(domainC)).Status);
        Assert.Equal(1, await VerifiedHolders(world, "example.com"));
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(0, await db.VerificationEvidence.CountAsync(e => e.DomainId == domainC && e.Status == EvidenceStatus.Active));
    }

    [Fact]
    public async Task AutomaticTakeover_RacingANewClaim_NeverCreatesTwoHolders()
    {
        var world = await TestWorld.CreateAsync(_postgres);

        for (var round = 0; round < 3; round++)
        {
            var name = $"race{round}.example.com";
            var d = await Scenarios.OpenDisputeAsync(world, name);
            await LapseTheHolder(world, d);
            var newcomer = await world.NewOrgAsync($"Newcomer{round}");
            var domainC = await world.AddDomainAsync(newcomer, name);
            var challenge = await world.Challenges.IssueAsync(newcomer, domainC, VerificationMethod.DnsTxt, null, CancellationToken.None);

            var errors = await Task.WhenAll(
                world.Disputes.AutoResolveAsync(CancellationToken.None).ContinueWith(t => t.Exception?.GetBaseException()),
                world.Verification.VerifyAsync(newcomer, challenge.ChallengeId, CancellationToken.None).ContinueWith(t => t.Exception?.GetBaseException()));

            Assert.All(errors, e => Assert.Null(e));
            Assert.Equal(1, await VerifiedHolders(world, name));    // whichever came first holds the name; never two, never a crash
        }
    }

    [Fact]
    public async Task AutomaticTakeover_RacingAnAdminsDecision_LeavesOneConsistentOutcome()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);
        await LapseTheHolder(world, d);
        var admin = await world.NewPlatformAdminAsync();

        var errors = await Task.WhenAll(
            world.Disputes.AutoResolveAsync(CancellationToken.None).ContinueWith(t => t.Exception?.GetBaseException()),
            Resolve(world, admin, d.DisputeId, DisputeResolution.IncumbentWins).ContinueWith(t => t.Exception?.GetBaseException()));

        Assert.All(errors.Where(e => e is not null), e => Assert.IsType<ServiceException>(e));
        Assert.True(await VerifiedHolders(world, "example.com") <= 1);
        await using var db = world.Db.CreateDbContext();
        Assert.NotEqual(DisputeStatus.Open, (await db.DomainDisputes.SingleAsync()).Status);
    }

    // ------------------------------------------------------------------ who may act as a platform administrator

    [Fact]
    public async Task OnlyServerApprovedUsers_CanBecomePlatformAdmins()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var d = await Scenarios.OpenDisputeAsync(world);

        // An organization Owner is not a platform administrator, and neither is an empty or unknown identity.
        foreach (var userId in new[] { d.Holder.UserId, d.Claimant.UserId, Guid.Empty, Guid.NewGuid() })
        {
            var ex = await Assert.ThrowsAsync<ServiceException>(() => world.AdminGate.AuthorizeAsync(userId, CancellationToken.None));
            Assert.Equal("NotAllowed", ex.Code);
        }

        var approved = await world.NewPlatformAdminAsync();
        Assert.NotEqual(Guid.Empty, approved.UserId);
        Assert.Single(await world.Disputes.ListOpenAsync(approved, CancellationToken.None));
    }
}
