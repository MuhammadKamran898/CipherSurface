using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using Xunit;

namespace CipherSurface.Policy.Tests;

public sealed class ScanPolicyGateTests
{
    private readonly ScanPolicyGate _gate = new();

    [Fact]
    public void ProofAbsent_DeniesImmediatelyAndProposesAtRiskEvenIfLastValidWasFiveMinutesAgo()
    {
        var evidence = TestFixture.DnsEvidence(lastValidAt: TestFixture.Now.AddMinutes(-5));
        var request = TestFixture.StartRequest(evidence: [TestFixture.Checked(evidence, CheckOutcome.ProofAbsent)]);

        var result = _gate.Evaluate(request);

        Assert.False(result.Allowed);
        Assert.Equal("NoEffectiveScope", result.FailedCheckCode);
        var change = Assert.Single(result.EvidenceChanges);
        Assert.Equal(EvidenceStatus.AtRisk, change.Status);
        Assert.Equal(TestFixture.Now, change.FailingSince);
        Assert.Equal(TestFixture.Now.AddMinutes(-5), change.LastValidAt);
    }

    [Fact]
    public void InconclusiveAtTwentyThreeHours_AllowsIfEverythingElsePasses()
    {
        var evidence = TestFixture.DnsEvidence(lastValidAt: TestFixture.Now.AddHours(-23));
        var result = _gate.Evaluate(TestFixture.StartRequest(evidence: [TestFixture.Checked(evidence, CheckOutcome.Inconclusive)]));

        Assert.True(result.Allowed);
        Assert.Null(result.Decision.FailedCheckCode);
        Assert.Empty(result.EvidenceChanges); // Inconclusive does not change evidence state.
        Assert.Equal(TestFixture.Now.AddMinutes(15), result.Decision.ExpiresAt);
    }

    [Fact]
    public void InconclusiveAtTwentyFiveHours_Denies()
    {
        var evidence = TestFixture.DnsEvidence(lastValidAt: TestFixture.Now.AddHours(-25));
        var result = _gate.Evaluate(TestFixture.StartRequest(evidence: [TestFixture.Checked(evidence, CheckOutcome.Inconclusive)]));

        Assert.False(result.Allowed);
        Assert.Equal("NoEffectiveScope", result.FailedCheckCode);
    }

    [Fact]
    public void InconclusiveOnAtRiskEvidence_DoesNotUseTwentyFourHourFallback()
    {
        var evidence = TestFixture.DnsEvidence(
            status: EvidenceStatus.AtRisk,
            lastValidAt: TestFixture.Now.AddMinutes(-10),
            failingSince: TestFixture.Now.AddMinutes(-30));
        var result = _gate.Evaluate(TestFixture.StartRequest(
            domain: TestFixture.Domain(DomainStatus.AtRisk),
            evidence: [TestFixture.Checked(evidence, CheckOutcome.Inconclusive)]));

        Assert.False(result.Allowed);
        Assert.Equal("NoEffectiveScope", result.FailedCheckCode);
        Assert.Empty(result.EvidenceChanges);
    }

    [Fact]
    public void ValidMetaProofAllowsOnlyItsExactHostWhenDnsProofIsAbsent()
    {
        var dns = TestFixture.DnsEvidence();
        var meta = TestFixture.MetaEvidence("www.example.com");
        var evidence = new[]
        {
            TestFixture.Checked(dns, CheckOutcome.ProofAbsent),
            TestFixture.Checked(meta, CheckOutcome.ProofValid)
        };
        var rules = new[] { TestFixture.Rule(ScopeRuleType.Include, "*.example.com") };

        var allowed = _gate.Evaluate(TestFixture.StartRequest(
            targets: ["www.example.com"], evidence: evidence, rules: rules));
        var denied = _gate.Evaluate(TestFixture.StartRequest(
            targets: ["api.example.com"], evidence: evidence, rules: rules));

        Assert.True(allowed.Allowed);
        Assert.False(denied.Allowed);
        Assert.Equal("TargetOutsideEffectiveScope", denied.FailedCheckCode);
        Assert.Equal(new[] { meta.Id }, allowed.Decision.EvidenceIds);
    }

    [Fact]
    public void ValidDnsProofKeepsCoverageWhenMetaProofIsAbsent()
    {
        var dns = TestFixture.DnsEvidence();
        var meta = TestFixture.MetaEvidence("www.example.com");
        var result = _gate.Evaluate(TestFixture.StartRequest(
            targets: ["api.example.com"],
            evidence: [
                TestFixture.Checked(dns, CheckOutcome.ProofValid),
                TestFixture.Checked(meta, CheckOutcome.ProofAbsent)
            ],
            rules: [TestFixture.Rule(ScopeRuleType.Include, "*.example.com")]));

        Assert.True(result.Allowed);
        Assert.Equal(new[] { dns.Id }, result.Decision.EvidenceIds);
        var atRisk = Assert.Single(result.EvidenceChanges, c => c.Status == EvidenceStatus.AtRisk);
        Assert.Equal(meta.Id, atRisk.EvidenceId);
        var refreshed = Assert.Single(result.EvidenceChanges, c => c.EvidenceId == dns.Id);
        Assert.Equal(EvidenceStatus.Active, refreshed.Status);
        Assert.Equal(TestFixture.Now, refreshed.LastValidAt);
        Assert.Null(refreshed.FailingSince);
    }


    [Fact]
    public void DnsProofAbsentAndExactHostProofValid_AllowsOnlyTheExactHost()
    {
        var dns = TestFixture.DnsEvidence();
        var meta = TestFixture.MetaEvidence("www.example.com");
        var permitted = _gate.Evaluate(TestFixture.StartRequest(
            targets: ["www.example.com"],
            evidence: [
                TestFixture.Checked(dns, CheckOutcome.ProofAbsent),
                TestFixture.Checked(meta, CheckOutcome.ProofValid)
            ],
            rules: [TestFixture.Rule(ScopeRuleType.Include, "*.example.com")]));

        Assert.True(permitted.Allowed);
        Assert.Equal(new[] { meta.Id }, permitted.Decision.EvidenceIds);
        Assert.Contains(permitted.EvidenceChanges, x => x.EvidenceId == dns.Id && x.Status == EvidenceStatus.AtRisk);

        var outsideExactCeiling = _gate.Evaluate(TestFixture.StartRequest(
            targets: ["api.example.com"],
            evidence: [
                TestFixture.Checked(TestFixture.DnsEvidence(), CheckOutcome.ProofAbsent),
                TestFixture.Checked(TestFixture.MetaEvidence("www.example.com"), CheckOutcome.ProofValid)
            ],
            rules: [TestFixture.Rule(ScopeRuleType.Include, "*.example.com")]));

        Assert.False(outsideExactCeiling.Allowed);
        Assert.Equal("TargetOutsideEffectiveScope", outsideExactCeiling.FailedCheckCode);
    }

    [Fact]
    public void SuspendedOrganizationDeniesBeforeEvidenceEvaluation()
    {
        var result = _gate.Evaluate(TestFixture.StartRequest(
            organization: TestFixture.Organization(OrganizationStatus.Suspended),
            evidence: []));

        Assert.False(result.Allowed);
        Assert.Equal("OrganizationSuspended", result.FailedCheckCode);
    }

    [Fact]
    public void PreflightDeniesSuspendedOrganizationBeforeLiveChecks()
    {
        var request = TestFixture.StartRequest(
            organization: TestFixture.Organization(OrganizationStatus.Suspended),
            evidence: []);

        var preflight = _gate.CheckPreflight(request);
        var final = _gate.Evaluate(request);

        Assert.False(preflight.MayPerformLiveChecks);
        Assert.Equal("OrganizationSuspended", preflight.FailedCheckCode);
        Assert.Equal("OrganizationSuspended", final.FailedCheckCode);
    }

    [Fact]
    public void KnownProofAbsentTransitionIsReturnedEvenIfAnotherActiveEvidenceCheckIsMissing()
    {
        var dns = TestFixture.DnsEvidence();
        var meta = TestFixture.MetaEvidence("www.example.com");
        var result = _gate.Evaluate(TestFixture.StartRequest(evidence: [
            TestFixture.Checked(dns, CheckOutcome.ProofAbsent),
            TestFixture.Unchecked(meta)
        ]));

        Assert.False(result.Allowed);
        Assert.Equal("LiveCheckMissing", result.FailedCheckCode);
        var update = Assert.Single(result.EvidenceChanges);
        Assert.Equal(dns.Id, update.EvidenceId);
        Assert.Equal(EvidenceStatus.AtRisk, update.Status);
    }

    [Fact]
    public void EvidenceChangedWhileLiveCheckWasRunning_FailsClosed()
    {
        var evidence = TestFixture.DnsEvidence();
        var check = TestFixture.Checked(evidence, CheckOutcome.ProofValid);
        evidence.Version += 1; // Represents a concurrent write after the check began.
        var result = _gate.Evaluate(TestFixture.StartRequest(evidence: [check]));

        Assert.False(result.Allowed);
        Assert.Equal("EvidenceChangedDuringLiveCheck", result.FailedCheckCode);
    }

    [Fact]
    public void MembershipFromAnotherOrganizationDenies()
    {
        var membership = TestFixture.Membership();
        membership.OrganizationId = Guid.NewGuid();
        var result = _gate.Evaluate(TestFixture.StartRequest(membership: membership));

        Assert.False(result.Allowed);
        Assert.Equal("MembershipMismatch", result.FailedCheckCode);
    }

    [Fact]
    public void RevokedGrantDenies()
    {
        var result = _gate.Evaluate(TestFixture.StartRequest(grant: TestFixture.Grant(GrantStatus.Revoked)));
        Assert.False(result.Allowed);
        Assert.Equal("AuthorizationGrantInactive", result.FailedCheckCode);
    }

    [Fact]
    public void DisputedDomainDeniesEvenWithValidEvidence()
    {
        var result = _gate.Evaluate(TestFixture.StartRequest(
            domain: TestFixture.Domain(DomainStatus.Disputed),
            evidence: [TestFixture.Checked(TestFixture.DnsEvidence(), CheckOutcome.ProofValid)]));

        Assert.False(result.Allowed);
        Assert.Equal("DomainNotScannable", result.FailedCheckCode);
    }

    [Fact]
    public void ExcludedHostDeniesEvenInsideDnsCeiling()
    {
        var result = _gate.Evaluate(TestFixture.StartRequest(
            targets: ["admin.example.com"],
            rules: [TestFixture.Rule(ScopeRuleType.Include, "*.example.com"), TestFixture.Rule(ScopeRuleType.Exclude, "admin.example.com")]));

        Assert.False(result.Allowed);
        Assert.Equal("TargetOutsideEffectiveScope", result.FailedCheckCode);
    }

    [Fact]
    public void EmailOnlyEvidenceDoesNotAuthorizeSubdomain()
    {
        var email = TestFixture.EmailEvidence();
        var result = _gate.Evaluate(TestFixture.StartRequest(
            targets: ["app.example.com"],
            evidence: [TestFixture.Checked(email, CheckOutcome.ProofValid)],
            rules: [TestFixture.Rule(ScopeRuleType.Include, "example.com"), TestFixture.Rule(ScopeRuleType.Include, "*.example.com")]));

        Assert.False(result.Allowed);
        Assert.Equal("TargetOutsideEffectiveScope", result.FailedCheckCode);
    }

    [Fact]
    public void LapsedEvidenceNeverRevivesFromProofValid()
    {
        var lapsed = TestFixture.DnsEvidence(EvidenceStatus.Lapsed, TestFixture.Now.AddMinutes(-1));
        var result = _gate.Evaluate(TestFixture.StartRequest(
            domain: TestFixture.Domain(DomainStatus.AtRisk),
            evidence: [TestFixture.Checked(lapsed, CheckOutcome.ProofValid)]));

        Assert.False(result.Allowed);
        Assert.Equal("NoEffectiveScope", result.FailedCheckCode);
        Assert.Empty(result.EvidenceChanges);
    }

    [Fact]
    public void ExpiredEmailEvidenceIsNotUsableEvenBeforeLifecycleJobRuns()
    {
        var email = TestFixture.EmailEvidence();
        email.ExpiresAt = TestFixture.Now.AddSeconds(-1);
        var result = _gate.Evaluate(TestFixture.StartRequest(
            targets: ["example.com"],
            evidence: [TestFixture.Checked(email, CheckOutcome.ProofValid)],
            rules: [TestFixture.Rule(ScopeRuleType.Include, "example.com")]));

        Assert.False(result.Allowed);
        Assert.Equal("NoEffectiveScope", result.FailedCheckCode);
        Assert.Single(result.EvidenceChanges);
        Assert.Equal(EvidenceStatus.Expired, result.EvidenceChanges[0].Status);
    }

    [Fact]
    public void MissingLiveCheckForActiveEvidence_FailsClosed()
    {
        var active = TestFixture.DnsEvidence();
        var result = _gate.Evaluate(TestFixture.StartRequest(evidence: [TestFixture.Unchecked(active)]));

        Assert.False(result.Allowed);
        Assert.Equal("LiveCheckMissing", result.FailedCheckCode);
    }


    [Fact]
    public void ActiveEvidenceOmittedFromLiveResultSet_FailsClosed()
    {
        var dns = TestFixture.DnsEvidence();
        var meta = TestFixture.MetaEvidence("www.example.com");
        var result = _gate.Evaluate(TestFixture.StartRequest(
            evidence: [TestFixture.Checked(dns, CheckOutcome.ProofValid)],
            currentEvidence: [dns, meta]));

        Assert.False(result.Allowed);
        Assert.Equal("LiveCheckMissing", result.FailedCheckCode);
        // A known valid result is still persisted if another active row has no result.
        Assert.Contains(result.EvidenceChanges, x => x.EvidenceId == dns.Id && x.Status == EvidenceStatus.Active);
    }

    [Fact]
    public void ViewerRoleCannotStartScan()
    {
        var result = _gate.Evaluate(TestFixture.StartRequest(membership: TestFixture.Membership(MembershipRole.Viewer)));
        Assert.False(result.Allowed);
        Assert.Equal("RoleNotPermitted", result.FailedCheckCode);
    }

    [Fact]
    public void ScheduledDecisionStoresNullUserIdButStillChecksScheduleOwnersMembership()
    {
        var result = _gate.Evaluate(TestFixture.StartRequest(trigger: DecisionTrigger.Scheduled));

        Assert.True(result.Allowed);
        Assert.Null(result.Decision.UserId);
    }
}
