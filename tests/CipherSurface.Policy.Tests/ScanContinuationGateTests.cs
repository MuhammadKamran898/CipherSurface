using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;
using Xunit;

namespace CipherSurface.Policy.Tests;

public sealed class ScanContinuationGateTests
{
    private readonly ScanContinuationGate _gate = new();

    [Fact]
    public void ExpiredStartByDecisionDoesNotCutOffAlreadyRunningScan_AndContinueRenewsLease()
    {
        var request = TestFixture.ContinuationRequest();
        Assert.True(request.StartDecision.ExpiresAt < TestFixture.Now);

        var result = _gate.Evaluate(request);

        Assert.Equal(ContinuationOutcome.Continue, result.Outcome);
        Assert.Equal(TestFixture.Now.AddMinutes(5), result.NewLeaseExpiresAt);
        Assert.Empty(result.BlockedTargets);
    }

    [Fact]
    public void SuspensionCancelsWholeRunningScan()
    {
        var result = _gate.Evaluate(TestFixture.ContinuationRequest(
            organization: TestFixture.Organization(OrganizationStatus.Suspended)));

        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Equal("OrganizationSuspended", result.ReasonCode);
        Assert.Null(result.NewLeaseExpiresAt);
    }

    [Fact]
    public void RevokedGrantCancelsWholeRunningScan()
    {
        var result = _gate.Evaluate(TestFixture.ContinuationRequest(grant: TestFixture.Grant(GrantStatus.Revoked)));
        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Equal("AuthorizationGrantInactive", result.ReasonCode);
    }

    [Fact]
    public void RequestedCancellationCancelsWholeRunningScan()
    {
        var (run, decision) = TestFixture.RunningScan();
        run.Status = ScanRunStatus.CancelRequested;
        run.CancelRequestedAt = TestFixture.Now.AddSeconds(-1);
        run.CancelReason = "domain revoked";

        var result = _gate.Evaluate(TestFixture.ContinuationRequest(run: run, decision: decision));
        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Equal("CancellationRequested", result.ReasonCode);
    }

    [Fact]
    public void PartialEvidenceLossRestrictsTargetsAndRenewsLeaseForRemainingAuthorizedWork()
    {
        var dns = TestFixture.DnsEvidence();
        var meta = TestFixture.MetaEvidence("www.example.com");
        var request = TestFixture.ContinuationRequest(
            targets: ["www.example.com", "api.example.com"],
            evidence: [
                TestFixture.Checked(dns, CheckOutcome.ProofAbsent),
                TestFixture.Checked(meta, CheckOutcome.ProofValid)
            ],
            rules: [TestFixture.Rule(ScopeRuleType.Include, "*.example.com")]);

        var result = _gate.Evaluate(request);

        Assert.Equal(ContinuationOutcome.Restrict, result.Outcome);
        Assert.Equal(new[] { "www.example.com" }, result.AllowedTargets);
        Assert.Equal(new[] { "api.example.com" }, result.BlockedTargets);
        Assert.Equal(TestFixture.Now.AddMinutes(5), result.NewLeaseExpiresAt);
        var atRisk = Assert.Single(result.EvidenceChanges, c => c.Status == EvidenceStatus.AtRisk);
        Assert.Equal(dns.Id, atRisk.EvidenceId);
        var refreshed = Assert.Single(result.EvidenceChanges, c => c.EvidenceId == meta.Id);
        Assert.Equal(EvidenceStatus.Active, refreshed.Status);
        Assert.Equal(TestFixture.Now, refreshed.LastValidAt);
        Assert.Null(refreshed.FailingSince);
    }

    [Fact]
    public void LossOfAllTargetCoverageCancelsScan()
    {
        var dns = TestFixture.DnsEvidence();
        var result = _gate.Evaluate(TestFixture.ContinuationRequest(
            targets: ["api.example.com"],
            evidence: [TestFixture.Checked(dns, CheckOutcome.ProofAbsent)]));

        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Equal("NoEffectiveScope", result.ReasonCode);
        Assert.Null(result.NewLeaseExpiresAt);
    }

    [Fact]
    public void DisputedDomainCancelsWholeScan()
    {
        var result = _gate.Evaluate(TestFixture.ContinuationRequest(domain: TestFixture.Domain(DomainStatus.Disputed)));
        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Equal("DomainNotScannable", result.ReasonCode);
    }

    [Fact]
    public void AtRiskEvidenceWithInconclusiveCheckIsNotUsedForContinuation()
    {
        var atRisk = TestFixture.DnsEvidence(
            status: EvidenceStatus.AtRisk,
            lastValidAt: TestFixture.Now.AddMinutes(-1),
            failingSince: TestFixture.Now.AddMinutes(-30));
        var result = _gate.Evaluate(TestFixture.ContinuationRequest(
            domain: TestFixture.Domain(DomainStatus.AtRisk),
            evidence: [TestFixture.Checked(atRisk, CheckOutcome.Inconclusive)]));

        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Equal("NoEffectiveScope", result.ReasonCode);
    }


    [Fact]
    public void ActiveEvidenceOmittedFromContinuationChecks_CancelsFailClosed()
    {
        var dns = TestFixture.DnsEvidence();
        var meta = TestFixture.MetaEvidence("www.example.com");
        var result = _gate.Evaluate(TestFixture.ContinuationRequest(
            evidence: [TestFixture.Checked(dns, CheckOutcome.ProofValid)],
            currentEvidence: [dns, meta]));

        Assert.Equal(ContinuationOutcome.Cancel, result.Outcome);
        Assert.Equal("LiveCheckMissing", result.ReasonCode);
        Assert.Null(result.NewLeaseExpiresAt);
    }

    [Fact]
    public void InconclusiveActiveEvidenceCanContinueWithinTwentyFourHours()
    {
        var active = TestFixture.DnsEvidence(lastValidAt: TestFixture.Now.AddHours(-23));
        var result = _gate.Evaluate(TestFixture.ContinuationRequest(
            evidence: [TestFixture.Checked(active, CheckOutcome.Inconclusive)]));

        Assert.Equal(ContinuationOutcome.Continue, result.Outcome);
        Assert.Equal(TestFixture.Now.AddMinutes(5), result.NewLeaseExpiresAt);
    }
}
