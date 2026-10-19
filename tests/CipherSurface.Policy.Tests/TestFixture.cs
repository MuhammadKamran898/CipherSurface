using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Policy;

namespace CipherSurface.Policy.Tests;

internal static class TestFixture
{
    public static readonly DateTimeOffset Now = new(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);
    public static readonly Guid OrganizationId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    public static readonly Guid UserId = Guid.Parse("20000000-0000-0000-0000-000000000001");
    public static readonly Guid DomainId = Guid.Parse("30000000-0000-0000-0000-000000000001");
    public static readonly Guid GrantId = Guid.Parse("40000000-0000-0000-0000-000000000001");

    public static Organization Organization(OrganizationStatus status = OrganizationStatus.Active) => new()
    {
        Id = OrganizationId,
        Name = "Example Org",
        Status = status,
        CreatedAt = Now.AddDays(-100)
    };

    public static User User(UserStatus status = UserStatus.Active) => new()
    {
        Id = UserId,
        Email = "owner@example.com",
        PasswordHash = "not-a-real-hash",
        Status = status,
        CreatedAt = Now.AddDays(-100)
    };

    public static Membership Membership(MembershipRole role = MembershipRole.Owner) => new()
    {
        Id = Guid.NewGuid(),
        OrganizationId = OrganizationId,
        UserId = UserId,
        Role = role,
        CreatedAt = Now.AddDays(-90)
    };

    public static Domain Domain(DomainStatus status = DomainStatus.Verified) => new()
    {
        Id = DomainId,
        OrganizationId = OrganizationId,
        Name = "example.com",
        Status = status,
        CreatedByUserId = UserId,
        CreatedAt = Now.AddDays(-20)
    };

    public static AuthorizationGrant Grant(GrantStatus status = GrantStatus.Active) => new()
    {
        Id = GrantId,
        OrganizationId = OrganizationId,
        DomainId = DomainId,
        GrantedByUserId = UserId,
        GrantType = GrantType.SelfAttestation,
        AttestationTextVersion = "v1",
        AttestationHash = "attestation-hash",
        AcceptedAt = Now.AddDays(-20),
        Ip = "192.0.2.10",
        Status = status
    };

    public static VerificationEvidence DnsEvidence(
        EvidenceStatus status = EvidenceStatus.Active,
        DateTimeOffset? lastValidAt = null,
        DateTimeOffset? failingSince = null) => new()
    {
        Id = Guid.NewGuid(),
        DomainId = DomainId,
        ChallengeId = Guid.NewGuid(),
        Method = VerificationMethod.DnsTxt,
        Assurance = AssuranceLevel.High,
        ScopeCeilingType = ScopeCeilingType.DomainAndSubdomains,
        Host = "example.com",
        EstablishedAt = Now.AddDays(-10),
        LastCheckedAt = lastValidAt ?? Now.AddMinutes(-5),
        LastValidAt = lastValidAt ?? Now.AddMinutes(-5),
        FailingSince = failingSince,
        Status = status
    };

    public static VerificationEvidence MetaEvidence(string host, EvidenceStatus status = EvidenceStatus.Active) => new()
    {
        Id = Guid.NewGuid(),
        DomainId = DomainId,
        ChallengeId = Guid.NewGuid(),
        Method = VerificationMethod.HtmlMeta,
        Assurance = AssuranceLevel.Medium,
        ScopeCeilingType = ScopeCeilingType.ExactHost,
        Host = host,
        EstablishedAt = Now.AddDays(-3),
        LastCheckedAt = Now.AddMinutes(-5),
        LastValidAt = Now.AddMinutes(-5),
        Status = status
    };

    public static VerificationEvidence EmailEvidence() => new()
    {
        Id = Guid.NewGuid(),
        DomainId = DomainId,
        ChallengeId = Guid.NewGuid(),
        Method = VerificationMethod.AdminEmail,
        Assurance = AssuranceLevel.Low,
        ScopeCeilingType = ScopeCeilingType.RootOnly,
        Host = "example.com",
        EstablishedAt = Now.AddDays(-2),
        ExpiresAt = Now.AddDays(28),
        LastCheckedAt = Now.AddMinutes(-2),
        LastValidAt = Now.AddMinutes(-2),
        Status = EvidenceStatus.Active
    };

    public static ScopeRule Rule(ScopeRuleType type, string pattern, DateTimeOffset? removedAt = null) => new()
    {
        Id = Guid.NewGuid(),
        DomainId = DomainId,
        RuleType = type,
        Pattern = pattern,
        CreatedByUserId = UserId,
        CreatedAt = Now.AddDays(-2),
        RemovedAt = removedAt
    };

    public static LiveEvidenceResult Checked(VerificationEvidence evidence, CheckOutcome outcome) =>
        new(evidence, outcome, evidence.Version, Now);
    public static LiveEvidenceResult Unchecked(VerificationEvidence evidence) =>
        new(evidence, null, evidence.Version, Now);

    public static ScanGateRequest StartRequest(
        IReadOnlyCollection<string>? targets = null,
        IReadOnlyCollection<LiveEvidenceResult>? evidence = null,
        IReadOnlyCollection<VerificationEvidence>? currentEvidence = null,
        IReadOnlyCollection<ScopeRule>? rules = null,
        Organization? organization = null,
        Domain? domain = null,
        AuthorizationGrant? grant = null,
        Membership? membership = null,
        User? user = null,
        DecisionTrigger trigger = DecisionTrigger.Manual)
    {
        var liveResults = evidence ?? [Checked(DnsEvidence(), CheckOutcome.ProofValid)];
        var currentRows = currentEvidence ?? liveResults.Select(x => x.Evidence).ToArray();
        return new ScanGateRequest(
            Guid.NewGuid(),
            OrganizationId,
            DomainId,
            true,
            user ?? User(),
            membership ?? Membership(),
            organization ?? Organization(),
            grant ?? Grant(),
            domain ?? Domain(),
            trigger,
            targets ?? ["app.example.com"],
            currentRows,
            liveResults,
            rules ?? [Rule(ScopeRuleType.Include, "*.example.com")],
            Now);
    }

    public static (ScanRun Run, PolicyDecision Decision) RunningScan()
    {
        var decision = new PolicyDecision
        {
            Id = Guid.NewGuid(),
            OrganizationId = OrganizationId,
            DomainId = DomainId,
            UserId = null,
            Trigger = DecisionTrigger.Scheduled,
            Outcome = DecisionOutcome.Allow,
            EffectiveScopeSnapshot = "{}",
            EvidenceIds = [],
            ScopeRulesHash = "hash",
            DecidedAt = Now.AddMinutes(-20),
            ExpiresAt = Now.AddMinutes(-5) // expired start-by deadline; running work may continue.
        };
        var run = new ScanRun
        {
            Id = Guid.NewGuid(),
            PolicyDecisionId = decision.Id,
            Status = ScanRunStatus.Running,
            CreatedAt = Now.AddMinutes(-20),
            StartedAt = Now.AddMinutes(-19),
            LeaseExpiresAt = Now.AddMinutes(-1)
        };
        return (run, decision);
    }

    public static ScanContinuationRequest ContinuationRequest(
        IReadOnlyCollection<string>? targets = null,
        IReadOnlyCollection<LiveEvidenceResult>? evidence = null,
        IReadOnlyCollection<VerificationEvidence>? currentEvidence = null,
        IReadOnlyCollection<ScopeRule>? rules = null,
        Organization? organization = null,
        Domain? domain = null,
        AuthorizationGrant? grant = null,
        ScanRun? run = null,
        PolicyDecision? decision = null)
    {
        var (defaultRun, defaultDecision) = RunningScan();
        var liveResults = evidence ?? [Checked(DnsEvidence(), CheckOutcome.ProofValid)];
        var currentRows = currentEvidence ?? liveResults.Select(x => x.Evidence).ToArray();
        return new ScanContinuationRequest(
            run ?? defaultRun,
            decision ?? defaultDecision,
            organization ?? Organization(),
            domain ?? Domain(),
            grant ?? Grant(),
            currentRows,
            liveResults,
            rules ?? [Rule(ScopeRuleType.Include, "*.example.com")],
            targets ?? ["app.example.com", "api.example.com"],
            Now);
    }

}
