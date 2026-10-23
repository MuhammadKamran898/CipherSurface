using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using CipherSurface.Verification.Email;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class EmailVerificationTests
{
    private static readonly Uri Page = new("https://app.ciphersurface.test/verify-email");
    private readonly PostgresFixture _postgres;
    public EmailVerificationTests(PostgresFixture postgres) => _postgres = postgres;

    private static Task<IssuedEmailChallenge> Issue(TestWorld world, Actor actor, Guid domainId, string recipient) =>
        world.Email.IssueAsync(actor, domainId, recipient, Page, CancellationToken.None);

    private static Task<EmailConfirmResult> Confirm(TestWorld world, Actor actor, Guid challengeId, string? token) =>
        world.Email.ConfirmAsync(actor, challengeId, token, CancellationToken.None);

    // ------------------------------------------------------------------ issuing

    [Fact]
    public async Task Issue_SendsOneEmail_ToTheChosenRoleMailbox_AndStoresOnlyAHash()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var issued = await Issue(world, owner, domainId, "Admin@Example.com");

        var message = Assert.Single(world.Sender.Sent);
        Assert.Equal("admin@example.com", message.To);
        Assert.Equal("admin@example.com", issued.Recipient);
        Assert.StartsWith("https://app.ciphersurface.test/verify-email?c=", message.TextBody[(message.TextBody.IndexOf("https://", StringComparison.Ordinal))..]);

        var (challengeId, token) = Scenarios.ParseLink(message);
        Assert.Equal(issued.ChallengeId, challengeId);
        var stored = await world.GetChallengeAsync(challengeId);
        Assert.True(stored.TokenIsHashed);
        Assert.NotEqual(token, stored.Token);
        Assert.Equal(EmailTokens.Hash(token), stored.Token);
        Assert.Equal(TestWorld.Start.AddHours(48), stored.ExpiresAt);

        await using var db = world.Db.CreateDbContext();
        var audit = string.Join("\n", await db.AuditLogs.Select(a => a.Data).ToListAsync());
        Assert.DoesNotContain(token, audit);
    }

    [Theory]
    [InlineData("john@example.com")]
    [InlineData("admin@app.example.com")]
    [InlineData("admin@example.com.evil.net")]
    [InlineData("admin+x@example.com")]
    [InlineData("Admin <admin@example.com>")]
    [InlineData("")]
    public async Task Issue_RejectsEveryRecipientThatIsNotARoleMailboxOnTheDomain(string recipient)
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Issue(world, owner, domainId, recipient));
        Assert.Equal("RecipientNotAllowed", ex.Code);
        Assert.Empty(world.Sender.Sent);
    }

    [Fact]
    public async Task Issuing_Again_ReplacesTheOldLink()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var (firstId, firstToken) = await Scenarios.IssueEmailAsync(world, owner, domainId, "admin@example.com");
        var (secondId, secondToken) = await Scenarios.IssueEmailAsync(world, owner, domainId, "postmaster@example.com");

        Assert.Equal(ChallengeStatus.Superseded, (await world.GetChallengeAsync(firstId)).Status);
        var ex = await Assert.ThrowsAsync<ServiceException>(() => Confirm(world, owner, firstId, firstToken));
        Assert.Equal("ChallengeNotActive", ex.Code);

        var result = await Confirm(world, owner, secondId, secondToken);
        Assert.Equal(DomainStatus.Verified, result.DomainStatus);
    }

    [Fact]
    public async Task Issue_IsRateLimitedPerDomain()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        for (var i = 0; i < 3; i++) await Issue(world, owner, domainId, "admin@example.com");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Issue(world, owner, domainId, "admin@example.com"));
        Assert.Equal("RateLimited", ex.Code);
        Assert.Equal(3, world.Sender.Sent.Count);

        world.Time.Advance(TimeSpan.FromMinutes(61));
        await Issue(world, owner, domainId, "admin@example.com"); // the hour has passed
    }

    [Fact]
    public async Task SendFailure_ClosesTheChallenge()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        world.Sender.FailNext = true;

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Issue(world, owner, domainId, "admin@example.com"));

        Assert.Equal("EmailSendFailed", ex.Code);
        await using var db = world.Db.CreateDbContext();
        var challenge = await db.VerificationChallenges.SingleAsync();
        Assert.Equal(ChallengeStatus.Failed, challenge.Status);
    }

    // ------------------------------------------------------------------ preview (GET) never consumes

    [Fact]
    public async Task Preview_DoesNotConsumeTheLink_ThenConfirmWorks()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        var (challengeId, token) = await Scenarios.IssueEmailAsync(world, owner, domainId, "admin@example.com");

        // An email scanner opens the link several times.
        for (var i = 0; i < 3; i++)
        {
            var preview = await world.Email.PreviewAsync(owner, challengeId, CancellationToken.None);
            Assert.Equal(EmailLinkState.Usable, preview.State);
            Assert.Equal("example.com", preview.DomainName);
        }
        await using (var db = world.Db.CreateDbContext())
            Assert.Equal(0, await db.VerificationAttempts.CountAsync());

        var result = await Confirm(world, owner, challengeId, token);
        Assert.Equal(DomainStatus.Verified, result.DomainStatus);
    }

    [Fact]
    public async Task Preview_ReportsExpiry_WithoutChangingAnything()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        var (challengeId, _) = await Scenarios.IssueEmailAsync(world, owner, domainId, "admin@example.com");
        world.Time.Advance(TimeSpan.FromHours(49));

        var preview = await world.Email.PreviewAsync(owner, challengeId, CancellationToken.None);

        Assert.Equal(EmailLinkState.Expired, preview.State);
        Assert.Equal(ChallengeStatus.Issued, (await world.GetChallengeAsync(challengeId)).Status);
    }

    // ------------------------------------------------------------------ confirming (POST)

    [Fact]
    public async Task Confirm_WithTheRightToken_VerifiesTheDomain_WithWeakRootOnlyEvidence()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, evidenceId) = await Scenarios.VerifiedByEmailAsync(world, owner);

        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);
        var evidence = await world.GetEvidenceAsync(evidenceId);
        Assert.Equal(VerificationMethod.AdminEmail, evidence.Method);
        Assert.Equal(AssuranceLevel.Low, evidence.Assurance);
        Assert.Equal(ScopeCeilingType.RootOnly, evidence.ScopeCeilingType);
        Assert.Equal(TestWorld.Start.AddDays(30), evidence.ExpiresAt);
        Assert.Equal(EvidenceStatus.Active, evidence.Status);
        Assert.Equal("example.com", evidence.Host);

        await using var db = world.Db.CreateDbContext();
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, owner.OrganizationId, CancellationToken.None)).Intact);
    }

    [Fact]
    public async Task Confirm_SecondTime_IsRejected()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        var (challengeId, token) = await Scenarios.IssueEmailAsync(world, owner, domainId, "admin@example.com");
        await Confirm(world, owner, challengeId, token);

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Confirm(world, owner, challengeId, token));
        Assert.Equal("ChallengeNotActive", ex.Code);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(1, await db.VerificationEvidence.CountAsync());
    }

    [Fact]
    public async Task Confirm_WrongToken_IsRecordedAsAFailedAttempt_AndNothingIsVerified()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        var (challengeId, _) = await Scenarios.IssueEmailAsync(world, owner, domainId, "admin@example.com");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Confirm(world, owner, challengeId, EmailTokens.Generate()));

        Assert.Equal("InvalidToken", ex.Code);
        Assert.Equal(DomainStatus.Pending, (await world.GetDomainAsync(domainId)).Status);
        Assert.Equal(ChallengeStatus.Issued, (await world.GetChallengeAsync(challengeId)).Status);
        await using var db = world.Db.CreateDbContext();
        var attempt = await db.VerificationAttempts.SingleAsync();   // the rollback must not lose the evidence of the attempt
        Assert.Equal(CheckOutcome.ProofAbsent, attempt.Result);
        Assert.Equal(0, await db.VerificationEvidence.CountAsync());
    }

    [Fact]
    public async Task Confirm_FiveWrongTokens_ExpireTheLink_EvenForTheRightTokenAfterwards()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        var (challengeId, token) = await Scenarios.IssueEmailAsync(world, owner, domainId, "admin@example.com");

        for (var i = 0; i < 5; i++)
        {
            var wrong = await Assert.ThrowsAsync<ServiceException>(() => Confirm(world, owner, challengeId, "wrong-token-" + i));
            Assert.Equal("InvalidToken", wrong.Code);
        }

        Assert.Equal(ChallengeStatus.Expired, (await world.GetChallengeAsync(challengeId)).Status);
        var ex = await Assert.ThrowsAsync<ServiceException>(() => Confirm(world, owner, challengeId, token));
        Assert.Equal("ChallengeNotActive", ex.Code);
        Assert.Equal(DomainStatus.Pending, (await world.GetDomainAsync(domainId)).Status);
    }

    [Fact]
    public async Task Confirm_AfterExpiry_IsRejected_AndMarkedExpired()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        var (challengeId, token) = await Scenarios.IssueEmailAsync(world, owner, domainId, "admin@example.com");
        world.Time.Advance(TimeSpan.FromHours(49));

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Confirm(world, owner, challengeId, token));

        Assert.Equal("ChallengeExpired", ex.Code);
        Assert.Equal(ChallengeStatus.Expired, (await world.GetChallengeAsync(challengeId)).Status);
        Assert.Equal(DomainStatus.Pending, (await world.GetDomainAsync(domainId)).Status);
    }

    // ------------------------------------------------------------------ who may confirm

    [Fact]
    public async Task OnlyAManagerOfTheOwningOrganization_CanPreviewOrConfirm()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        var (challengeId, token) = await Scenarios.IssueEmailAsync(world, owner, domainId, "admin@example.com");

        var analyst = await world.AddMemberAsync(owner.OrganizationId, MembershipRole.Analyst);
        var stranger = await world.NewOrgAsync("Stranger");

        var denied = await Assert.ThrowsAsync<ServiceException>(() => Confirm(world, analyst, challengeId, token));
        Assert.Equal("NotAllowed", denied.Code);
        var deniedPreview = await Assert.ThrowsAsync<ServiceException>(() => world.Email.PreviewAsync(analyst, challengeId, CancellationToken.None));
        Assert.Equal("NotAllowed", deniedPreview.Code);

        var hidden = await Assert.ThrowsAsync<ServiceException>(() => Confirm(world, stranger, challengeId, token));
        Assert.Equal("NotFound", hidden.Code);

        Assert.Equal(DomainStatus.Pending, (await world.GetDomainAsync(domainId)).Status);

        var admin = await world.AddMemberAsync(owner.OrganizationId, MembershipRole.Admin);
        var ok = await Confirm(world, admin, challengeId, token);   // a colleague with an account can confirm a forwarded link
        Assert.Equal(DomainStatus.Verified, ok.DomainStatus);
    }

    // ------------------------------------------------------------------ competing claims

    [Fact]
    public async Task EmailClaim_AgainstAnExistingHolder_IsDisputed()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var a = await world.NewOrgAsync("A");
        var b = await world.NewOrgAsync("B");
        var (domainA, _) = await Scenarios.VerifiedByDnsAsync(world, a);
        var domainB = await world.AddDomainAsync(b, "example.com");
        var (challengeId, token) = await Scenarios.IssueEmailAsync(world, b, domainB, "admin@example.com");

        var result = await Confirm(world, b, challengeId, token);

        Assert.Equal(DomainStatus.Disputed, result.DomainStatus);
        Assert.True(result.DisputeOpened);
        Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainA)).Status);
    }

    [Fact]
    public async Task TwoSimultaneousConfirmations_CreateEvidenceOnce_AndTheLoserGetsAServiceError()
    {
        var world = await TestWorld.CreateAsync(_postgres);

        for (var round = 0; round < 5; round++)
        {
            var owner = await world.NewOrgAsync($"Org{round}");
            var colleague = await world.AddMemberAsync(owner.OrganizationId, MembershipRole.Admin);
            var domainId = await world.AddDomainAsync(owner, $"mail{round}.example.com");
            var (challengeId, token) = await Scenarios.IssueEmailAsync(world, owner, domainId, $"admin@mail{round}.example.com");

            var errors = await Task.WhenAll(
                Confirm(world, owner, challengeId, token).ContinueWith(t => t.Exception?.GetBaseException()),
                Confirm(world, colleague, challengeId, token).ContinueWith(t => t.Exception?.GetBaseException()));

            Assert.Equal(1, errors.Count(e => e is null));
            Assert.All(errors.Where(e => e is not null), e => Assert.IsType<ServiceException>(e));
            Assert.Equal(DomainStatus.Verified, (await world.GetDomainAsync(domainId)).Status);
            await using var db = world.Db.CreateDbContext();
            Assert.Equal(1, await db.VerificationEvidence.CountAsync(e => e.DomainId == domainId));
        }
    }
}
