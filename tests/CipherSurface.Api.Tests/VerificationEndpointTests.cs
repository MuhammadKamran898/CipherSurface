using System.Net;
using CipherSurface.Data.Enums;
using CipherSurface.Services.Tests;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static CipherSurface.Api.Tests.DomainKit;

namespace CipherSurface.Api.Tests;

/// <summary>Challenges, the Verify click and the admin-email flow over HTTP, against a real database and scripted verifiers.</summary>
[Collection("postgres")]
public class VerificationEndpointTests
{
    private readonly PostgresFixture _postgres;
    public VerificationEndpointTests(PostgresFixture postgres) => _postgres = postgres;

    // ------------------------------------------------------------------ issuing public-proof challenges

    [Fact]
    public async Task ADnsChallengeComesWithAnInstruction_AndANewOneSupersedesTheOld()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        var first = await BodyAsync(await IssueChallengeAsync(host, org.Owner.Access, domainId, "dnstxt"), HttpStatusCode.Created);
        var second = await BodyAsync(await IssueChallengeAsync(host, org.Owner.Access, domainId, "DnsTxt"), HttpStatusCode.Created);

        Assert.Equal("DnsTxt", first.GetProperty("method").GetString());
        Assert.Equal("example.com", first.GetProperty("host").GetString());
        var instruction = second.GetProperty("instruction").GetString()!;
        Assert.Contains("_ciphersurface-verify.example.com", instruction);
        Assert.Contains("ciphersurface-verify=", instruction);
        Assert.True(second.GetProperty("expiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddHours(47));

        await using var db = host.Database.CreateDbContext();
        var firstRow = await db.VerificationChallenges.SingleAsync(c => c.Id == first.GetProperty("challengeId").GetGuid());
        var secondRow = await db.VerificationChallenges.SingleAsync(c => c.Id == second.GetProperty("challengeId").GetGuid());
        Assert.Equal(ChallengeStatus.Superseded, firstRow.Status);
        Assert.Equal(ChallengeStatus.Issued, secondRow.Status);

        // Reloading the page shows the same single open challenge and the same instruction.
        var details = await Check.JsonAsync(await DetailsAsync(host, org.Owner.Access, domainId));
        var open = details.GetProperty("openChallenges").EnumerateArray().Single();
        Assert.Equal(second.GetProperty("challengeId").GetGuid(), open.GetProperty("id").GetGuid());
        Assert.Equal(instruction, open.GetProperty("instruction").GetString());
        Assert.Equal(0, open.GetProperty("failedAttempts").GetInt32());
        Assert.Equal(5, open.GetProperty("maxAttempts").GetInt32());
    }

    [Fact]
    public async Task HttpFileAndMetaChallengesMayUseASubdomain_ButNotAnotherDomain()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        var http = await BodyAsync(await IssueChallengeAsync(host, org.Owner.Access, domainId, "HttpFile", " WWW.Example.com. "), HttpStatusCode.Created);
        Assert.Equal("www.example.com", http.GetProperty("host").GetString());
        Assert.Contains("/.well-known/ciphersurface-verify.txt", http.GetProperty("instruction").GetString());

        var meta = await BodyAsync(await IssueChallengeAsync(host, org.Owner.Access, domainId, "HtmlMeta"), HttpStatusCode.Created);
        Assert.Equal("example.com", meta.GetProperty("host").GetString());

        await Check.ProblemAsync(await IssueChallengeAsync(host, org.Owner.Access, domainId, "HttpFile", "evil.com"), HttpStatusCode.BadRequest, "HostInvalid");
        await Check.ProblemAsync(await IssueChallengeAsync(host, org.Owner.Access, domainId, "HttpFile", "notexample.com"), HttpStatusCode.BadRequest, "HostInvalid");
        await Check.ProblemAsync(await IssueChallengeAsync(host, org.Owner.Access, domainId, "DnsTxt", "www.example.com"), HttpStatusCode.BadRequest, "HostInvalid");
    }

    [Theory]
    [InlineData("AdminEmail")]
    [InlineData("1")]
    [InlineData("DnsTxt,HttpFile")]
    [InlineData("Carrier-pigeon")]
    [InlineData("")]
    [InlineData(null)]
    public async Task OnlyTheThreePublicProofMethodsAreAccepted(string? method)
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        await Check.ProblemAsync(await IssueChallengeAsync(host, org.Owner.Access, domainId, method), HttpStatusCode.BadRequest, "MethodNotSupported");

        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.VerificationChallenges);
    }

    [Fact]
    public async Task IssuingNeedsAManager_AndAnotherOrganizationCannotReachTheDomain()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var other = await OtherOrgAsync(host);
        var analyst = await MemberAsync(host, org.OrganizationId, "analyst@acme.example", MembershipRole.Analyst);
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);

        foreach (var person in new[] { analyst, viewer })
            await Check.ProblemAsync(await IssueChallengeAsync(host, person.Access, domainId, "DnsTxt", org: org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
        await Check.ProblemAsync(await IssueChallengeAsync(host, other.Owner.Access, domainId, "DnsTxt"), HttpStatusCode.NotFound, "NotFound");
        await Check.ProblemAsync(await IssueChallengeAsync(host, org.Owner.Access, Guid.NewGuid(), "DnsTxt"), HttpStatusCode.NotFound, "NotFound");

        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.VerificationChallenges);
    }

    // ------------------------------------------------------------------ the Verify click

    [Fact]
    public async Task AValidProofVerifiesTheDomain_AndTheEvidenceShowsInTheDetails()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var challengeId = await IssueAsync(host, org.Owner.Access, domainId);
        org.Rig.Dns.Script = _ => VerificationObservation.Valid();

        var result = await Check.JsonAsync(await VerifyAsync(host, org.Owner.Access, challengeId));

        Assert.Equal("ProofValid", result.GetProperty("outcome").GetString());
        Assert.Equal("Passed", result.GetProperty("challengeStatus").GetString());
        Assert.Equal("Verified", result.GetProperty("domainStatus").GetString());
        Assert.False(result.GetProperty("disputeOpened").GetBoolean());

        var details = await Check.JsonAsync(await DetailsAsync(host, org.Owner.Access, domainId));
        Assert.Equal("Verified", details.GetProperty("status").GetString());
        Assert.Empty(details.GetProperty("openChallenges").EnumerateArray().ToList());
        var evidence = details.GetProperty("evidence").EnumerateArray().Single();
        Assert.Equal("DnsTxt", evidence.GetProperty("method").GetString());
        Assert.Equal("High", evidence.GetProperty("assurance").GetString());
        Assert.Equal("DomainAndSubdomains", evidence.GetProperty("scopeCeiling").GetString());
        Assert.Equal("Active", evidence.GetProperty("status").GetString());

        // A passed challenge cannot be used again.
        await Check.ProblemAsync(await VerifyAsync(host, org.Owner.Access, challengeId), HttpStatusCode.Conflict, "ChallengeNotActive");
    }

    [Fact]
    public async Task AMissingProofIsAnAnswerNotAnError_AndDnsRetriesDoNotUseUpAttempts()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var challengeId = await IssueAsync(host, org.Owner.Access, domainId);

        var result = await Check.JsonAsync(await VerifyAsync(host, org.Owner.Access, challengeId));

        Assert.Equal("ProofAbsent", result.GetProperty("outcome").GetString());
        Assert.Equal("TxtRecordMissing", result.GetProperty("reason").GetString());
        Assert.Equal("Issued", result.GetProperty("challengeStatus").GetString());
        Assert.Equal("Pending", result.GetProperty("domainStatus").GetString());
        Assert.Equal(1, result.GetProperty("failedAttempts").GetInt32());
        Assert.Equal(5, result.GetProperty("maxAttempts").GetInt32());
        Assert.Equal(3, org.Rig.Dns.Calls);   // one click, three looks for DNS propagation, still one attempt

        var details = await Check.JsonAsync(await DetailsAsync(host, org.Owner.Access, domainId));
        Assert.Equal(1, details.GetProperty("openChallenges").EnumerateArray().Single().GetProperty("failedAttempts").GetInt32());
    }

    [Fact]
    public async Task AnInconclusiveCheckNeverCountsAsAFailure()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var challengeId = await IssueAsync(host, org.Owner.Access, domainId);
        org.Rig.Dns.Script = _ => VerificationObservation.Inconclusive(Reasons.ResolverFailure);

        var result = await Check.JsonAsync(await VerifyAsync(host, org.Owner.Access, challengeId));

        Assert.Equal("Inconclusive", result.GetProperty("outcome").GetString());
        Assert.Equal(0, result.GetProperty("failedAttempts").GetInt32());
        Assert.Equal("Issued", result.GetProperty("challengeStatus").GetString());
    }

    [Fact]
    public async Task FiveFailedAttemptsExpireTheChallenge()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var challengeId = await IssueAsync(host, org.Owner.Access, domainId, "HttpFile");

        System.Text.Json.JsonElement last = default;
        for (var i = 1; i <= 5; i++)
        {
            last = await Check.JsonAsync(await VerifyAsync(host, org.Owner.Access, challengeId));
            Assert.Equal(i, last.GetProperty("failedAttempts").GetInt32());
        }

        Assert.Equal("Expired", last.GetProperty("challengeStatus").GetString());
        await Check.ProblemAsync(await VerifyAsync(host, org.Owner.Access, challengeId), HttpStatusCode.Conflict, "ChallengeNotActive");
        Assert.Equal(5, org.Rig.Http.Calls);   // an HTTP check is one look per click
    }

    [Fact]
    public async Task VerifyNeedsAManager_AndAChallengeOfAnotherOrganizationIsNotFound()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var challengeId = await IssueAsync(host, org.Owner.Access, domainId);
        org.Rig.Dns.Script = _ => VerificationObservation.Valid();
        var other = await OtherOrgAsync(host);
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);

        await Check.ProblemAsync(await VerifyAsync(host, viewer.Access, challengeId, org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
        var crossTenant = await Check.ProblemAsync(await VerifyAsync(host, other.Owner.Access, challengeId), HttpStatusCode.NotFound, "NotFound");
        var missing = await Check.ProblemAsync(await VerifyAsync(host, other.Owner.Access, Guid.NewGuid()), HttpStatusCode.NotFound, "NotFound");
        Assert.Equal(missing.GetProperty("detail").GetString(), crossTenant.GetProperty("detail").GetString());

        // Nothing above reached the verifier or changed the domain.
        Assert.Equal(0, org.Rig.Dns.Calls);
        await using var db = host.Database.CreateDbContext();
        Assert.Equal(DomainStatus.Pending, (await db.Domains.SingleAsync()).Status);
    }

    [Fact]
    public async Task ASecondOrganizationThatProvesTheSameNameIsDisputed_AndNeitherSeesTheOther()
    {
        var org = await StartAsync(_postgres);
        await using var host = org.Host;
        var other = await OtherOrgAsync(host, name: "Rival Corp");
        org.Rig.Dns.Script = _ => VerificationObservation.Valid();

        var incumbentDomain = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await VerifyAsync(host, org.Owner.Access, await IssueAsync(host, org.Owner.Access, incumbentDomain));

        var claimantDomain = await AddDomainAsync(host, other.Owner.Access, "example.com");
        var claim = await Check.JsonAsync(await VerifyAsync(host, other.Owner.Access, await IssueAsync(host, other.Owner.Access, claimantDomain)));

        Assert.True(claim.GetProperty("disputeOpened").GetBoolean());
        Assert.Equal("Disputed", claim.GetProperty("domainStatus").GetString());

        var incumbentResponse = await DetailsAsync(host, org.Owner.Access, incumbentDomain);
        var incumbentText = await incumbentResponse.Content.ReadAsStringAsync();
        var incumbent = await Check.JsonAsync(incumbentResponse);
        var claimantResponse = await DetailsAsync(host, other.Owner.Access, claimantDomain);
        var claimantText = await claimantResponse.Content.ReadAsStringAsync();
        var claimant = await Check.JsonAsync(claimantResponse);

        Assert.Equal("Verified", incumbent.GetProperty("status").GetString());
        Assert.Equal("Incumbent", incumbent.GetProperty("disputes").EnumerateArray().Single().GetProperty("role").GetString());
        Assert.Equal("Disputed", claimant.GetProperty("status").GetString());
        var claimantDispute = claimant.GetProperty("disputes").EnumerateArray().Single();
        Assert.Equal("Claimant", claimantDispute.GetProperty("role").GetString());
        Assert.Equal("Open", claimantDispute.GetProperty("status").GetString());

        // Each side learns that a dispute exists, never who the other side is or what the platform administrator wrote.
        Assert.DoesNotContain(other.OrganizationId.ToString(), incumbentText);
        Assert.DoesNotContain("Rival Corp", incumbentText);
        Assert.DoesNotContain(org.OrganizationId.ToString(), claimantText);
        Assert.DoesNotContain("Acme", claimantText);
        Assert.DoesNotContain(incumbentDomain.ToString(), claimantText);

        // A disputed domain cannot be verified further.
        await Check.ProblemAsync(await IssueChallengeAsync(host, other.Owner.Access, claimantDomain, "DnsTxt"), HttpStatusCode.Conflict, "DomainNotVerifiable");
    }

    [Fact]
    public async Task VerifyAndIssueAreRateLimitedPerClient()
    {
        var org = await StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:RateLimiting:VerificationRequestsPerMinute"] = "2" });
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        Assert.Equal(HttpStatusCode.Created, (await IssueChallengeAsync(host, org.Owner.Access, domainId, "DnsTxt")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await IssueChallengeAsync(host, org.Owner.Access, domainId, "DnsTxt")).StatusCode);
        var limited = await IssueChallengeAsync(host, org.Owner.Access, domainId, "DnsTxt");

        await Check.ProblemAsync(limited, HttpStatusCode.TooManyRequests, "RateLimited");
        Assert.True(limited.Headers.Contains("Retry-After"));
    }

    // ------------------------------------------------------------------ admin email

    [Fact]
    public async Task EmailVerification_ChecksTheRoleBeforeItAdmitsItIsUnavailable()
    {
        // No confirmation page and no provider: the method is unavailable. A person who may not even use it must not learn that.
        var org = await StartAsync(_postgres, withEmailSender: false);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);

        await Check.ProblemAsync(await IssueEmailAsync(host, viewer.Access, domainId, "admin@example.com", org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
        await Check.ProblemAsync(await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com"), HttpStatusCode.ServiceUnavailable, "EmailNotConfigured");

        var details = await Check.JsonAsync(await DetailsAsync(host, org.Owner.Access, domainId));
        Assert.False(details.GetProperty("emailVerificationAvailable").GetBoolean());
        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.VerificationChallenges);
    }

    [Fact]
    public async Task EmailVerification_WithAPageButNoProvider_IsStillUnavailable()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage(), withEmailSender: false);
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        await Check.ProblemAsync(await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com"), HttpStatusCode.ServiceUnavailable, "EmailNotConfigured");

        var details = await Check.JsonAsync(await DetailsAsync(host, org.Owner.Access, domainId));
        Assert.False(details.GetProperty("emailVerificationAvailable").GetBoolean());
        await using var db = host.Database.CreateDbContext();
        Assert.Empty(db.VerificationChallenges);
    }

    [Fact]
    public async Task TheEmailIsSentOnce_TheTokenIsStoredOnlyAsAHash_AndNeverComesBack()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        var response = await IssueEmailAsync(host, org.Owner.Access, domainId, "Admin@Example.com");
        var responseText = await response.Content.ReadAsStringAsync();
        var issued = await BodyAsync(response, HttpStatusCode.Created);

        var mail = org.Rig.Email.Sent.Single();
        Assert.Equal("admin@example.com", mail.To);
        Assert.Equal("admin@example.com", issued.GetProperty("recipient").GetString());
        Assert.StartsWith(DomainRig.ConfirmationPage + "#c=", mail.TextBody[(mail.TextBody.IndexOf("https://", StringComparison.Ordinal))..]);
        var (challengeId, token) = ReadLink(mail);
        Assert.Equal(issued.GetProperty("challengeId").GetGuid(), challengeId);

        await using var db = host.Database.CreateDbContext();
        var row = await db.VerificationChallenges.SingleAsync();
        Assert.True(row.TokenIsHashed);
        Assert.NotEqual(token, row.Token);
        Assert.Equal(64, row.Token.Length);
        Assert.Equal(VerificationMethod.AdminEmail, row.Method);

        // The secret is in the mailbox only: not in the response, not in the details, not in the stored form.
        var detailsResponse = await DetailsAsync(host, org.Owner.Access, domainId);
        var detailsText = await detailsResponse.Content.ReadAsStringAsync();
        var details = await Check.JsonAsync(detailsResponse);
        foreach (var text in new[] { responseText, detailsText })
        {
            Assert.DoesNotContain(token, text);
            Assert.DoesNotContain(row.Token, text);
        }
        var open = details.GetProperty("openChallenges").EnumerateArray().Single();
        Assert.Equal("AdminEmail", open.GetProperty("method").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, open.GetProperty("instruction").ValueKind);
        Assert.True(details.GetProperty("emailVerificationAvailable").GetBoolean());
    }

    [Fact]
    public async Task OnlyTheRoleMailboxesOnTheExactDomainAreAccepted_AndAFailedSendClosesTheChallenge()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        foreach (var recipient in new[] { "user@example.com", "admin@sub.example.com", "admin+x@example.com", "admin@example.com.evil.net", "", null })
            await Check.ProblemAsync(await IssueEmailAsync(host, org.Owner.Access, domainId, recipient), HttpStatusCode.BadRequest, "RecipientNotAllowed");
        Assert.Empty(org.Rig.Email.Sent);

        org.Rig.Email.FailNext = true;
        await Check.ProblemAsync(await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com"), HttpStatusCode.BadGateway, "EmailSendFailed");

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(ChallengeStatus.Failed, (await db.VerificationChallenges.SingleAsync()).Status);   // a link nobody received stays unusable
    }

    [Fact]
    public async Task IssuingAnEmailChallengeNeedsAManagerOfTheOrganizationThatOwnsTheDomain()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var other = await OtherOrgAsync(host);
        var analyst = await MemberAsync(host, org.OrganizationId, "analyst@acme.example", MembershipRole.Analyst);

        await Check.ProblemAsync(await IssueEmailAsync(host, analyst.Access, domainId, "admin@example.com", org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
        await Check.ProblemAsync(await IssueEmailAsync(host, other.Owner.Access, domainId, "admin@example.com"), HttpStatusCode.NotFound, "NotFound");

        Assert.Empty(org.Rig.Email.Sent);
    }

    [Fact]
    public async Task OpeningTheLinkChangesNothing_NoMatterHowOften()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com");
        var (challengeId, token) = ReadLink(org.Rig.Email.Sent.Single());

        for (var i = 0; i < 3; i++)   // a mail scanner opening the link, and the person
        {
            var preview = await Check.JsonAsync(await PreviewEmailAsync(host, org.Owner.Access, challengeId));
            Assert.Equal("Usable", preview.GetProperty("state").GetString());
            Assert.Equal("example.com", preview.GetProperty("domainName").GetString());
        }

        await using (var db = host.Database.CreateDbContext())
        {
            Assert.Equal(ChallengeStatus.Issued, (await db.VerificationChallenges.SingleAsync()).Status);
            Assert.Empty(db.VerificationAttempts);
            Assert.Empty(db.VerificationEvidence);
        }

        // The token was not used up by looking: confirming still works.
        Assert.Equal(HttpStatusCode.OK, (await ConfirmEmailAsync(host, org.Owner.Access, challengeId, token)).StatusCode);
    }

    [Fact]
    public async Task PreviewNeedsAManager_AndAnotherOrganizationCannotSeeTheChallenge()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com");
        var (challengeId, _) = ReadLink(org.Rig.Email.Sent.Single());
        var other = await OtherOrgAsync(host);
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);

        await Check.ProblemAsync(await PreviewEmailAsync(host, viewer.Access, challengeId, org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
        await Check.ProblemAsync(await PreviewEmailAsync(host, other.Owner.Access, challengeId), HttpStatusCode.NotFound, "NotFound");
        await Check.ProblemAsync(await PreviewEmailAsync(host, org.Owner.Access, Guid.NewGuid()), HttpStatusCode.NotFound, "NotFound");
    }

    [Fact]
    public async Task ConfirmingWithTheRightTokenCreatesLowAssuranceRootOnlyEvidence_ExactlyOnce()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com");
        var (challengeId, token) = ReadLink(org.Rig.Email.Sent.Single());

        var confirmed = await Check.JsonAsync(await ConfirmEmailAsync(host, org.Owner.Access, challengeId, token));

        Assert.Equal("Verified", confirmed.GetProperty("domainStatus").GetString());
        Assert.False(confirmed.GetProperty("disputeOpened").GetBoolean());

        await using var db = host.Database.CreateDbContext();
        var evidence = await db.VerificationEvidence.SingleAsync();
        Assert.Equal(VerificationMethod.AdminEmail, evidence.Method);
        Assert.Equal(AssuranceLevel.Low, evidence.Assurance);
        Assert.Equal(ScopeCeilingType.RootOnly, evidence.ScopeCeilingType);
        Assert.NotNull(evidence.ExpiresAt);
        Assert.True(evidence.ExpiresAt > DateTimeOffset.UtcNow.AddDays(29));

        var preview = await Check.JsonAsync(await PreviewEmailAsync(host, org.Owner.Access, challengeId));
        Assert.Equal("AlreadyUsed", preview.GetProperty("state").GetString());
        await Check.ProblemAsync(await ConfirmEmailAsync(host, org.Owner.Access, challengeId, token), HttpStatusCode.Conflict, "ChallengeNotActive");
        Assert.Equal(1, await db.VerificationEvidence.CountAsync());
    }

    [Fact]
    public async Task WrongTokensAreRecordedAsAttempts_AndFiveOfThemKillTheLink()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com");
        var (challengeId, token) = ReadLink(org.Rig.Email.Sent.Single());

        await Check.ProblemAsync(await ConfirmEmailAsync(host, org.Owner.Access, challengeId, null), HttpStatusCode.BadRequest, "InvalidToken");
        for (var i = 0; i < 4; i++)
            await Check.ProblemAsync(await ConfirmEmailAsync(host, org.Owner.Access, challengeId, "not-the-token-" + i), HttpStatusCode.BadRequest, "InvalidToken");

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(5, await db.VerificationAttempts.CountAsync(a => a.Result == CheckOutcome.ProofAbsent));

        // Even the right token is useless now: a new email is required.
        var late = await ConfirmEmailAsync(host, org.Owner.Access, challengeId, token);
        Assert.True(late.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.TooManyRequests, $"Unexpected status {(int)late.StatusCode}.");
        Assert.Empty(db.VerificationEvidence);
    }

    [Fact]
    public async Task OnlyAManagerOfTheRightOrganizationCanConfirm_AndTheTokenSurvivesTheirMistakes()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com");
        var (challengeId, token) = ReadLink(org.Rig.Email.Sent.Single());
        var other = await OtherOrgAsync(host);
        var analyst = await MemberAsync(host, org.OrganizationId, "analyst@acme.example", MembershipRole.Analyst);
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);

        // Holding the link and the token is not enough: the person must be an Owner or Admin of the organization that owns the domain.
        foreach (var person in new[] { analyst, viewer })
            await Check.ProblemAsync(await ConfirmEmailAsync(host, person.Access, challengeId, token, org.OrganizationId), HttpStatusCode.Forbidden, "NotAllowed");
        await Check.ProblemAsync(await ConfirmEmailAsync(host, other.Owner.Access, challengeId, token), HttpStatusCode.NotFound, "NotFound");

        await using (var db = host.Database.CreateDbContext())
        {
            Assert.Empty(db.VerificationAttempts);       // none of the above touched the challenge
            Assert.Empty(db.VerificationEvidence);
        }

        var admin = await MemberAsync(host, org.OrganizationId, "admin@acme.example", MembershipRole.Admin);
        Assert.Equal(HttpStatusCode.OK, (await ConfirmEmailAsync(host, admin.Access, challengeId, token, org.OrganizationId)).StatusCode);
    }

    [Fact]
    public async Task TheTokenIsNeverWrittenToTheLogs()
    {
        var org = await StartAsync(_postgres, DomainRig.WithEmailPage());
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        await IssueEmailAsync(host, org.Owner.Access, domainId, "admin@example.com");
        var (challengeId, token) = ReadLink(org.Rig.Email.Sent.Single());

        await ConfirmEmailAsync(host, org.Owner.Access, challengeId, "wrong-" + token);
        await ConfirmEmailAsync(host, org.Owner.Access, challengeId, token);

        Assert.DoesNotContain(host.Logs.Lines, line => line.Contains(token, StringComparison.Ordinal));
    }
}
