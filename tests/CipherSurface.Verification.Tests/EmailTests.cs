using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification.Email;
using Xunit;

namespace CipherSurface.Verification.Tests;

public class EmailTokenTests
{
    [Fact]
    public void Generate_IsUniqueAndWellFormed()
    {
        var tokens = Enumerable.Range(0, 100).Select(_ => EmailTokens.Generate()).ToList();

        Assert.Equal(100, tokens.Distinct().Count());
        Assert.All(tokens, t =>
        {
            Assert.Equal(43, t.Length);
            Assert.True(ProofFormat.IsValidToken(t));
        });
    }

    [Fact]
    public void Hash_Is64LowerHex_AndDeterministic()
    {
        var hash = EmailTokens.Hash("some-token-value-1234567890");

        Assert.Equal(64, hash.Length);
        Assert.Matches("^[0-9a-f]{64}$", hash);
        Assert.Equal(hash, EmailTokens.Hash("some-token-value-1234567890"));
        Assert.NotEqual(hash, EmailTokens.Hash("some-token-value-1234567891"));
    }

    [Fact]
    public void Matches_AcceptsOnlyTheRightToken()
    {
        var token = EmailTokens.Generate();
        var hash = EmailTokens.Hash(token);

        Assert.True(EmailTokens.Matches(token, hash));
        Assert.False(EmailTokens.Matches(token + "x", hash));
        Assert.False(EmailTokens.Matches(EmailTokens.Generate(), hash));
        Assert.False(EmailTokens.Matches(hash, hash)); // the stored hash is not a usable token
    }

    [Theory]
    [InlineData(null, "abcd")]
    [InlineData("", "abcd")]
    [InlineData("token", null)]
    [InlineData("token", "")]
    [InlineData("token", "not-hex")]
    public void Matches_BadInputs_AreFalse(string? token, string? hash) =>
        Assert.False(EmailTokens.Matches(token, hash));
}

public class AdminMailboxTests
{
    [Fact]
    public void For_ListsTheFiveRoleAddresses() =>
        Assert.Equal(
            new[] { "admin@example.com", "administrator@example.com", "webmaster@example.com", "hostmaster@example.com", "postmaster@example.com" },
            AdminMailboxes.For("example.com"));

    [Theory]
    [InlineData("admin@example.com")]
    [InlineData("Postmaster@Example.com")]
    [InlineData("webmaster@example.com")]
    public void RoleAddressOnTheRootDomain_IsAllowed(string address) =>
        Assert.True(AdminMailboxes.IsAllowed(address, "example.com"));

    [Theory]
    [InlineData("john@example.com")]                    // not a role mailbox
    [InlineData("admin@app.example.com")]               // subdomain mailbox
    [InlineData("admin@example.com.evil.net")]          // look-alike
    [InlineData("admin@evilexample.com")]
    [InlineData("admin+tag@example.com")]               // plus-addressing
    [InlineData("Admin <admin@example.com>")]           // display name
    [InlineData("admin@@example.com")]
    [InlineData("admin@example.com,attacker@evil.net")] // list injection
    [InlineData(" admin@example.com")]
    [InlineData("admin@example.com ")]
    [InlineData("")]
    [InlineData(null)]
    public void Everything_Else_IsRejected(string? address) =>
        Assert.False(AdminMailboxes.IsAllowed(address, "example.com"));
}

public class EmailConfirmationPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);

    private static (VerificationChallenge Challenge, string Token) NewChallenge() =>
        EmailChallengeFactory.Issue(Guid.NewGuid(), "example.com", Now);

    private static void AddAttempts(VerificationChallenge challenge, int count)
    {
        for (var i = 0; i < count; i++)
            challenge.Attempts.Add(new VerificationAttempt { Id = Guid.NewGuid(), ChallengeId = challenge.Id });
    }

    [Fact]
    public void RightToken_WhileActive_IsConfirmed()
    {
        var (challenge, token) = NewChallenge();
        Assert.Equal(EmailConfirmationResult.Confirmed, EmailConfirmationPolicy.Evaluate(challenge, token, Now.AddHours(1)));
    }

    [Fact]
    public void CheckingStatus_IsStillConfirmable()
    {
        var (challenge, token) = NewChallenge();
        challenge.Status = ChallengeStatus.Checking;
        Assert.Equal(EmailConfirmationResult.Confirmed, EmailConfirmationPolicy.Evaluate(challenge, token, Now.AddHours(1)));
    }

    [Theory]
    [InlineData("wrong-token-value-1234567890")]
    [InlineData("")]
    [InlineData(null)]
    public void WrongOrMissingToken_IsInvalid(string? presented)
    {
        var (challenge, _) = NewChallenge();
        Assert.Equal(EmailConfirmationResult.InvalidToken, EmailConfirmationPolicy.Evaluate(challenge, presented, Now.AddHours(1)));
    }

    [Fact]
    public void ExpiryBoundary_LastSecondWorks_ExactExpiryDoesNot()
    {
        var (challenge, token) = NewChallenge();
        Assert.Equal(EmailConfirmationResult.Confirmed,
            EmailConfirmationPolicy.Evaluate(challenge, token, challenge.ExpiresAt.AddSeconds(-1)));
        Assert.Equal(EmailConfirmationResult.Expired,
            EmailConfirmationPolicy.Evaluate(challenge, token, challenge.ExpiresAt));
        Assert.Equal(EmailConfirmationResult.Expired,
            EmailConfirmationPolicy.Evaluate(challenge, token, challenge.ExpiresAt.AddDays(1)));
    }

    [Fact]
    public void SecondUse_IsRejectedAsAlreadyUsed()
    {
        var (challenge, token) = NewChallenge();
        challenge.Status = ChallengeStatus.Passed;
        Assert.Equal(EmailConfirmationResult.AlreadyUsed, EmailConfirmationPolicy.Evaluate(challenge, token, Now.AddHours(1)));
    }

    [Theory]
    [InlineData(ChallengeStatus.Failed)]
    [InlineData(ChallengeStatus.Expired)]
    [InlineData(ChallengeStatus.Superseded)]
    public void TerminalChallenges_AreNotActive(ChallengeStatus status)
    {
        var (challenge, token) = NewChallenge();
        challenge.Status = status;
        Assert.Equal(EmailConfirmationResult.NotActive, EmailConfirmationPolicy.Evaluate(challenge, token, Now.AddHours(1)));
    }

    [Fact]
    public void AttemptLimit_BlocksEvenTheRightToken()
    {
        var (challenge, token) = NewChallenge();
        AddAttempts(challenge, 4);
        Assert.Equal(EmailConfirmationResult.Confirmed, EmailConfirmationPolicy.Evaluate(challenge, token, Now.AddHours(1)));

        AddAttempts(challenge, 1);
        Assert.Equal(EmailConfirmationResult.TooManyAttempts, EmailConfirmationPolicy.Evaluate(challenge, token, Now.AddHours(1)));
    }

    [Fact]
    public void ChallengeOfAnotherMethod_IsRejected()
    {
        var (challenge, token) = NewChallenge();
        challenge.Method = VerificationMethod.DnsTxt;
        Assert.Equal(EmailConfirmationResult.WrongMethod, EmailConfirmationPolicy.Evaluate(challenge, token, Now.AddHours(1)));
    }

    [Fact]
    public void ChallengeStoringAPlainToken_IsNeverAccepted()
    {
        var (challenge, token) = NewChallenge();
        challenge.Token = token;          // misconfigured: plain token stored
        challenge.TokenIsHashed = false;
        Assert.Equal(EmailConfirmationResult.InvalidToken, EmailConfirmationPolicy.Evaluate(challenge, token, Now.AddHours(1)));
    }

    [Fact]
    public void PresentingTheStoredHashAsTheToken_IsRejected()
    {
        var (challenge, _) = NewChallenge();
        Assert.Equal(EmailConfirmationResult.InvalidToken, EmailConfirmationPolicy.Evaluate(challenge, challenge.Token, Now.AddHours(1)));
    }

    [Fact]
    public void Preview_NeverNeedsTheToken_AndReportsTheLinkState()
    {
        var (challenge, _) = NewChallenge();
        Assert.Equal(EmailLinkState.Usable, EmailConfirmationPolicy.Preview(challenge, Now.AddHours(1)));
        Assert.Equal(EmailLinkState.Expired, EmailConfirmationPolicy.Preview(challenge, challenge.ExpiresAt));

        challenge.Status = ChallengeStatus.Passed;
        Assert.Equal(EmailLinkState.AlreadyUsed, EmailConfirmationPolicy.Preview(challenge, Now.AddHours(1)));
    }
}

public class EmailFactoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void IssuedChallenge_StoresOnlyTheHash()
    {
        var domainId = Guid.NewGuid();
        var (challenge, plain) = EmailChallengeFactory.Issue(domainId, "example.com", Now);

        Assert.NotEqual(plain, challenge.Token);
        Assert.Equal(EmailTokens.Hash(plain), challenge.Token);
        Assert.True(challenge.TokenIsHashed);
        Assert.Equal(VerificationMethod.AdminEmail, challenge.Method);
        Assert.Equal(domainId, challenge.DomainId);
        Assert.Equal("example.com", challenge.Host);
        Assert.Equal(ChallengeStatus.Issued, challenge.Status);
        Assert.Equal(5, challenge.MaxAttempts);
        Assert.Equal(Now.AddHours(48), challenge.ExpiresAt);
    }

    [Fact]
    public void CreatedEvidence_IsLowAssurance_RootOnly_AndExpires()
    {
        var (challenge, _) = EmailChallengeFactory.Issue(Guid.NewGuid(), "example.com", Now);

        var evidence = EmailEvidenceFactory.Create(challenge, Now);

        Assert.Equal(VerificationMethod.AdminEmail, evidence.Method);
        Assert.Equal(AssuranceLevel.Low, evidence.Assurance);
        Assert.Equal(ScopeCeilingType.RootOnly, evidence.ScopeCeilingType);
        Assert.Equal(Now.AddDays(30), evidence.ExpiresAt);
        Assert.Equal(EvidenceStatus.Active, evidence.Status);
        Assert.Null(evidence.FailingSince);
        Assert.Equal(challenge.Id, evidence.ChallengeId);
        Assert.Equal(challenge.DomainId, evidence.DomainId);
        Assert.Equal("example.com", evidence.Host);
    }
}

public class ConfirmationEmailTests
{
    private static readonly DateTimeOffset Expires = new(2026, 10, 22, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Build_ContainsTheLinkWithChallengeIdAndToken()
    {
        var id = Guid.NewGuid();
        var token = EmailTokens.Generate();

        var message = ConfirmationEmail.Build("admin@example.com", "example.com",
            new Uri("https://app.ciphersurface.test/verify-email"), id, token, Expires);

        Assert.Equal("admin@example.com", message.To);
        Assert.Contains("example.com", message.Subject);
        Assert.Contains($"https://app.ciphersurface.test/verify-email?c={id:D}&t={token}", message.TextBody);
        Assert.Contains("Confirm", message.TextBody);
        Assert.Contains("2026-10-22 12:00 UTC", message.TextBody);
    }

    [Fact]
    public void Build_DropsAnyQueryOrFragmentOnTheBaseUrl()
    {
        var message = ConfirmationEmail.Build("admin@example.com", "example.com",
            new Uri("https://app.ciphersurface.test/verify-email?x=1#frag"), Guid.NewGuid(), "tok123456789012345", Expires);

        Assert.DoesNotContain("x=1", message.TextBody);
        Assert.DoesNotContain("#frag", message.TextBody);
    }

    [Theory]
    [InlineData("http://app.ciphersurface.test/verify-email")]
    [InlineData("ftp://app.ciphersurface.test/verify-email")]
    public void Build_RequiresAnHttpsPage(string page) =>
        Assert.Throws<ArgumentException>(() => ConfirmationEmail.Build(
            "admin@example.com", "example.com", new Uri(page), Guid.NewGuid(), "tok123456789012345", Expires));
}
