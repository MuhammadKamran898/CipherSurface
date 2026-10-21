using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class ChallengeTests
{
    private readonly PostgresFixture _postgres;
    public ChallengeTests(PostgresFixture postgres) => _postgres = postgres;

    private static Task<IssuedChallenge> Issue(TestWorld world, Actor actor, Guid domainId, VerificationMethod method, string? host = null) =>
        world.Challenges.IssueAsync(actor, domainId, method, host, CancellationToken.None);

    [Fact]
    public async Task DnsChallenge_HasAValidToken_AndTheRightInstruction()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var issued = await Issue(world, owner, domainId, VerificationMethod.DnsTxt);

        Assert.True(ProofFormat.IsValidToken(issued.PlainToken));
        Assert.Equal("example.com", issued.Host);
        Assert.Contains($"_ciphersurface-verify.example.com", issued.Instruction);
        Assert.Contains($"ciphersurface-verify={issued.PlainToken}", issued.Instruction);
        Assert.Equal(TestWorld.Start.AddHours(48), issued.ExpiresAt);

        var stored = await world.GetChallengeAsync(issued.ChallengeId);
        Assert.Equal(ChallengeStatus.Issued, stored.Status);
        Assert.False(stored.TokenIsHashed);
        Assert.Equal(5, stored.MaxAttempts);
    }

    [Fact]
    public async Task IssuingAgain_SupersedesTheOldChallenge_AndOnlyOneStaysActive()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var first = await Issue(world, owner, domainId, VerificationMethod.DnsTxt);
        var second = await Issue(world, owner, domainId, VerificationMethod.DnsTxt);

        Assert.NotEqual(first.PlainToken, second.PlainToken);
        Assert.Equal(ChallengeStatus.Superseded, (await world.GetChallengeAsync(first.ChallengeId)).Status);
        Assert.Equal(ChallengeStatus.Issued, (await world.GetChallengeAsync(second.ChallengeId)).Status);
    }

    [Fact]
    public async Task DifferentMethods_CanBeActiveAtTheSameTime()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var dns = await Issue(world, owner, domainId, VerificationMethod.DnsTxt);
        var file = await Issue(world, owner, domainId, VerificationMethod.HttpFile);

        Assert.Equal(ChallengeStatus.Issued, (await world.GetChallengeAsync(dns.ChallengeId)).Status);
        Assert.Equal(ChallengeStatus.Issued, (await world.GetChallengeAsync(file.ChallengeId)).Status);
    }

    [Fact]
    public async Task HttpFile_CanUseASubdomainHost_ButNotAnotherDomain()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var ok = await Issue(world, owner, domainId, VerificationMethod.HttpFile, "www.example.com");
        Assert.Equal("www.example.com", ok.Host);
        Assert.Contains("https://www.example.com/.well-known/ciphersurface-verify.txt", ok.Instruction);

        foreach (var bad in new[] { "evil.net", "notexample.com", "example.com.evil.net", "93.184.216.34", "WWW.example.com" })
        {
            var ex = await Assert.ThrowsAsync<ServiceException>(() => Issue(world, owner, domainId, VerificationMethod.HttpFile, bad));
            Assert.Equal("HostInvalid", ex.Code);
        }
    }

    [Fact]
    public async Task Dns_MustUseTheDomainItself()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Issue(world, owner, domainId, VerificationMethod.DnsTxt, "www.example.com"));
        Assert.Equal("HostInvalid", ex.Code);
    }

    [Fact]
    public async Task EmailMethod_IsNotIssuedHere()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => Issue(world, owner, domainId, VerificationMethod.AdminEmail));
        Assert.Equal("MethodNotSupported", ex.Code);
    }

    [Fact]
    public async Task AnalystAndOtherOrganizations_CannotIssue()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var analyst = await world.NewOrgAsync("Other", MembershipRole.Analyst);
        var stranger = await world.NewOrgAsync("Stranger");

        var denied = await Assert.ThrowsAsync<ServiceException>(() => Issue(world, analyst, domainId, VerificationMethod.DnsTxt));
        Assert.Equal("NotAllowed", denied.Code);

        var notFound = await Assert.ThrowsAsync<ServiceException>(() => Issue(world, stranger, domainId, VerificationMethod.DnsTxt));
        Assert.Equal("NotFound", notFound.Code); // another organization's domain is invisible
    }

    [Fact]
    public async Task TokenNeverAppearsInTheAuditLog()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");

        var issued = await Issue(world, owner, domainId, VerificationMethod.DnsTxt);

        await using var db = world.Db.CreateDbContext();
        var allData = string.Join("\n", await db.AuditLogs.Select(a => a.Data).ToListAsync());
        Assert.DoesNotContain(issued.PlainToken, allData);
        Assert.Contains("challenge.issued", string.Join(",", await db.AuditLogs.Select(a => a.Action).ToListAsync()));
    }
}
