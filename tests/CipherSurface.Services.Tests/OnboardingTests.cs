using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class OnboardingTests
{
    private readonly PostgresFixture _postgres;
    public OnboardingTests(PostgresFixture postgres) => _postgres = postgres;

    [Fact]
    public async Task Owner_AddsDomain_AsPending_WithGrantAndAudit()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("BrightCart");

        var id = await world.AddDomainAsync(owner, "  BrightCart.com ");

        var domain = await world.GetDomainAsync(id);
        Assert.Equal("brightcart.com", domain.Name);
        Assert.Equal(DomainStatus.Pending, domain.Status);

        await using var db = world.Db.CreateDbContext();
        var grant = await db.AuthorizationGrants.SingleAsync(g => g.DomainId == id);
        Assert.Equal(GrantStatus.Active, grant.Status);
        Assert.Equal(owner.UserId, grant.GrantedByUserId);
        Assert.Equal(64, grant.AttestationHash.Length);

        var actions = await db.AuditLogs.Where(a => a.OrganizationId == owner.OrganizationId)
            .OrderBy(a => a.Sequence).Select(a => a.Action).ToListAsync();
        Assert.Equal(new[] { "domain.added", "grant.created" }, actions);
        Assert.True((await new AuditChainVerifier().VerifyAsync(db, owner.OrganizationId, CancellationToken.None)).Intact);
    }

    [Theory]
    [InlineData(MembershipRole.Analyst)]
    [InlineData(MembershipRole.Viewer)]
    public async Task OnlyOwnersAndAdmins_CanAddDomains(MembershipRole role)
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var actor = await world.NewOrgAsync("Org", role);

        var ex = await Assert.ThrowsAsync<ServiceException>(() => world.AddDomainAsync(actor, "example.com"));
        Assert.Equal("NotAllowed", ex.Code);
    }

    [Fact]
    public async Task Admin_CanAddDomains()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var admin = await world.NewOrgAsync("Org", MembershipRole.Admin);
        Assert.NotEqual(Guid.Empty, await world.AddDomainAsync(admin, "example.com"));
    }

    [Fact]
    public async Task NonMember_IsRejected()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var a = await world.NewOrgAsync("A");
        var b = await world.NewOrgAsync("B");
        var impostor = new Actor(b.UserId, a.OrganizationId, "203.0.113.9"); // B's user claiming to act for A

        var ex = await Assert.ThrowsAsync<ServiceException>(() => world.AddDomainAsync(impostor, "example.com"));
        Assert.Equal("NotAllowed", ex.Code);
    }

    [Fact]
    public async Task SuspendedOrganization_CannotAddDomains()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        await world.SuspendAsync(owner.OrganizationId);

        var ex = await Assert.ThrowsAsync<ServiceException>(() => world.AddDomainAsync(owner, "example.com"));
        Assert.Equal("OrganizationSuspended", ex.Code);
    }

    [Fact]
    public async Task SameDomainTwice_InOneOrganization_IsRejected()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        await world.AddDomainAsync(owner, "example.com");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => world.AddDomainAsync(owner, "EXAMPLE.com"));
        Assert.Equal("DomainExists", ex.Code);
    }

    [Fact]
    public async Task TwoOrganizations_CanBothAddTheSameName_AsPending()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var a = await world.NewOrgAsync("A");
        var b = await world.NewOrgAsync("B");

        await world.AddDomainAsync(a, "example.com");
        await world.AddDomainAsync(b, "example.com");

        await using var db = world.Db.CreateDbContext();
        Assert.Equal(2, await db.Domains.CountAsync(d => d.Name == "example.com"));
    }

    [Theory]
    [InlineData("", "text")]
    [InlineData("v1", "")]
    public async Task AttestationIsRequired(string version, string text)
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");

        var ex = await Assert.ThrowsAsync<ServiceException>(() =>
            world.Onboarding.AddDomainAsync(owner, "example.com", version, text, CancellationToken.None));
        Assert.Equal("AttestationRequired", ex.Code);
    }

    [Fact]
    public async Task PublicSuffix_IsRejected()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");

        var ex = await Assert.ThrowsAsync<ServiceException>(() => world.AddDomainAsync(owner, "github.io"));
        Assert.Equal("DomainIsPublicSuffix", ex.Code);
    }
}
