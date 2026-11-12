using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>The domain quota in DomainOnboardingService itself: its default, its validation, its scope and its concurrency safety.</summary>
[Collection("postgres")]
public class DomainQuotaServiceTests
{
    private readonly PostgresFixture _postgres;
    public DomainQuotaServiceTests(PostgresFixture postgres) => _postgres = postgres;

    private static readonly CancellationToken Ct = CancellationToken.None;

    private static DomainOnboardingService Onboarding(TestWorld world, int limit) =>
        new(world.Db, world.Time, world.Audit, new DomainNameValidator(new BasicPublicSuffixCheck()),
            new GovernanceOptions { MaxDomainsPerOrganization = limit });

    private static Task<Guid> AddAsync(DomainOnboardingService service, Actor actor, string name) =>
        service.AddDomainAsync(actor, name, "v1", "I am authorized to monitor this domain.", Ct);

    [Fact]
    public void TheDefaultQuotaIsOneHundred()
    {
        Assert.Equal(100, new GovernanceOptions().MaxDomainsPerOrganization);
        Assert.Equal(100, GovernanceOptions.DefaultMaxDomainsPerOrganization);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task AQuotaBelowOneIsRejectedWhenTheServiceIsBuilt(int limit)
    {
        var world = await TestWorld.CreateAsync(_postgres);

        Assert.Throws<ArgumentOutOfRangeException>(() => Onboarding(world, limit));
    }

    [Fact]
    public async Task TheLimitIsEnforced_WithAnErrorCodeAndNoSideEffects()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var service = Onboarding(world, 2);
        await AddAsync(service, owner, "a.example.com");
        await AddAsync(service, owner, "b.example.com");
        await using var db = world.Db.CreateDbContext();
        var auditBefore = await db.AuditLogs.CountAsync();

        var ex = await Assert.ThrowsAsync<ServiceException>(() => AddAsync(service, owner, "c.example.com"));

        Assert.Equal("TooManyDomains", ex.Code);
        Assert.Equal(2, await db.Domains.CountAsync());
        Assert.Equal(2, await db.AuthorizationGrants.CountAsync());
        Assert.Equal(auditBefore, await db.AuditLogs.CountAsync());   // nothing is recorded for the refusal
    }

    [Fact]
    public async Task EveryRowCounts_RevokedOnesToo_AndAnotherOrganizationIsUnaffected()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var rival = await world.NewOrgAsync("Rival");
        var service = Onboarding(world, 2);
        var first = await AddAsync(service, owner, "a.example.com");
        await AddAsync(service, owner, "b.example.com");
        await using (var db = world.Db.CreateDbContext())
            await db.Domains.Where(d => d.Id == first).ExecuteUpdateAsync(s => s.SetProperty(d => d.Status, DomainStatus.Revoked));

        var ex = await Assert.ThrowsAsync<ServiceException>(() => AddAsync(service, owner, "c.example.com"));

        Assert.Equal("TooManyDomains", ex.Code);
        await AddAsync(service, rival, "a.example.com");
        await AddAsync(service, rival, "b.example.com");
    }

    [Fact]
    public async Task ConcurrentAddsRespectTheLimitExactly()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var service = Onboarding(world, 3);

        var outcomes = await Task.WhenAll(Enumerable.Range(1, 12).Select(async i =>
        {
            try
            {
                await AddAsync(service, owner, $"race{i}.example.com");
                return "created";
            }
            catch (ServiceException ex)
            {
                return ex.Code;
            }
        }));

        Assert.Equal(3, outcomes.Count(o => o == "created"));
        Assert.Equal(9, outcomes.Count(o => o == "TooManyDomains"));
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(3, await db.Domains.CountAsync());
    }
}
