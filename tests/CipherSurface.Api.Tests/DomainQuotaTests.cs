using System.Net;
using CipherSurface.Data.Enums;
using CipherSurface.Services.Tests;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static CipherSurface.Api.Tests.DomainKit;

namespace CipherSurface.Api.Tests;

/// <summary>The per-organization domain quota over HTTP: it is configured from settings, counts every row, and cannot be raced.</summary>
[Collection("postgres")]
public class DomainQuotaTests
{
    private readonly PostgresFixture _postgres;
    public DomainQuotaTests(PostgresFixture postgres) => _postgres = postgres;

    private static Dictionary<string, string?> Quota(int limit) =>
        new() { ["CipherSurface:Governance:MaxDomainsPerOrganization"] = limit.ToString() };

    [Fact]
    public async Task AnOrganizationCannotAddMoreDomainsThanItsQuota_AndRefusalsCreateNothing()
    {
        var org = await StartAsync(_postgres, Quota(2));
        await using var host = org.Host;
        await AddDomainAsync(host, org.Owner.Access, "a.example.com");
        await AddDomainAsync(host, org.Owner.Access, "b.example.com");

        await Check.ProblemAsync(await CreateDomainAsync(host, org.Owner.Access, "c.example.com"), HttpStatusCode.Conflict, "TooManyDomains");
        // A name that is already there is reported as such, not as a quota problem.
        await Check.ProblemAsync(await CreateDomainAsync(host, org.Owner.Access, "a.example.com"), HttpStatusCode.Conflict, "DomainExists");

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(2, await db.Domains.CountAsync());
        Assert.Equal(2, await db.AuthorizationGrants.CountAsync());
        Assert.DoesNotContain(await db.AuditLogs.Select(a => a.Data).ToListAsync(), data => data.Contains("c.example.com"));
    }

    [Fact]
    public async Task TheQuotaIsPerOrganization()
    {
        var org = await StartAsync(_postgres, Quota(1));
        await using var host = org.Host;
        var other = await OtherOrgAsync(host);

        await AddDomainAsync(host, org.Owner.Access, "a.example.com");
        await Check.ProblemAsync(await CreateDomainAsync(host, org.Owner.Access, "b.example.com"), HttpStatusCode.Conflict, "TooManyDomains");

        // Another organization has its own allowance, and the same name is allowed there (ownership is decided by proof).
        Assert.Equal(HttpStatusCode.Created, (await CreateDomainAsync(host, other.Owner.Access, "a.example.com")).StatusCode);
    }

    [Fact]
    public async Task ARevokedDomainStillCountsAgainstTheQuota()
    {
        var org = await StartAsync(_postgres, Quota(2));
        await using var host = org.Host;
        var first = await AddDomainAsync(host, org.Owner.Access, "a.example.com");
        await AddDomainAsync(host, org.Owner.Access, "b.example.com");

        await using (var db = host.Database.CreateDbContext())
            await db.Domains.Where(d => d.Id == first).ExecuteUpdateAsync(s => s.SetProperty(d => d.Status, DomainStatus.Revoked));

        // A revoked domain keeps its row (it can be authorized again later), so it keeps its slot.
        await Check.ProblemAsync(await CreateDomainAsync(host, org.Owner.Access, "c.example.com"), HttpStatusCode.Conflict, "TooManyDomains");
    }

    [Fact]
    public async Task ConcurrentAddsCannotRacePastTheQuota()
    {
        var org = await StartAsync(_postgres, Quota(3));
        await using var host = org.Host;

        var responses = await Task.WhenAll(Enumerable.Range(1, 10)
            .Select(i => CreateDomainAsync(host, org.Owner.Access, $"race{i}.example.com")));

        Assert.Equal(3, responses.Count(r => r.StatusCode == HttpStatusCode.Created));
        Assert.Equal(7, responses.Count(r => r.StatusCode == HttpStatusCode.Conflict));
        foreach (var refused in responses.Where(r => r.StatusCode == HttpStatusCode.Conflict))
            await Check.ProblemAsync(refused, HttpStatusCode.Conflict, "TooManyDomains");

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(3, await db.Domains.CountAsync());
        Assert.Equal(3, await db.AuthorizationGrants.CountAsync());
    }
}
