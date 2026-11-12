using System.Net;
using CipherSurface.Data.Enums;
using CipherSurface.Services.Tests;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static CipherSurface.Api.Tests.DomainKit;

namespace CipherSurface.Api.Tests;

/// <summary>
/// The two governance limit layers: by client address (a named built-in policy, before authentication) and by signed-in
/// user (a middleware after authentication, before the handler). Each test lowers one layer and leaves the other high.
/// </summary>
[Collection("postgres")]
public class GovernanceLimitTests
{
    private readonly PostgresFixture _postgres;
    public GovernanceLimitTests(PostgresFixture postgres) => _postgres = postgres;

    private static Task<HttpResponseMessage> CreateRuleAsync(ApiHost host, string bearer, Guid domainId, string pattern, Guid? org = null, string ruleType = "Include") =>
        host.SendAsync(HttpMethod.Post, $"{V1}/domains/{domainId}/scope-rules", new { ruleType, pattern }, bearer, org);

    private static Dictionary<string, string?> Limits(string? address = null, string? actor = null)
    {
        var settings = new Dictionary<string, string?>();
        if (address is not null) settings["CipherSurface:RateLimiting:GovernanceRequestsPerMinute"] = address;
        if (actor is not null) settings["CipherSurface:RateLimiting:GovernanceActorRequestsPerMinute"] = actor;
        return settings;
    }

    private static async Task AssertLimitedAsync(HttpResponseMessage response)
    {
        await Check.ProblemAsync(response, HttpStatusCode.TooManyRequests, "RateLimited");
        var wait = response.Headers.RetryAfter?.Delta;
        Assert.NotNull(wait);
        Assert.InRange(wait!.Value.TotalSeconds, 1, 60);
    }

    // ------------------------------------------------------------------ by client address

    [Fact]
    public async Task TheAddressLayerLimitsGovernanceWrites_ButNotReadsOrOtherWrites()
    {
        var org = await StartAsync(_postgres, Limits(address: "3"));
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");

        for (var i = 1; i <= 3; i++)
            Assert.Equal(HttpStatusCode.Created, (await CreateRuleAsync(host, org.Owner.Access, domainId, $"h{i}.example.com")).StatusCode);
        await AssertLimitedAsync(await CreateRuleAsync(host, org.Owner.Access, domainId, "h4.example.com"));

        // Reads, and writes that are not governance changes, are not affected by this limit.
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync($"{V1}/domains/{domainId}/scope-rules", org.Owner.Access)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await CreateDomainAsync(host, org.Owner.Access, "second.example.com")).StatusCode);

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(3, await db.ScopeRules.CountAsync());
    }

    [Fact]
    public async Task TheAddressLayerIsSharedByEveryoneBehindTheSameAddress()
    {
        var org = await StartAsync(_postgres, Limits(address: "2"));
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var admin = await MemberAsync(host, org.OrganizationId, "admin@acme.example", MembershipRole.Admin);

        Assert.Equal(HttpStatusCode.Created, (await CreateRuleAsync(host, org.Owner.Access, domainId, "a.example.com")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await CreateRuleAsync(host, admin.Access, domainId, "b.example.com", org.OrganizationId)).StatusCode);

        // Two different people, one address: the third request is refused whoever sends it.
        await AssertLimitedAsync(await CreateRuleAsync(host, admin.Access, domainId, "c.example.com", org.OrganizationId));
    }

    // ------------------------------------------------------------------ by signed-in user

    [Fact]
    public async Task TheUserLayerLimitsEachPersonSeparately_AndCountsEveryGovernanceMethod()
    {
        var org = await StartAsync(_postgres, Limits(actor: "3"));
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        var admin = await MemberAsync(host, org.OrganizationId, "admin@acme.example", MembershipRole.Admin);

        var first = await BodyAsync(await CreateRuleAsync(host, org.Owner.Access, domainId, "a.example.com"), HttpStatusCode.Created);
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Put, $"{V1}/scope-rules/{first.GetProperty("id").GetGuid()}",
            new { ruleType = "Exclude", pattern = "a.example.com" }, org.Owner.Access)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await host.SendAsync(HttpMethod.Delete, $"{V1}/scope-rules/{first.GetProperty("id").GetGuid()}", null, org.Owner.Access)).StatusCode);

        // Create, update and remove share one counter per person. The fourth call is refused, before it is even validated.
        await AssertLimitedAsync(await CreateRuleAsync(host, org.Owner.Access, domainId, "b.example.com", ruleType: "not-a-type"));

        // Another person at the same address is not affected.
        Assert.Equal(HttpStatusCode.Created, (await CreateRuleAsync(host, admin.Access, domainId, "c.example.com", org.OrganizationId)).StatusCode);

        // Reading is never limited by this layer.
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync($"{V1}/domains/{domainId}/scope-rules", org.Owner.Access)).StatusCode);

        await using var db = host.Database.CreateDbContext();
        Assert.Equal(2, await db.ScopeRules.CountAsync());   // the refused request created nothing
    }

    [Fact]
    public async Task ARefusedRequestNeverReachesTheHandler()
    {
        var org = await StartAsync(_postgres, Limits(actor: "1"));
        await using var host = org.Host;
        var domainId = await AddDomainAsync(host, org.Owner.Access, "example.com");
        Assert.Equal(HttpStatusCode.Created, (await CreateRuleAsync(host, org.Owner.Access, domainId, "a.example.com")).StatusCode);

        // The conflicting rule is refused by the limiter before the service sees it. The viewer's first request is within
        // the limit, so it reaches the role check (403); the second is limited.
        await AssertLimitedAsync(await CreateRuleAsync(host, org.Owner.Access, domainId, "a.example.com"));
        var viewer = await MemberAsync(host, org.OrganizationId, "viewer@acme.example", MembershipRole.Viewer);
        Assert.Equal(HttpStatusCode.Forbidden, (await CreateRuleAsync(host, viewer.Access, domainId, "z.example.com", org.OrganizationId)).StatusCode);
        await AssertLimitedAsync(await CreateRuleAsync(host, viewer.Access, domainId, "z.example.com", org.OrganizationId));
    }
}
