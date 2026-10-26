using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

public class ScanPayloadSignerTests
{
    private static readonly byte[] Key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static readonly Guid RunId = Guid.NewGuid();
    private static readonly Guid DecisionId = Guid.NewGuid();
    private static readonly DateTimeOffset Expires = new(2026, 10, 20, 12, 15, 0, TimeSpan.Zero);

    private static ScanWorkOrder Order(ScanPayloadSigner signer, string[]? targets = null, string scope = "{\"hosts\":[\"a\"]}", DateTimeOffset? expires = null)
    {
        var t = targets ?? new[] { "a.example.com", "b.example.com" };
        var e = expires ?? Expires;
        return new ScanWorkOrder(RunId, DecisionId, t, scope, e, e.AddMinutes(-10), signer.Sign(RunId, DecisionId, t, scope, e));
    }

    [Fact]
    public void ASignedOrder_Verifies_EvenIfTheTargetsAreListedInAnotherOrder_AndTheLeaseIsNotSigned()
    {
        var signer = new ScanPayloadSigner(Key);
        var order = Order(signer);

        Assert.True(signer.Verify(order));
        Assert.True(signer.Verify(order with { Targets = new[] { "b.example.com", "a.example.com" } }));
        Assert.True(signer.Verify(order with { LeaseExpiresAt = order.LeaseExpiresAt.AddMinutes(30) }));
    }

    [Fact]
    public void AnyChangeToASignedField_BreaksTheSignature()
    {
        var signer = new ScanPayloadSigner(Key);
        var order = Order(signer);

        Assert.False(signer.Verify(order with { ScanRunId = Guid.NewGuid() }));
        Assert.False(signer.Verify(order with { DecisionId = Guid.NewGuid() }));
        Assert.False(signer.Verify(order with { Targets = new[] { "a.example.com", "b.example.com", "evil.example.com" } }));
        Assert.False(signer.Verify(order with { Targets = new[] { "a.example.com" } }));
        Assert.False(signer.Verify(order with { ScopeSnapshot = "{\"hosts\":[\"a\",\"evil\"]}" }));
        Assert.False(signer.Verify(order with { ExpiresAt = order.ExpiresAt.AddHours(1) }));   // a longer start-by deadline is a forgery
    }

    [Fact]
    public void ADifferentKey_OrAMalformedSignature_NeverVerifies()
    {
        var signer = new ScanPayloadSigner(Key);
        var order = Order(signer);
        var other = new ScanPayloadSigner(Enumerable.Range(100, 32).Select(i => (byte)i).ToArray());

        Assert.False(other.Verify(order));
        Assert.False(signer.Verify(order with { Signature = "not-hex" }));
        Assert.False(signer.Verify(order with { Signature = "" }));
        Assert.False(signer.Verify(order with { Signature = order.Signature[..^2] }));
    }

    [Fact]
    public void AShortKey_IsRefused() =>
        Assert.Throws<ArgumentException>(() => new ScanPayloadSigner(new byte[31]));
}

[Collection("postgres")]
public class GrantAndOrganizationTests
{
    private readonly PostgresFixture _postgres;
    public GrantAndOrganizationTests(PostgresFixture postgres) => _postgres = postgres;

    [Fact]
    public async Task OnlyAManager_CanRevokeAGrant_ItNeedsAReason_AndItHappensOnce()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var analyst = await world.AddMemberAsync(owner.OrganizationId, MembershipRole.Analyst);

        var denied = await Assert.ThrowsAsync<ServiceException>(() => world.Grants.RevokeAsync(analyst, domainId, "x", CancellationToken.None));
        Assert.Equal("NotAllowed", denied.Code);
        var noReason = await Assert.ThrowsAsync<ServiceException>(() => world.Grants.RevokeAsync(owner, domainId, " ", CancellationToken.None));
        Assert.Equal("ReasonRequired", noReason.Code);

        await world.Grants.RevokeAsync(owner, domainId, "Contract ended.", CancellationToken.None);

        await using var db = world.Db.CreateDbContext();
        var grant = await db.AuthorizationGrants.SingleAsync(g => g.DomainId == domainId);
        Assert.Equal(GrantStatus.Revoked, grant.Status);
        Assert.Equal(owner.UserId, grant.RevokedByUserId);
        Assert.Contains("grant.revoked", await db.AuditLogs.Select(a => a.Action).ToListAsync());

        var again = await Assert.ThrowsAsync<ServiceException>(() => world.Grants.RevokeAsync(owner, domainId, "Again.", CancellationToken.None));
        Assert.Equal("NoActiveGrant", again.Code);

        var stranger = await world.NewOrgAsync("Stranger");
        var hidden = await Assert.ThrowsAsync<ServiceException>(() => world.Grants.RevokeAsync(stranger, domainId, "Hostile.", CancellationToken.None));
        Assert.Equal("NotFound", hidden.Code);
    }

    [Fact]
    public async Task SuspendedOrganization_CannotStartScans_UntilItIsReactivated()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var (domainId, _) = await Scenarios.ScannableByDnsAsync(world, owner);
        var admin = await world.NewPlatformAdminAsync();

        await world.Orgs.SuspendAsync(admin, owner.OrganizationId, "Abuse report.", CancellationToken.None);
        Assert.Equal("OrganizationSuspended", (await world.StartScanAsync(owner, domainId, "www.example.com")).FailedCheckCode);

        var twice = await Assert.ThrowsAsync<ServiceException>(() => world.Orgs.SuspendAsync(admin, owner.OrganizationId, "Again.", CancellationToken.None));
        Assert.Equal("AlreadySuspended", twice.Code);

        await world.Orgs.ReactivateAsync(admin, owner.OrganizationId, "Resolved.", CancellationToken.None);
        Assert.True((await world.StartScanAsync(owner, domainId, "www.example.com")).Allowed);

        var already = await Assert.ThrowsAsync<ServiceException>(() => world.Orgs.ReactivateAsync(admin, owner.OrganizationId, "Again.", CancellationToken.None));
        Assert.Equal("AlreadyActive", already.Code);

        await using var db = world.Db.CreateDbContext();
        var entries = await db.AuditLogs.Where(a => a.OrganizationId == owner.OrganizationId && a.Action.StartsWith("organization.")).ToListAsync();
        Assert.All(entries, e => Assert.Equal("PlatformAdmin", e.ActorType));
        Assert.Equal(2, entries.Count);
    }
}
