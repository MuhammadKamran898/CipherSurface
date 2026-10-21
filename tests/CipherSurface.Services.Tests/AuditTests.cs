using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CipherSurface.Services.Tests;

[Collection("postgres")]
public class AuditTests
{
    private readonly PostgresFixture _postgres;
    public AuditTests(PostgresFixture postgres) => _postgres = postgres;

    private static async Task Append(TestWorld world, Guid orgId, string action)
    {
        await using var db = world.Db.CreateDbContext();
        await using var tx = await db.Database.BeginTransactionAsync();
        await world.Audit.AppendAsync(db, new AuditEntry(orgId, "System", null, action, "Test", null,
            new Dictionary<string, object?> { ["b"] = 2, ["a"] = "x", ["nested"] = new { z = 1, y = true } }), CancellationToken.None);
        await tx.CommitAsync();
    }

    private static async Task<AuditChainResult> Verify(TestWorld world, Guid orgId)
    {
        await using var db = world.Db.CreateDbContext();
        return await new AuditChainVerifier().VerifyAsync(db, orgId, CancellationToken.None);
    }

    [Fact]
    public async Task Chain_IsIntact_AndSequencesStartAtOne()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var actor = await world.NewOrgAsync("Org");
        for (var i = 0; i < 3; i++) await Append(world, actor.OrganizationId, $"test.{i}");

        Assert.True((await Verify(world, actor.OrganizationId)).Intact);

        await using var db = world.Db.CreateDbContext();
        var rows = await db.AuditLogs.Where(a => a.OrganizationId == actor.OrganizationId).OrderBy(a => a.Sequence).ToListAsync();
        Assert.Equal(new long[] { 1, 2, 3 }, rows.Select(r => r.Sequence));
        Assert.Null(rows[0].PrevHash);
        Assert.Equal(rows[0].Hash, rows[1].PrevHash);
    }

    [Fact]
    public async Task Chains_OfDifferentOrganizations_AreIndependent()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var a = await world.NewOrgAsync("A");
        var b = await world.NewOrgAsync("B");
        await Append(world, a.OrganizationId, "x");
        await Append(world, b.OrganizationId, "x");
        await Append(world, a.OrganizationId, "y");

        Assert.True((await Verify(world, a.OrganizationId)).Intact);
        Assert.True((await Verify(world, b.OrganizationId)).Intact);
    }

    [Fact]
    public async Task ConcurrentAppends_ToOneOrganization_KeepAnUnbrokenChain()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var actor = await world.NewOrgAsync("Org");

        await Task.WhenAll(Enumerable.Range(0, 12).Select(i => Append(world, actor.OrganizationId, $"c.{i}")));

        var result = await Verify(world, actor.OrganizationId);
        Assert.True(result.Intact, result.Problem);
        await using var db = world.Db.CreateDbContext();
        Assert.Equal(12, await db.AuditLogs.CountAsync(a => a.OrganizationId == actor.OrganizationId));
    }

    [Fact]
    public async Task DatabaseRefusesUpdatesAndDeletes()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var actor = await world.NewOrgAsync("Org");
        await Append(world, actor.OrganizationId, "x");

        await Assert.ThrowsAnyAsync<Exception>(() => world.Db.ExecuteAsync("UPDATE audit_logs SET action = 'tampered'"));
        await Assert.ThrowsAnyAsync<Exception>(() => world.Db.ExecuteAsync("DELETE FROM audit_logs"));
        await Assert.ThrowsAnyAsync<Exception>(() => world.Db.ExecuteAsync("TRUNCATE audit_logs"));
    }

    [Fact]
    public async Task EditedRecord_IsDetected_EvenIfTheTriggerIsBypassed()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var actor = await world.NewOrgAsync("Org");
        for (var i = 0; i < 3; i++) await Append(world, actor.OrganizationId, $"test.{i}");

        // An administrator disables the trigger and edits record 2.
        await world.Db.ExecuteAsync("ALTER TABLE audit_logs DISABLE TRIGGER USER; UPDATE audit_logs SET action = 'tampered' WHERE sequence = 2; ALTER TABLE audit_logs ENABLE TRIGGER USER;");

        var result = await Verify(world, actor.OrganizationId);
        Assert.False(result.Intact);
        Assert.Equal(2, result.BrokenAtSequence);
    }

    [Fact]
    public async Task DeletedRecord_IsDetected()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var actor = await world.NewOrgAsync("Org");
        for (var i = 0; i < 3; i++) await Append(world, actor.OrganizationId, $"test.{i}");

        await world.Db.ExecuteAsync("ALTER TABLE audit_logs DISABLE TRIGGER USER; DELETE FROM audit_logs WHERE sequence = 2; ALTER TABLE audit_logs ENABLE TRIGGER USER;");

        var result = await Verify(world, actor.OrganizationId);
        Assert.False(result.Intact);
        Assert.Equal(2, result.BrokenAtSequence);
    }

    [Fact]
    public async Task AppendOutsideATransaction_IsRefused()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var actor = await world.NewOrgAsync("Org");
        await using var db = world.Db.CreateDbContext();

        await Assert.ThrowsAsync<InvalidOperationException>(() => world.Audit.AppendAsync(
            db, new AuditEntry(actor.OrganizationId, "System", null, "x", "Test", null), CancellationToken.None));
    }
}
