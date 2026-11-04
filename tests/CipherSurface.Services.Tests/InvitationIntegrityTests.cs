using CipherSurface.Auth;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>
/// The database itself refuses what the service must never do: a second pending invitation, an invitation for an Owner,
/// a changed email or token, a reopened or deleted invitation. These hold even for code that bypasses InvitationService.
/// </summary>
[Collection("postgres")]
public class InvitationIntegrityTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);

    private readonly PostgresFixture _postgres;
    public InvitationIntegrityTests(PostgresFixture postgres) => _postgres = postgres;

    private async Task<(TestDatabase Db, Guid OrganizationId, Guid UserId)> SeedAsync()
    {
        var db = await _postgres.CreateDatabaseAsync();
        var time = new FakeTime(Now);
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddSingleton<TimeProvider>(time);
        services.AddLogging();
        services.AddCipherSurfaceData(db.ConnectionString);
        services.AddCipherSurfaceAuth(new JwtOptions(), TokenKeys.Generate("k").Keys);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var owner = await scope.ServiceProvider.GetRequiredService<AccountService>().RegisterAsync("owner@example.com", "correct horse battery staple", "Acme", Ct);
        return (db, owner.OrganizationId, owner.UserId);
    }

    private static Invitation Row(Guid org, Guid user, Action<Invitation>? change = null)
    {
        var invitation = new Invitation
        {
            Id = Guid.NewGuid(), OrganizationId = org, Email = "invitee@example.com", Role = MembershipRole.Analyst,
            TokenHash = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N"), Status = InvitationStatus.Pending,
            CreatedByUserId = user, CreatedAt = Now, ExpiresAt = Now.AddDays(7)
        };
        change?.Invoke(invitation);
        return invitation;
    }

    private static async Task<string> SqlStateOfAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pg)
        {
            return pg.SqlState;
        }
        catch (PostgresException pg)
        {
            return pg.SqlState;
        }

        return "none";
    }

    private static async Task<string> InsertAsync(TestDatabase database, Invitation invitation)
    {
        await using var db = database.CreateDbContext();
        db.Invitations.Add(invitation);
        return await SqlStateOfAsync(() => db.SaveChangesAsync(Ct));
    }

    [Fact]
    public async Task AValidRowIsAccepted()
    {
        var (db, org, user) = await SeedAsync();

        Assert.Equal("none", await InsertAsync(db, Row(org, user)));
    }

    [Fact]
    public async Task OnlyOnePendingInvitationPerOrganizationAndEmail()
    {
        var (db, org, user) = await SeedAsync();
        await InsertAsync(db, Row(org, user));

        Assert.Equal("23505", await InsertAsync(db, Row(org, user)));                                          // same pair, pending
        Assert.Equal("none", await InsertAsync(db, Row(org, user, i => i.Email = "someone-else@example.com")));   // another email
        Assert.Equal("none", await InsertAsync(db, Row(org, user, i =>                                          // a resolved one does not block
        {
            i.Status = InvitationStatus.Revoked;
            i.ResolvedAt = Now;
            i.ResolvedByUserId = user;
        })));
    }

    [Fact]
    public async Task TwoInvitationsCannotShareAToken()
    {
        var (db, org, user) = await SeedAsync();
        var hash = new string('a', 64);
        await InsertAsync(db, Row(org, user, i => i.TokenHash = hash));

        Assert.Equal("23505", await InsertAsync(db, Row(org, user, i => { i.TokenHash = hash; i.Email = "other@example.com"; })));
    }

    [Theory]
    [InlineData(MembershipRole.Admin)]
    [InlineData(MembershipRole.Analyst)]
    [InlineData(MembershipRole.Viewer)]
    public async Task EachInvitableRoleIsAccepted(MembershipRole role)
    {
        var (db, org, user) = await SeedAsync();

        Assert.Equal("none", await InsertAsync(db, Row(org, user, i => i.Role = role)));
    }

    [Fact]
    public async Task AnInvitationForAnOwnerIsRefused()
    {
        var (db, org, user) = await SeedAsync();

        Assert.Equal("23514", await InsertAsync(db, Row(org, user, i => i.Role = MembershipRole.Owner)));
    }

    // EF reads role text case-insensitively, so 'owner' would come back as Owner: the database must refuse every spelling,
    // and anything else that is not one of the three invitable roles.
    [Theory]
    [InlineData("owner")]
    [InlineData("OWNER")]
    [InlineData("Owner ")]
    [InlineData("admin")]
    [InlineData("Root")]
    [InlineData("")]
    public async Task OnlyTheExactInvitableRoleNamesAreAccepted(string role)
    {
        var (database, org, user) = await SeedAsync();
        await using var db = database.CreateDbContext();
        var (id, hash) = (Guid.NewGuid(), new string('a', 64));

        var state = await SqlStateOfAsync(() => db.Database.ExecuteSqlAsync(
            $"INSERT INTO invitations (id, organization_id, email, role, token_hash, status, created_by_user_id, created_at, expires_at) VALUES ({id}, {org}, 'x@example.com', {role}, {hash}, 'Pending', {user}, {Now}, {Now.AddDays(7)})", Ct));

        Assert.Equal("23514", state);
        Assert.Equal(0, await db.Invitations.CountAsync(Ct));
    }

    [Theory]
    [InlineData("email")]
    [InlineData("hash")]
    [InlineData("expiry")]
    [InlineData("pending-but-resolved")]
    [InlineData("accepted-without-resolver")]
    public async Task MalformedRowsAreRefused(string problem)
    {
        var (db, org, user) = await SeedAsync();
        var row = Row(org, user, i =>
        {
            switch (problem)
            {
                case "email": i.Email = "Invitee@Example.com"; break;
                case "hash": i.TokenHash = "short"; break;
                case "expiry": i.ExpiresAt = i.CreatedAt; break;
                case "pending-but-resolved": i.ResolvedAt = Now; i.ResolvedByUserId = user; break;
                case "accepted-without-resolver": i.Status = InvitationStatus.Accepted; i.ResolvedAt = Now; break;
            }
        });

        Assert.Equal("23514", await InsertAsync(db, row));
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "none")]   // what OpaqueTokens.Hash produces
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", "23514")]   // the code never writes upper case, and lookups are exact
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "23514")]   // right length, not hexadecimal
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", "23514")]    // 63 characters
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", "22001")]   // 65 characters: the varchar(64) column itself refuses it first
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\n", "23514")]   // 64 characters, last one a newline
    public async Task TheTokenHashMustBeExactlyLowerCaseSha256Hex(string hash, string expected)
    {
        var (db, org, user) = await SeedAsync();

        Assert.Equal(expected, await InsertAsync(db, Row(org, user, i => i.TokenHash = hash)));
    }

    [Fact]
    public async Task AnInvitationNeedsARealOrganizationAndCreator()
    {
        var (db, org, user) = await SeedAsync();

        Assert.Equal("23503", await InsertAsync(db, Row(Guid.NewGuid(), user)));
        Assert.Equal("23503", await InsertAsync(db, Row(org, Guid.NewGuid())));
    }

    [Theory]
    [InlineData("email")]
    [InlineData("role")]
    [InlineData("token")]
    [InlineData("expiry")]
    [InlineData("created")]
    public async Task TheCoreOfAPendingInvitationCannotBeChanged(string field)
    {
        var (database, org, user) = await SeedAsync();
        var row = Row(org, user);
        await InsertAsync(database, row);
        await using var db = database.CreateDbContext();
        var id = row.Id;
        var otherHash = new string('f', 64);

        // One fixed statement per field; only values go in as parameters.
        var state = await SqlStateOfAsync(() => field switch
        {
            "email" => db.Database.ExecuteSqlAsync($"UPDATE invitations SET email = 'changed@example.com' WHERE id = {id}", Ct),
            "role" => db.Database.ExecuteSqlAsync($"UPDATE invitations SET role = 'Admin' WHERE id = {id}", Ct),
            "token" => db.Database.ExecuteSqlAsync($"UPDATE invitations SET token_hash = {otherHash} WHERE id = {id}", Ct),
            "expiry" => db.Database.ExecuteSqlAsync($"UPDATE invitations SET expires_at = expires_at + interval '1 day' WHERE id = {id}", Ct),
            "created" => db.Database.ExecuteSqlAsync($"UPDATE invitations SET created_at = created_at - interval '1 day' WHERE id = {id}", Ct),
            _ => throw new ArgumentOutOfRangeException(nameof(field), field, "Unknown invitation field.")
        });

        Assert.Equal("23001", state);
    }

    [Fact]
    public async Task APendingInvitationCanBeResolved_ButAResolvedOneIsFrozen()
    {
        var (database, org, user) = await SeedAsync();
        var row = Row(org, user);
        await InsertAsync(database, row);
        await using var db = database.CreateDbContext();

        await db.Database.ExecuteSqlRawAsync("UPDATE invitations SET status = 'Accepted', resolved_at = now(), resolved_by_user_id = {0} WHERE id = {1}", [user, row.Id], Ct);

        Assert.Equal("23001", await SqlStateOfAsync(() => db.Database.ExecuteSqlRawAsync("UPDATE invitations SET status = 'Pending', resolved_at = NULL, resolved_by_user_id = NULL WHERE id = {0}", [row.Id], Ct)));
        Assert.Equal("23001", await SqlStateOfAsync(() => db.Database.ExecuteSqlRawAsync("UPDATE invitations SET status = 'Revoked' WHERE id = {0}", [row.Id], Ct)));
    }

    [Fact]
    public async Task AnInvitationCanNeverBeDeleted()
    {
        var (database, org, user) = await SeedAsync();
        var row = Row(org, user);
        await InsertAsync(database, row);
        await using var db = database.CreateDbContext();

        Assert.Equal("23001", await SqlStateOfAsync(() => db.Database.ExecuteSqlRawAsync("DELETE FROM invitations WHERE id = {0}", [row.Id], Ct)));
        Assert.Equal("23001", await SqlStateOfAsync(() => db.Database.ExecuteSqlRawAsync("DELETE FROM invitations", Ct)));
        Assert.Equal(1, await db.Invitations.CountAsync(Ct));
    }

    [Fact]
    public async Task TheRowCarriesAConcurrencyToken()
    {
        var (database, org, user) = await SeedAsync();
        var row = Row(org, user);
        await InsertAsync(database, row);
        await using var first = database.CreateDbContext();
        await using var second = database.CreateDbContext();
        var a = await first.Invitations.SingleAsync(i => i.Id == row.Id);
        var b = await second.Invitations.SingleAsync(i => i.Id == row.Id);
        a.Status = InvitationStatus.Revoked;
        a.ResolvedAt = Now;
        a.ResolvedByUserId = user;
        await first.SaveChangesAsync();
        b.Status = InvitationStatus.Accepted;
        b.ResolvedAt = Now;
        b.ResolvedByUserId = user;

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
    }
}
