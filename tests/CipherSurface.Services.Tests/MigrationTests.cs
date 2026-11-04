using CipherSurface.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>
/// Proves the schema can be built from NOTHING the way production builds it: EF migrations create the tables, then the
/// SQL scripts add the triggers and (for the application role) the privileges. Every other test class builds its schema
/// with EnsureCreated, so these tests are what keep the migration and that schema from drifting apart.
/// </summary>
[Collection("postgres")]
public class MigrationTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly PostgresFixture _postgres;
    public MigrationTests(PostgresFixture postgres) => _postgres = postgres;

    private static readonly string[] AppendOnlyTables = ["audit_logs", "policy_decisions", "verification_checks", "scan_run_authorization_checks"];

    private static readonly string[] NoDeleteTables =
    [
        "organizations", "users", "domains", "authorization_grants", "domain_disputes", "verification_challenges",
        "verification_attempts", "verification_evidence", "scope_rules", "scan_runs", "invitations"
    ];

    private static string ReadScript(string fileName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Sql", fileName);
        Assert.True(File.Exists(path), $"{fileName} was not copied next to the test assembly ({path}).");
        return File.ReadAllText(path);
    }

    private static async Task MigrateAsync(TestDatabase db)
    {
        await using var context = db.CreateDbContext();
        await context.Database.MigrateAsync(Ct);
    }

    /// <summary>One sorted line per column, index and constraint. Two schemas are the same when their lines are the same.</summary>
    private static async Task<List<string>> SchemaAsync(TestDatabase db)
    {
        var queries = new[]
        {
            """
            SELECT 'column ' || table_name || '.' || column_name || ' ' || data_type || ' len=' || coalesce(character_maximum_length::text, '-')
                   || ' null=' || is_nullable || ' default=' || coalesce(column_default, '')
            FROM information_schema.columns WHERE table_schema = 'public'
            """,
            "SELECT 'index ' || tablename || ' ' || indexname || ' ' || indexdef FROM pg_indexes WHERE schemaname = 'public'",
            """
            SELECT 'constraint ' || conrelid::regclass::text || ' ' || conname || ' ' || pg_get_constraintdef(oid)
            FROM pg_constraint WHERE connamespace = 'public'::regnamespace
            """
        };

        await using var connection = new NpgsqlConnection(db.ConnectionString);
        await connection.OpenAsync(Ct);
        var lines = new List<string>();
        foreach (var sql in queries)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            await using var reader = await command.ExecuteReaderAsync(Ct);
            while (await reader.ReadAsync(Ct))
                lines.Add(reader.GetString(0));
        }

        return lines.Where(l => !l.Contains("__EFMigrationsHistory", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
    }

    private static async Task<List<string>> ColumnAsync(TestDatabase db, string sql)
    {
        await using var connection = new NpgsqlConnection(db.ConnectionString);
        await connection.OpenAsync(Ct);
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(Ct);
        var values = new List<string>();
        while (await reader.ReadAsync(Ct))
            values.Add(reader.GetString(0));
        return values;
    }

    private static async Task<bool> HasPrivilegeAsync(TestDatabase db, string role, string table, string privilege)
    {
        await using var connection = new NpgsqlConnection(db.ConnectionString);
        await connection.OpenAsync(Ct);
        await using var command = new NpgsqlCommand("SELECT has_table_privilege(@role, @table, @privilege)", connection);
        command.Parameters.AddWithValue("role", role);
        command.Parameters.AddWithValue("table", table);
        command.Parameters.AddWithValue("privilege", privilege);
        return (bool)(await command.ExecuteScalarAsync(Ct))!;
    }

    // ------------------------------------------------------------------ the migration

    [Fact]
    public async Task MigrationsBuildTheSchemaOnAnEmptyDatabase()
    {
        var db = await _postgres.CreateEmptyDatabaseAsync();

        await MigrateAsync(db);

        await using var context = db.CreateDbContext();
        Assert.NotEmpty(await context.Database.GetAppliedMigrationsAsync(Ct));
        Assert.Empty(await context.Database.GetPendingMigrationsAsync(Ct));
        Assert.Contains("domains", await ColumnAsync(db, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"));
        Assert.Contains("scope_rules", await ColumnAsync(db, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"));
    }

    [Fact]
    public async Task MigratingTwice_ChangesNothing()
    {
        var db = await _postgres.CreateEmptyDatabaseAsync();
        await MigrateAsync(db);
        var before = await SchemaAsync(db);

        await MigrateAsync(db);

        Assert.Equal(before, await SchemaAsync(db));
    }

    [Fact]
    public async Task TheMigratedSchema_IsTheSchemaTheRestOfTheTestsRunAgainst()
    {
        var migrated = await _postgres.CreateEmptyDatabaseAsync();
        await MigrateAsync(migrated);

        var created = await _postgres.CreateEmptyDatabaseAsync();
        await using (var context = created.CreateDbContext())
            await context.Database.EnsureCreatedAsync(Ct);

        Assert.Equal(await SchemaAsync(created), await SchemaAsync(migrated));
    }

    // ------------------------------------------------------------------ the SQL scripts on top of the migration

    [Fact]
    public async Task IntegrityScript_InstallsEveryTrigger_AndCanBeRunAgain()
    {
        var db = await _postgres.CreateEmptyDatabaseAsync();
        await MigrateAsync(db);

        await using (var context = db.CreateDbContext())
        {
            await db.RunScriptAsync(context, IntegrityScripts.Load());
            await db.RunScriptAsync(context, IntegrityScripts.Load());
        }

        var expected = AppendOnlyTables.SelectMany(t => new[] { $"trg_{t}_append_only", $"trg_{t}_no_truncate" })
            .Concat(NoDeleteTables.Select(t => $"trg_{t}_no_delete"))
            .Append("trg_scope_rules_within_domain")
            .Append("trg_scan_runs_requires_allow")
            .Append("trg_invitations_immutable")
            .Order(StringComparer.Ordinal)
            .ToList();
        var actual = await ColumnAsync(db,
            "SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace");
        Assert.Equal(expected, actual.Order(StringComparer.Ordinal).ToList());
    }

    [Fact]
    public async Task IntegrityRules_HoldOnTheMigratedSchema()
    {
        var db = await _postgres.CreateEmptyDatabaseAsync();
        await MigrateAsync(db);
        await using var context = db.CreateDbContext();
        await db.RunScriptAsync(context, IntegrityScripts.Load());

        // The smoke script raises an exception if any rule does not behave, and rolls everything back.
        await db.RunScriptAsync(context, ReadScript("003_integrity_smoke_test.sql"));
    }

    [Fact]
    public async Task AppRoleGrants_LeaveTheApplicationUnableToChangeHistory()
    {
        var db = await _postgres.CreateEmptyDatabaseAsync();
        await MigrateAsync(db);
        await using (var context = db.CreateDbContext())
        {
            await db.RunScriptAsync(context, IntegrityScripts.Load());
            // Roles belong to the whole server, so tolerate another test having created it already.
            await db.RunScriptAsync(context, "DO $$ BEGIN CREATE ROLE cipher_app NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;");
            await db.RunScriptAsync(context, ReadScript("002_app_role_grants.sql"));
        }

        foreach (var table in AppendOnlyTables)
        {
            Assert.True(await HasPrivilegeAsync(db, "cipher_app", table, "SELECT"), $"{table} SELECT");
            Assert.True(await HasPrivilegeAsync(db, "cipher_app", table, "INSERT"), $"{table} INSERT");
            Assert.False(await HasPrivilegeAsync(db, "cipher_app", table, "UPDATE"), $"{table} UPDATE");
            Assert.False(await HasPrivilegeAsync(db, "cipher_app", table, "DELETE"), $"{table} DELETE");
            Assert.False(await HasPrivilegeAsync(db, "cipher_app", table, "TRUNCATE"), $"{table} TRUNCATE");
        }

        foreach (var table in NoDeleteTables)
        {
            Assert.True(await HasPrivilegeAsync(db, "cipher_app", table, "SELECT"), $"{table} SELECT");
            Assert.True(await HasPrivilegeAsync(db, "cipher_app", table, "INSERT"), $"{table} INSERT");
            Assert.True(await HasPrivilegeAsync(db, "cipher_app", table, "UPDATE"), $"{table} UPDATE");
            Assert.False(await HasPrivilegeAsync(db, "cipher_app", table, "DELETE"), $"{table} DELETE");
            Assert.False(await HasPrivilegeAsync(db, "cipher_app", table, "TRUNCATE"), $"{table} TRUNCATE");
        }

        Assert.False(await HasPrivilegeAsync(db, "cipher_app", "\"__EFMigrationsHistory\"", "SELECT"));
        Assert.False(await HasPrivilegeAsync(db, "cipher_app", "\"__EFMigrationsHistory\"", "INSERT"));
    }
}
