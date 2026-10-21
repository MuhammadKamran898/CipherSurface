using CipherSurface.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>One throwaway PostgreSQL container for the whole test run. Needs Docker running.</summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:16-alpine").Build();

    public async ValueTask InitializeAsync() => await _container.StartAsync();

    public async ValueTask DisposeAsync() => await _container.DisposeAsync();

    /// <summary>A fresh, isolated database with the EF schema and the SQL integrity rules applied.</summary>
    public async Task<TestDatabase> CreateDatabaseAsync()
    {
        var name = "t_" + Guid.NewGuid().ToString("N");
        await using (var admin = new NpgsqlConnection(_container.GetConnectionString()))
        {
            await admin.OpenAsync();
            await using var command = admin.CreateCommand();
            command.CommandText = $"CREATE DATABASE \"{name}\"";
            await command.ExecuteNonQueryAsync();
        }

        var connectionString = new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
        {
            Database = name,
            Pooling = false
        }.ConnectionString;

        var database = new TestDatabase(connectionString);
        await using var context = database.CreateDbContext();
        await context.Database.EnsureCreatedAsync();
        await database.RunScriptAsync(context, IntegrityScripts.Load());
        return database;
    }
}

public sealed class TestDatabase : IDbContextFactory<CipherSurfaceDbContext>
{
    private readonly string _connectionString;

    public TestDatabase(string connectionString) => _connectionString = connectionString;

    public CipherSurfaceDbContext CreateDbContext() =>
        new(new DbContextOptionsBuilder<CipherSurfaceDbContext>()
            .UseNpgsql(_connectionString)
            .UseSnakeCaseNamingConvention()
            .Options);

    public async Task RunScriptAsync(CipherSurfaceDbContext context, string sql)
    {
        var connection = context.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open) await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>Runs SQL as the schema owner (used to simulate tampering in tests).</summary>
    public async Task ExecuteAsync(string sql)
    {
        await using var context = CreateDbContext();
        await RunScriptAsync(context, sql);
    }
}

[CollectionDefinition("postgres")]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture> { }
