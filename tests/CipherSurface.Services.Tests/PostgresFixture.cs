using CipherSurface.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>
/// One throwaway PostgreSQL container for the whole test run. Needs Docker running.
/// The schema is built ONCE into a template database; every test gets a fast copy of it. Connections are
/// pooled with a short idle lifetime, which keeps the number of sockets opened through Docker Desktop low.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private const string TemplateName = "cs_template";

    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:16-alpine")
        .WithCommand("-c", "max_connections=500", "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off")
        .Build();

    public async ValueTask InitializeAsync()
    {
        await _container.StartAsync();
        await ExecuteAdminAsync($"CREATE DATABASE {TemplateName}");

        var template = new TestDatabase(ConnectionStringFor(TemplateName, pooled: false));
        await using (var context = template.CreateDbContext())
        {
            await context.Database.EnsureCreatedAsync();
            await template.RunScriptAsync(context, IntegrityScripts.Load());
        }
        NpgsqlConnection.ClearAllPools();   // nobody may be connected to the template when it is copied
    }

    public async ValueTask DisposeAsync() => await _container.DisposeAsync();

    /// <summary>A fresh, isolated database with the EF schema and the SQL integrity rules already applied.</summary>
    public async Task<TestDatabase> CreateDatabaseAsync()
    {
        var name = "t_" + Guid.NewGuid().ToString("N");
        await ExecuteAdminAsync($"CREATE DATABASE \"{name}\" TEMPLATE {TemplateName}");
        return new TestDatabase(ConnectionStringFor(name, pooled: true));
    }

    private string ConnectionStringFor(string database, bool pooled) =>
        new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
        {
            Database = database,
            Pooling = pooled,
            MaxPoolSize = 30,
            ConnectionIdleLifetime = 5,
            ConnectionPruningInterval = 2,
            Timeout = 60,
            CommandTimeout = 60
        }.ConnectionString;

    private async Task ExecuteAdminAsync(string sql)
    {
        var builder = new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Pooling = false, Timeout = 60, CommandTimeout = 120 };
        await using var admin = new NpgsqlConnection(builder.ConnectionString);
        await admin.OpenAsync();
        await using var command = admin.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}

public sealed class TestDatabase : IDbContextFactory<CipherSurfaceDbContext>
{
    private readonly string _connectionString;

    public TestDatabase(string connectionString) => _connectionString = connectionString;

    public string ConnectionString => _connectionString;

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
