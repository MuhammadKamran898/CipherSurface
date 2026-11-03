using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CipherSurface.Api;
using CipherSurface.Auth;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Services.Tests;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CipherSurface.Api.Tests;

/// <summary>
/// A real API instance on a loopback port (real Kestrel, real pipeline) in front of a real PostgreSQL database.
/// Keys live in temporary files outside the repository, exactly as configuration expects.
/// </summary>
public sealed class ApiHost : IAsyncDisposable
{
    public const string SetupToken = "setup-token-for-tests-0123456789abcdef";
    public const string Password = "correct horse battery staple";
    public const string KeyId = "test-key-1";

    private readonly string _directory;
    private readonly WebApplication _app;

    public HttpClient Client { get; }
    public TestDatabase Database { get; }
    public TokenKeys Keys { get; }
    public string PrivateKeyFile { get; }
    public CapturingLoggerProvider Logs { get; }
    public string BaseAddress { get; }

    private ApiHost(WebApplication app, string baseAddress, TestDatabase database, TokenKeys keys, string directory, string keyFile, CapturingLoggerProvider logs)
    {
        _app = app;
        BaseAddress = baseAddress;
        Database = database;
        Keys = keys;
        _directory = directory;
        PrivateKeyFile = keyFile;
        Logs = logs;
        Client = new HttpClient(new SocketsHttpHandler { UseCookies = false, AllowAutoRedirect = false }) { BaseAddress = new Uri(baseAddress) };
    }

    /// <param name="settings">Configuration overrides (key "CipherSurface:...", null removes a default).</param>
    /// <param name="existing">Reuse the database of an earlier host, for tests that restart the API with other settings.</param>
    public static async Task<ApiHost> StartAsync(
        PostgresFixture postgres,
        IReadOnlyDictionary<string, string?>? settings = null,
        Action<WebApplication>? map = null,
        TestDatabase? existing = null)
    {
        var database = existing ?? await postgres.CreateDatabaseAsync();
        var directory = Path.Combine(Path.GetTempPath(), "cs-api-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        var (keys, privatePem) = Generate();
        var keyFile = Path.Combine(directory, "jwt-private.pem");
        WritePrivateKey(keyFile, privatePem);
        return await StartCoreAsync(database, keys, keyFile, directory, settings, map);
    }

    /// <summary>Starts the API with a key file written by the caller (rotation and key-validation tests).</summary>
    public static async Task<ApiHost> StartWithKeyFileAsync(
        PostgresFixture postgres, TokenKeys keys, string keyFile, IReadOnlyDictionary<string, string?>? settings = null,
        Action<WebApplication>? map = null, TestDatabase? existing = null)
    {
        var database = existing ?? await postgres.CreateDatabaseAsync();
        return await StartCoreAsync(database, keys, keyFile, Path.GetDirectoryName(keyFile)!, settings, map);
    }

    private static async Task<ApiHost> StartCoreAsync(
        TestDatabase database, TokenKeys keys, string keyFile, string directory,
        IReadOnlyDictionary<string, string?>? settings, Action<WebApplication>? map)
    {
        var logs = new CapturingLoggerProvider();
        var configuration = new Dictionary<string, string?>
        {
            ["ConnectionStrings:CipherSurface"] = database.ConnectionString,
            ["CipherSurface:Jwt:PrivateKeyFile"] = keyFile,
            ["CipherSurface:Jwt:KeyId"] = KeyId,
            ["CipherSurface:Setup:Token"] = SetupToken,
            // High limits so ordinary tests never meet them; the rate-limit tests lower them.
            ["CipherSurface:RateLimiting:AuthRequestsPerMinute"] = "1000",
            ["CipherSurface:RateLimiting:GlobalRequestsPerMinute"] = "100000"
        };
        if (settings is not null)
            foreach (var (key, value) in settings) configuration[key] = value;

        var app = ApiApplication.Build([],
            builder =>
            {
                builder.WebHost.UseUrls("http://127.0.0.1:0");
                builder.Configuration.AddInMemoryCollection(configuration);
                builder.Logging.ClearProviders();
                builder.Logging.AddProvider(logs);
            },
            map);
        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        return new ApiHost(app, address, database, keys, directory, keyFile, logs);
    }

    public static (TokenKeys Keys, string PrivatePem) Generate(string keyId = KeyId)
    {
        var (keys, privatePem, _) = TokenKeys.Generate(keyId);
        return (keys, privatePem);
    }

    public static void WritePrivateKey(string path, string pem)
    {
        File.WriteAllText(path, pem);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    /// <summary>Every route the API has mapped (used to prove that only the intended ones are anonymous).</summary>
    public IReadOnlyList<Microsoft.AspNetCore.Routing.RouteEndpoint> Endpoints =>
        _app.Services.GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>().Endpoints
            .OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>().ToList();

    public string NewTempFile(string name) => Path.Combine(_directory, name);

    // ------------------------------------------------------------------ people

    /// <summary>Creates an account and its organization through AccountService (the service layer stands in for invitations).</summary>
    public async Task<(Guid UserId, Guid OrganizationId, string Email)> RegisterAsync(string email, string organization = "Org")
    {
        await using var scope = _app.Services.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<AccountService>().RegisterAsync(email, Password, organization, CancellationToken.None);
        return (result.UserId, result.OrganizationId, email);
    }

    public async Task AddMembershipAsync(Guid userId, Guid organizationId, MembershipRole role)
    {
        await using var db = Database.CreateDbContext();
        db.Memberships.Add(new Membership { Id = Guid.NewGuid(), OrganizationId = organizationId, UserId = userId, Role = role, CreatedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
    }

    public async Task SetRoleAsync(Guid userId, Guid organizationId, MembershipRole role)
    {
        await using var db = Database.CreateDbContext();
        var membership = await db.Memberships.SingleAsync(m => m.UserId == userId && m.OrganizationId == organizationId);
        membership.Role = role;
        await db.SaveChangesAsync();
    }

    public async Task RemoveMembershipAsync(Guid userId, Guid organizationId)
    {
        await using var db = Database.CreateDbContext();
        await db.Memberships.Where(m => m.UserId == userId && m.OrganizationId == organizationId).ExecuteDeleteAsync();
    }

    public async Task DisableUserAsync(Guid userId)
    {
        await using var db = Database.CreateDbContext();
        await db.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(s => s.SetProperty(u => u.Status, UserStatus.Disabled));
    }

    public async Task<int> UserCountAsync()
    {
        await using var db = Database.CreateDbContext();
        return await db.Users.CountAsync();
    }

    public async Task<Tokens> LoginAsync(string email, string password = Password)
    {
        var response = await SendAsync(HttpMethod.Post, "/api/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadTokensAsync(response);
    }

    public static async Task<Tokens> ReadTokensAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return new Tokens(json.RootElement.GetProperty("accessToken").GetString()!, json.RootElement.GetProperty("refreshToken").GetString()!);
    }

    // ------------------------------------------------------------------ http

    public Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string path, object? body = null, string? bearer = null, Guid? organizationId = null,
        IReadOnlyDictionary<string, string>? headers = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = new StringContent(body as string ?? JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (organizationId is { } org) request.Headers.Add("X-Organization-Id", org.ToString("D"));
        if (headers is not null)
            foreach (var (name, value) in headers) request.Headers.TryAddWithoutValidation(name, value);
        return Client.SendAsync(request);
    }

    public Task<HttpResponseMessage> GetAsync(string path, string? bearer = null, Guid? organizationId = null, IReadOnlyDictionary<string, string>? headers = null) =>
        SendAsync(HttpMethod.Get, path, null, bearer, organizationId, headers);

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
    }
}

public sealed record Tokens(string Access, string Refresh);

public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly List<string> _lines = [];

    public IReadOnlyList<string> Lines { get { lock (_lines) return [.. _lines]; } }

    public ILogger CreateLogger(string categoryName) => new Capture(this);
    public void Dispose() { }

    private sealed class Capture(CapturingLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (owner._lines) owner._lines.Add($"{logLevel}: {formatter(state, exception)}{(exception is null ? "" : " | " + exception)}");
        }
    }
}
