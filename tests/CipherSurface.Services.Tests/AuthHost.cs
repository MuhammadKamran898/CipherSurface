using CipherSurface.Auth;
using CipherSurface.Data;
using Microsoft.Extensions.DependencyInjection;

namespace CipherSurface.Services.Tests;

/// <summary>The real dependency-injection setup the API will use, pointed at a test database and a fake clock.</summary>
public sealed class AuthHost : IDisposable
{
    public required ServiceProvider Provider { get; init; }
    public required FakeTime Time { get; init; }
    public required JwtOptions Options { get; init; }
    public required TokenKeys Keys { get; init; }

    public AccessTokenService Tokens => Provider.GetRequiredService<AccessTokenService>();

    public static AuthHost Create(TestDatabase db, TokenKeys? keys = null, JwtOptions? options = null)
    {
        var time = new FakeTime(TestWorld.Start);
        var jwt = options ?? new JwtOptions();
        var tokenKeys = keys ?? TokenKeys.Generate("test-key").Keys;

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(time);
        services.AddCipherSurfaceData(db.ConnectionString);
        services.AddCipherSurfaceAuth(jwt, tokenKeys);
        return new AuthHost { Provider = services.BuildServiceProvider(), Time = time, Options = jwt, Keys = tokenKeys };
    }

    /// <summary>Runs one call in its own scope, like one web request.</summary>
    public async Task<T> Run<T>(Func<AccountService, Task<T>> call)
    {
        using var scope = Provider.CreateScope();
        return await call(scope.ServiceProvider.GetRequiredService<AccountService>());
    }

    public Task Run(Func<AccountService, Task> call) => Run(async a => { await call(a); return 0; });

    public void Dispose() => Provider.Dispose();
}
