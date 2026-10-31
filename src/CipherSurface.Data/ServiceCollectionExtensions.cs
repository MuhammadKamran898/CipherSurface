using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CipherSurface.Data;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers BOTH ways of getting a database context: IDbContextFactory (used by the services, one short-lived context
    /// per operation) and a scoped CipherSurfaceDbContext (used by ASP.NET Core Identity's stores).
    /// </summary>
    public static IServiceCollection AddCipherSurfaceData(this IServiceCollection services, string connectionString)
    {
        services.AddDbContextFactory<CipherSurfaceDbContext>(o => o
            .UseNpgsql(connectionString)
            .UseSnakeCaseNamingConvention(), ServiceLifetime.Scoped);
        services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<CipherSurfaceDbContext>>().CreateDbContext());
        return services;
    }
}
