using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CipherSurface.Data;

public static class ServiceCollectionExtensions
{
    /// <summary>Call from ASP.NET Core: services.AddCipherSurfaceData(connectionString);</summary>
    public static IServiceCollection AddCipherSurfaceData(this IServiceCollection services, string connectionString)
    {
        services.AddDbContext<CipherSurfaceDbContext>(o => o
            .UseNpgsql(connectionString)
            .UseSnakeCaseNamingConvention());
        return services;
    }
}
