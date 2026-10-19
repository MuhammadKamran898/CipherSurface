using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CipherSurface.Data;

/// <summary>
/// Used only by `dotnet ef`. Set CIPHERSURFACE_DB, for example:
/// Host=localhost;Database=ciphersurface;Username=cipher_owner;Password=...
/// Migrations must run as the schema OWNER role, never the restricted application role.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<CipherSurfaceDbContext>
{
    public CipherSurfaceDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("CIPHERSURFACE_DB")
            ?? throw new InvalidOperationException("Set the CIPHERSURFACE_DB environment variable.");

        var options = new DbContextOptionsBuilder<CipherSurfaceDbContext>()
            .UseNpgsql(connectionString)
            .UseSnakeCaseNamingConvention()
            .Options;

        return new CipherSurfaceDbContext(options);
    }
}
