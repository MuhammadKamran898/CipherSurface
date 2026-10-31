using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CipherSurface.Auth;

public static class AuthServiceCollectionExtensions
{
    /// <summary>
    /// Call after AddCipherSurfaceData. Registers Identity (passwords, lockout), the token services and AccountService.
    /// Passwords: at least 12 characters, no composition rules (length is what matters). Lockout: 5 failures, 15 minutes.
    /// Platform administrators are NOT part of this: they are decided on the server by IPlatformAdminPolicy.
    /// </summary>
    public static IServiceCollection AddCipherSurfaceAuth(this IServiceCollection services, JwtOptions jwt, TokenKeys keys)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton(jwt);
        services.AddSingleton(keys);
        services.TryAddSingleton<AuditLogWriter>();

        services.AddIdentityCore<User>(o =>
            {
                o.User.RequireUniqueEmail = true;
                o.Password.RequiredLength = 12;
                o.Password.RequireDigit = false;
                o.Password.RequireLowercase = false;
                o.Password.RequireUppercase = false;
                o.Password.RequireNonAlphanumeric = false;
                o.Lockout.AllowedForNewUsers = true;
                o.Lockout.MaxFailedAccessAttempts = 5;
                o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            })
            .AddEntityFrameworkStores<CipherSurfaceDbContext>();

        services.AddSingleton<AccessTokenService>();
        services.AddScoped<RefreshTokenService>();
        services.AddScoped<AccountService>();
        return services;
    }
}
