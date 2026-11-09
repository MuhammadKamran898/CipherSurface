using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CipherSurface.Api.Configuration;
using CipherSurface.Api.Contracts;
using CipherSurface.Api.Security;
using CipherSurface.Auth;
using CipherSurface.Data;
using CipherSurface.Services;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Api.Endpoints;

/// <summary>
/// Thin HTTP layer over AccountService. Registration is invite-only: there is no public sign-up. The only way to create
/// an account here is the one-time setup of the first owner, protected by a setup token from configuration, and it closes
/// itself as soon as any account exists. Every later member arrives by invitation (see InvitationEndpoints).
/// </summary>
public static class AuthEndpoints
{
    public const string RateLimitPolicy = "auth";
    public const string SetupTokenHeader = "X-Setup-Token";

    public static void Map(RouteGroupBuilder api)
    {
        var setup = api.MapGroup("/setup").AllowAnonymous().RequireRateLimiting(RateLimitPolicy);
        setup.MapPost("/owner", async (SetupRequest request, HttpContext http, ApiSettings settings, AccountService accounts, CancellationToken ct) =>
        {
            RequireSetupToken(http, settings);
            var result = await accounts.RegisterFirstOwnerAsync(request.Email, request.Password, request.OrganizationName, ct);
            return Results.Json(new SetupResponse(result.UserId, result.OrganizationId), statusCode: StatusCodes.Status201Created);
        });

        var auth = api.MapGroup("/auth").RequireRateLimiting(RateLimitPolicy);
        auth.MapPost("/login", async (LoginRequest request, HttpContext http, AccountService accounts, CancellationToken ct) =>
            Results.Ok(await accounts.LoginAsync(request.Email, request.Password, ClientIp.Of(http), ct))).AllowAnonymous();

        auth.MapPost("/refresh", async (RefreshRequest request, HttpContext http, AccountService accounts, CancellationToken ct) =>
            Results.Ok(await accounts.RefreshAsync(request.RefreshToken, ClientIp.Of(http), ct))).AllowAnonymous();

        auth.MapPost("/logout", async (RefreshRequest request, AccountService accounts, CancellationToken ct) =>
        {
            await accounts.LogoutAsync(request.RefreshToken, ct);
            return Results.NoContent();
        }).AllowAnonymous();

        auth.MapPost("/change-password", async (ChangePasswordRequest request, ClaimsPrincipal user, AccountService accounts, CancellationToken ct) =>
        {
            try
            {
                await accounts.ChangePasswordAsync(user.Id(), request.CurrentPassword, request.NewPassword, ct);
            }
            catch (ServiceException ex) when (ex.Code == "InvalidCredentials")
            {
                // Here the caller IS authenticated, so a 401 would wrongly tell the client its token expired.
                throw new ServiceException("CurrentPasswordIncorrect", "The current password is wrong.");
            }

            return Results.NoContent();
        });

        api.MapGet("/me", async (ClaimsPrincipal user, IDbContextFactory<CipherSurfaceDbContext> factory, IPlatformAdminPolicy admins, CancellationToken ct) =>
        {
            var userId = user.Id();
            await using var db = await factory.CreateDbContextAsync(ct);
            var organizations = await db.Memberships.AsNoTracking()
                .Where(m => m.UserId == userId)
                .OrderBy(m => m.Organization.Name).ThenBy(m => m.OrganizationId)
                .Select(m => new MembershipView(m.OrganizationId, m.Organization.Name, m.Organization.Status, m.Role))
                .ToListAsync(ct);
            return Results.Ok(new MeResponse(userId, user.FindFirst("email")?.Value ?? string.Empty, await admins.IsPlatformAdminAsync(userId, ct), organizations));
        });

        api.MapGet("/organization", (OrganizationContext org) =>
            Results.Ok(new OrganizationResponse(org.Actor.OrganizationId, org.OrganizationName, org.OrganizationStatus, org.Role)));
    }

    private static void RequireSetupToken(HttpContext http, ApiSettings settings)
    {
        // Without a configured token setup does not exist: fail closed, and answer as if the route were absent.
        if (settings.SetupToken is null)
            throw new ServiceException("SetupDisabled", "The resource was not found.");

        var provided = http.Request.Headers[SetupTokenHeader].ToString();
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(settings.SetupToken));
        var providedHash = SHA256.HashData(Encoding.UTF8.GetBytes(provided));
        if (!CryptographicOperations.FixedTimeEquals(expectedHash, providedHash))
            throw new ServiceException("SetupTokenInvalid", "The setup token is missing or wrong.");
    }
}
