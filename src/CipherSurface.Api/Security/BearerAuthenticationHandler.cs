using System.Security.Claims;
using System.Text.Encodings.Web;
using CipherSurface.Api.Errors;
using CipherSurface.Auth;
using CipherSurface.Data;
using CipherSurface.Data.Enums;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CipherSurface.Api.Security;

public static class BearerDefaults
{
    public const string Scheme = "Bearer";
}

/// <summary>
/// Bearer-token authentication on top of the one token validator the platform already has (RS256 only, issuer,
/// audience and expiry checked). On top of the signature it also checks, on every request, that the session behind the
/// token is still alive and the account is still active, so logging out, a password change or disabling an account take
/// effect immediately and not when the 15-minute token expires. It reads the token from the Authorization header only.
/// </summary>
public sealed class BearerAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly AccessTokenService _tokens;
    private readonly RefreshTokenService _sessions;
    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;

    public BearerAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder,
        AccessTokenService tokens, RefreshTokenService sessions, IDbContextFactory<CipherSurfaceDbContext> factory)
        : base(options, logger, encoder)
    {
        _tokens = tokens;
        _sessions = sessions;
        _factory = factory;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var values))
            return AuthenticateResult.NoResult();

        if (values.Count != 1 || values[0] is not { } header || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.Fail("The Authorization header is not a bearer token.");

        var validated = await _tokens.ValidateAsync(header["Bearer ".Length..].Trim());
        if (validated is null)
            return AuthenticateResult.Fail("The token is not valid.");

        var ct = Context.RequestAborted;
        if (!await _sessions.IsSessionActiveAsync(validated.UserId, validated.SessionId, ct))
            return AuthenticateResult.Fail("The session has ended.");

        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            var status = await db.Users.AsNoTracking().Where(u => u.Id == validated.UserId).Select(u => (UserStatus?)u.Status).SingleOrDefaultAsync(ct);
            if (status != UserStatus.Active)
                return AuthenticateResult.Fail("The account is not active.");
        }

        var identity = new ClaimsIdentity(
            [new Claim("sub", validated.UserId.ToString("D")), new Claim("sid", validated.SessionId.ToString("D")), new Claim("email", validated.Email)],
            Scheme.Name, nameType: "email", roleType: ClaimsIdentity.DefaultRoleClaimType);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Bearer";
        await ProblemWriter.WriteAsync(Context, 401, "Unauthorized", ProblemWriter.GenericDetail(401));
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        ProblemWriter.WriteAsync(Context, 403, "Forbidden", ProblemWriter.GenericDetail(403));
}

public static class AuthenticatedUser
{
    /// <summary>The user id from the validated token. Never read a user id from a request body or query string.</summary>
    public static Guid Id(this ClaimsPrincipal user) =>
        Guid.TryParse(user.FindFirst("sub")?.Value, out var id) && id != Guid.Empty
            ? id
            : throw new CipherSurface.Services.ServiceException("Unauthorized", "Authentication is required.");
}
