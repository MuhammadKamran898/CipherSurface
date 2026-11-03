using CipherSurface.Data;
using CipherSurface.Data.Enums;
using CipherSurface.Services;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Api.Security;

/// <summary>The organization a request acts in, with the user's real role in it.</summary>
public sealed record OrganizationContext(Actor Actor, string OrganizationName, OrganizationStatus OrganizationStatus, MembershipRole Role);

/// <summary>
/// Works out which organization a request acts in. The X-Organization-Id header only SELECTS among the organizations
/// the authenticated user already belongs to; it never grants anything. Membership and role are read from the database
/// on every request. A user with several memberships who names none gets an error, never a guess.
/// The Actor is built here, on the server, from the validated token: no user id, organization owner or role is ever
/// taken from a request body.
/// </summary>
public sealed class OrganizationContextResolver
{
    public const string HeaderName = "X-Organization-Id";

    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    public OrganizationContextResolver(IDbContextFactory<CipherSurfaceDbContext> factory) => _factory = factory;

    public async Task<OrganizationContext> ResolveAsync(HttpContext http, CancellationToken ct)
    {
        var userId = http.User.Id();
        var requested = ReadHeader(http);

        await using var db = await _factory.CreateDbContextAsync(ct);
        var memberships = await db.Memberships.AsNoTracking()
            .Where(m => m.UserId == userId)
            .Select(m => new { m.OrganizationId, m.Role, m.Organization.Name, m.Organization.Status })
            .ToListAsync(ct);

        var chosen = requested is { } id
            ? memberships.SingleOrDefault(m => m.OrganizationId == id)
              ?? throw new ServiceException("NotAllowed", "You are not a member of this organization.")   // same answer whether it exists or not
            : memberships.Count switch
            {
                0 => throw new ServiceException("NoOrganization", "This account does not belong to any organization."),
                1 => memberships[0],
                _ => throw new ServiceException("OrganizationRequired", $"This account belongs to several organizations. Send the {HeaderName} header.")
            };

        return new OrganizationContext(new Actor(userId, chosen.OrganizationId, ClientIp.Of(http)), chosen.Name, chosen.Status, chosen.Role);
    }

    private static Guid? ReadHeader(HttpContext http)
    {
        if (!http.Request.Headers.TryGetValue(HeaderName, out var values)) return null;
        if (values.Count != 1 || !Guid.TryParse(values[0], out var id) || id == Guid.Empty)
            throw new ServiceException("InvalidOrganizationId", $"{HeaderName} must contain one organization id.");
        return id;
    }
}

public static class ClientIp
{
    /// <summary>The caller's address as the server sees it. Forwarded headers change it only when proxies are configured.</summary>
    public static string Of(HttpContext http) => http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
