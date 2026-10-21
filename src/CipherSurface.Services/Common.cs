using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

/// <summary>An expected, user-facing failure. Code is stable and safe to show or test against.</summary>
public sealed class ServiceException : Exception
{
    public string Code { get; }
    public ServiceException(string code, string message) : base(message) => Code = code;
}

/// <summary>Who is acting, in which organization, from which IP.</summary>
public sealed record Actor(Guid UserId, Guid OrganizationId, string Ip);

internal static class Access
{
    /// <summary>Only an Owner or Admin of an Active organization may add and verify domains.</summary>
    public static async Task RequireManagerAsync(CipherSurfaceDbContext db, Actor actor, CancellationToken ct)
    {
        var membership = await db.Memberships.AsNoTracking()
            .SingleOrDefaultAsync(m => m.OrganizationId == actor.OrganizationId && m.UserId == actor.UserId, ct);
        if (membership is null || membership.Role is not (MembershipRole.Owner or MembershipRole.Admin))
            throw new ServiceException("NotAllowed", "Only an organization Owner or Admin can do this.");

        var status = await db.Organizations.AsNoTracking()
            .Where(o => o.Id == actor.OrganizationId).Select(o => o.Status).SingleAsync(ct);
        if (status != OrganizationStatus.Active)
            throw new ServiceException("OrganizationSuspended", "This organization is suspended.");
    }

    public static async Task<Domain> LoadOwnDomainAsync(CipherSurfaceDbContext db, Actor actor, Guid domainId, CancellationToken ct)
    {
        var domain = await db.Domains.SingleOrDefaultAsync(d => d.Id == domainId && d.OrganizationId == actor.OrganizationId, ct);
        return domain ?? throw new ServiceException("NotFound", "Domain not found.");
    }
}

internal static class DbLocks
{
    /// <summary>Transaction-scoped advisory lock. Released automatically at commit or rollback.</summary>
    public static async Task AcquireAsync(CipherSurfaceDbContext db, string key, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("An advisory lock needs an open transaction.");
        await db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtextextended({key}, 0))", ct);
    }
}
