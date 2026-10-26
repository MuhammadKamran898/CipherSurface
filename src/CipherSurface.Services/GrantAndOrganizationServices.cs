using CipherSurface.Data;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

/// <summary>Revoking the authorization statement stops scanning of that domain at once, including scans already running.</summary>
public sealed class GrantService
{
    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;

    public GrantService(IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, AuditLogWriter audit)
    {
        _factory = factory;
        _time = time;
        _audit = audit;
    }

    public async Task RevokeAsync(Actor actor, Guid domainId, string reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason)) throw new ServiceException("ReasonRequired", "Say why the authorization is being revoked.");
        if (reason.Length > 500) throw new ServiceException("ReasonTooLong", "The reason can be at most 500 characters.");

        await using var db = await _factory.CreateDbContextAsync(ct);
        await Access.RequireManagerAsync(db, actor, ct);
        var domain = await Access.LoadOwnDomainAsync(db, actor, domainId, ct);

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var grant = await db.AuthorizationGrants.SingleOrDefaultAsync(g => g.DomainId == domain.Id && g.Status == GrantStatus.Active, ct)
                    ?? throw new ServiceException("NoActiveGrant", "This domain has no active authorization.");

        var now = _time.GetUtcNow();
        grant.Status = GrantStatus.Revoked;
        grant.RevokedAt = now;
        grant.RevokedByUserId = actor.UserId;
        await db.SaveChangesAsync(ct);

        var flagged = await ScanCancellation.RequestForDomainAsync(db, domain.Id, "AuthorizationGrantInactive", now, ct);
        await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "grant.revoked", "AuthorizationGrant", grant.Id,
            new Dictionary<string, object?> { ["domainId"] = domain.Id.ToString("D"), ["reason"] = reason.Trim(), ["scansFlagged"] = flagged }, actor.Ip), ct);
        await tx.CommitAsync(ct);
    }
}

/// <summary>Suspending an organization blocks all of its scans immediately; scans already running are told to stop.</summary>
public sealed class OrganizationService
{
    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;

    public OrganizationService(IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, AuditLogWriter audit)
    {
        _factory = factory;
        _time = time;
        _audit = audit;
    }

    public Task SuspendAsync(PlatformAdmin admin, Guid organizationId, string reason, CancellationToken ct) =>
        ChangeAsync(admin, organizationId, reason, suspend: true, ct);

    public Task ReactivateAsync(PlatformAdmin admin, Guid organizationId, string reason, CancellationToken ct) =>
        ChangeAsync(admin, organizationId, reason, suspend: false, ct);

    private async Task ChangeAsync(PlatformAdmin admin, Guid organizationId, string reason, bool suspend, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(admin);
        if (string.IsNullOrWhiteSpace(reason)) throw new ServiceException("ReasonRequired", "Say why the organization status is changing.");
        if (reason.Length > 500) throw new ServiceException("ReasonTooLong", "The reason can be at most 500 characters.");

        await using var db = await _factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var organization = await db.Organizations.SingleOrDefaultAsync(o => o.Id == organizationId, ct)
                           ?? throw new ServiceException("NotFound", "Organization not found.");

        var target = suspend ? OrganizationStatus.Suspended : OrganizationStatus.Active;
        if (organization.Status == target)
            throw new ServiceException(suspend ? "AlreadySuspended" : "AlreadyActive", $"The organization is already {target}.");

        var now = _time.GetUtcNow();
        organization.Status = target;
        await db.SaveChangesAsync(ct);

        var flagged = suspend ? await ScanCancellation.RequestForOrganizationAsync(db, organizationId, "OrganizationSuspended", now, ct) : 0;
        await _audit.AppendAsync(db, new AuditEntry(organizationId, "PlatformAdmin", admin.UserId,
            suspend ? "organization.suspended" : "organization.reactivated", "Organization", organizationId,
            new Dictionary<string, object?> { ["reason"] = reason.Trim(), ["scansFlagged"] = flagged }), ct);
        await tx.CommitAsync(ct);
    }
}
