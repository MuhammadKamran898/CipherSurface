using System.Security.Cryptography;
using System.Text;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace CipherSurface.Services;

public sealed class DomainOnboardingService
{
    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;
    private readonly DomainNameValidator _names;

    public DomainOnboardingService(IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, AuditLogWriter audit, DomainNameValidator names)
    {
        _factory = factory;
        _time = time;
        _audit = audit;
        _names = names;
    }

    /// <summary>Creates the domain in Pending state and records the organization's authorization attestation.</summary>
    public async Task<Guid> AddDomainAsync(Actor actor, string rawName, string attestationVersion, string attestationText, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(attestationVersion) || string.IsNullOrWhiteSpace(attestationText))
            throw new ServiceException("AttestationRequired", "You must accept the authorization statement.");

        var name = _names.Normalize(rawName);

        await using var db = await _factory.CreateDbContextAsync(ct);
        await Access.RequireManagerAsync(db, actor, ct);

        if (await db.Domains.AnyAsync(d => d.OrganizationId == actor.OrganizationId && d.Name == name, ct))
            throw new ServiceException("DomainExists", "This domain is already added.");

        var now = _time.GetUtcNow();
        var domain = new Domain
        {
            Id = Guid.NewGuid(),
            OrganizationId = actor.OrganizationId,
            Name = name,
            Status = DomainStatus.Pending,
            CreatedByUserId = actor.UserId,
            CreatedAt = now
        };
        var grant = new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            OrganizationId = actor.OrganizationId,
            DomainId = domain.Id,
            GrantedByUserId = actor.UserId,
            GrantType = GrantType.SelfAttestation,
            AttestationTextVersion = attestationVersion,
            AttestationHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(attestationText))).ToLowerInvariant(),
            AcceptedAt = now,
            Ip = actor.Ip,
            Status = GrantStatus.Active
        };

        try
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            db.Domains.Add(domain);
            db.AuthorizationGrants.Add(grant);
            await db.SaveChangesAsync(ct);

            await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "domain.added", "Domain", domain.Id,
                new Dictionary<string, object?> { ["name"] = name }, actor.Ip), ct);
            await _audit.AppendAsync(db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "grant.created", "AuthorizationGrant", grant.Id,
                new Dictionary<string, object?> { ["domainId"] = domain.Id.ToString("D"), ["attestationVersion"] = attestationVersion }, actor.Ip), ct);
            await tx.CommitAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: "23505" })
        {
            throw new ServiceException("DomainExists", "This domain is already added.");
        }

        return domain.Id;
    }
}
