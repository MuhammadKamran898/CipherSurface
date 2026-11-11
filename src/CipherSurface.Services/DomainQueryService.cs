using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

public sealed record DomainEvidenceSummary(VerificationMethod Method, EvidenceStatus Status, DateTimeOffset? ExpiresAt);
public sealed record DomainListItem(Guid Id, string Name, DomainStatus Status, DateTimeOffset CreatedAt, IReadOnlyList<DomainEvidenceSummary> Evidence);
public sealed record DomainPage(IReadOnlyList<DomainListItem> Items, int Page, int PageSize, int Total);

public sealed record DomainAuthorizationView(GrantStatus Status, string AttestationVersion, DateTimeOffset AcceptedAt, DateTimeOffset? RevokedAt);

public sealed record DomainEvidenceView(
    Guid Id, VerificationMethod Method, AssuranceLevel Assurance, ScopeCeilingType ScopeCeiling, string Host, EvidenceStatus Status,
    DateTimeOffset EstablishedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? LastValidAt, DateTimeOffset? FailingSince);

/// <summary>A challenge that can still be answered. Instruction is set only for a manager and only for public-proof methods; it is never built from a stored hash.</summary>
public sealed record OpenChallengeView(
    Guid Id, VerificationMethod Method, string Host, ChallengeStatus Status, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt,
    int FailedAttempts, int MaxAttempts, string? Instruction);

public enum DisputeRole { Claimant, Incumbent }

/// <summary>A dispute as one side sees it. It never names the other organization, and the platform administrator's note is not shown.</summary>
public sealed record DomainDisputeView(Guid Id, DisputeRole Role, DisputeStatus Status, DateTimeOffset OpenedAt, DateTimeOffset? ResolvedAt);

public sealed record DomainDetails(
    Guid Id, string Name, DomainStatus Status, DateTimeOffset CreatedAt, Guid CreatedByUserId,
    DomainAuthorizationView? Authorization,
    IReadOnlyList<DomainEvidenceView> Evidence,
    IReadOnlyList<OpenChallengeView> OpenChallenges,
    IReadOnlyList<DomainDisputeView> Disputes);

/// <summary>
/// Read side of the domain pages. Every query is filtered by the actor's organization in the query itself, and a domain
/// of another organization is reported as NotFound, exactly like one that does not exist. Any member (Owner, Admin,
/// Analyst, Viewer) may read; changing things stays with the write services.
/// </summary>
public sealed class DomainQueryService
{
    public const int DefaultPageSize = 50;
    public const int MaxPageSize = 200;
    private const int MaxPage = 100_000;
    private const int MaxEvidenceRows = 50;
    private const int MaxDisputeRows = 20;

    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;

    public DomainQueryService(IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time)
    {
        _factory = factory;
        _time = time;
    }

    public async Task<DomainPage> ListAsync(Actor actor, int page, int pageSize, DomainStatus? status, CancellationToken ct)
    {
        if (page < 1 || page > MaxPage)
            throw new ServiceException("InvalidRequest", "The page must be between 1 and 100000.");
        if (pageSize < 1 || pageSize > MaxPageSize)
            throw new ServiceException("InvalidRequest", $"The page size must be between 1 and {MaxPageSize}.");

        await using var db = await _factory.CreateDbContextAsync(ct);
        await RequireMemberAsync(db, actor, ct);

        IQueryable<Domain> query = db.Domains.AsNoTracking().Where(d => d.OrganizationId == actor.OrganizationId);
        if (status is { } wanted) query = query.Where(d => d.Status == wanted);

        var total = await query.CountAsync(ct);
        var rows = await query
            .OrderBy(d => d.Name).ThenBy(d => d.Id)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .Select(d => new { d.Id, d.Name, d.Status, d.CreatedAt })
            .ToListAsync(ct);

        // One query for the whole page, not one per domain.
        var ids = rows.Select(r => r.Id).ToList();
        var evidence = await db.VerificationEvidence.AsNoTracking()
            .Where(e => ids.Contains(e.DomainId) && (e.Status == EvidenceStatus.Active || e.Status == EvidenceStatus.AtRisk))
            .OrderBy(e => e.EstablishedAt).ThenBy(e => e.Id)
            .Select(e => new { e.DomainId, e.Method, e.Status, e.ExpiresAt })
            .ToListAsync(ct);

        var items = rows.Select(r => new DomainListItem(
            r.Id, r.Name, r.Status, r.CreatedAt,
            evidence.Where(e => e.DomainId == r.Id).Select(e => new DomainEvidenceSummary(e.Method, e.Status, e.ExpiresAt)).ToList())).ToList();

        return new DomainPage(items, page, pageSize, total);
    }

    public async Task<DomainDetails> GetAsync(Actor actor, Guid domainId, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var role = await RequireMemberAsync(db, actor, ct);
        var isManager = role is MembershipRole.Owner or MembershipRole.Admin;

        var domain = await db.Domains.AsNoTracking()
            .Where(d => d.Id == domainId && d.OrganizationId == actor.OrganizationId)
            .Select(d => new { d.Id, d.Name, d.Status, d.CreatedAt, d.CreatedByUserId })
            .SingleOrDefaultAsync(ct)
            ?? throw new ServiceException("NotFound", "Domain not found.");

        var grant = await db.AuthorizationGrants.AsNoTracking()
            .Where(g => g.DomainId == domain.Id)
            .OrderByDescending(g => g.AcceptedAt)
            .Select(g => new { g.Status, g.AttestationTextVersion, g.AcceptedAt, g.RevokedAt })
            .FirstOrDefaultAsync(ct);

        var evidence = await db.VerificationEvidence.AsNoTracking()
            .Where(e => e.DomainId == domain.Id)
            .OrderByDescending(e => e.EstablishedAt).ThenBy(e => e.Id)
            .Take(MaxEvidenceRows)
            .Select(e => new DomainEvidenceView(e.Id, e.Method, e.Assurance, e.ScopeCeilingType, e.Host, e.Status,
                e.EstablishedAt, e.ExpiresAt, e.LastValidAt, e.FailingSince))
            .ToListAsync(ct);

        var now = _time.GetUtcNow();
        var openRows = await db.VerificationChallenges.AsNoTracking()
            .Where(c => c.DomainId == domain.Id
                        && (c.Status == ChallengeStatus.Issued || c.Status == ChallengeStatus.Checking)
                        && c.ExpiresAt > now)
            .OrderBy(c => c.IssuedAt).ThenBy(c => c.Id)
            .Select(c => new
            {
                c.Id, c.Method, c.Host, c.Status, c.IssuedAt, c.ExpiresAt, c.MaxAttempts,
                // A stored hash (admin email) is never read out of the database here.
                PublicToken = c.TokenIsHashed ? null : c.Token,
                FailedAttempts = c.Attempts.Count(a => a.Result == CheckOutcome.ProofAbsent)
            })
            .ToListAsync(ct);

        var open = openRows.Select(c => new OpenChallengeView(
            c.Id, c.Method, c.Host, c.Status, c.IssuedAt, c.ExpiresAt, c.FailedAttempts, c.MaxAttempts,
            isManager && c.PublicToken is not null && MethodTraits.IsObservable(c.Method)
                ? ChallengeService.Instruction(c.Method, c.Host, c.PublicToken)
                : null)).ToList();

        var thisDomain = domain.Id;
        var disputeRows = await db.DomainDisputes.AsNoTracking()
            .Where(d => d.IncumbentDomainId == thisDomain || d.ClaimantDomainId == thisDomain)
            .OrderByDescending(d => d.OpenedAt).ThenBy(d => d.Id)
            .Take(MaxDisputeRows)
            .Select(d => new { d.Id, IsClaimant = d.ClaimantDomainId == thisDomain, d.Status, d.OpenedAt, d.ResolvedAt })
            .ToListAsync(ct);
        var disputes = disputeRows
            .Select(d => new DomainDisputeView(d.Id, d.IsClaimant ? DisputeRole.Claimant : DisputeRole.Incumbent, d.Status, d.OpenedAt, d.ResolvedAt))
            .ToList();

        return new DomainDetails(
            domain.Id, domain.Name, domain.Status, domain.CreatedAt, domain.CreatedByUserId,
            grant is null ? null : new DomainAuthorizationView(grant.Status, grant.AttestationTextVersion, grant.AcceptedAt, grant.RevokedAt),
            evidence, open, disputes);
    }

    /// <summary>The caller must belong to the actor's organization. Reading does not need the organization to be active.</summary>
    private static async Task<MembershipRole> RequireMemberAsync(CipherSurfaceDbContext db, Actor actor, CancellationToken ct)
    {
        var membership = await db.Memberships.AsNoTracking()
            .Where(m => m.OrganizationId == actor.OrganizationId && m.UserId == actor.UserId)
            .Select(m => new { m.Role })
            .SingleOrDefaultAsync(ct);
        return membership?.Role ?? throw new ServiceException("NotAllowed", "You are not a member of this organization.");
    }
}
