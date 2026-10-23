using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

/// <summary>Decides, on the server, who is a platform administrator (a role claim, a configured list, a database flag).</summary>
public interface IPlatformAdminPolicy
{
    Task<bool> IsPlatformAdminAsync(Guid userId, CancellationToken ct);
}

public sealed class ConfiguredPlatformAdminPolicy : IPlatformAdminPolicy
{
    private readonly HashSet<Guid> _userIds;
    public ConfiguredPlatformAdminPolicy(IEnumerable<Guid> userIds) => _userIds = new HashSet<Guid>(userIds);
    public Task<bool> IsPlatformAdminAsync(Guid userId, CancellationToken ct) => Task.FromResult(_userIds.Contains(userId));
}

/// <summary>
/// Proof that the server checked this user is a platform administrator. The constructor is internal,
/// so the only way to get one is PlatformAdminGate.AuthorizeAsync, which asks the policy. A caller can
/// never declare itself an administrator.
/// </summary>
public sealed class PlatformAdmin
{
    public Guid UserId { get; }
    internal PlatformAdmin(Guid userId) => UserId = userId;
}

public sealed class PlatformAdminGate
{
    private readonly IPlatformAdminPolicy _policy;
    public PlatformAdminGate(IPlatformAdminPolicy policy) => _policy = policy;

    /// <param name="authenticatedUserId">The id from the verified login token, never from request data.</param>
    public async Task<PlatformAdmin> AuthorizeAsync(Guid authenticatedUserId, CancellationToken ct)
    {
        if (authenticatedUserId == Guid.Empty || !await _policy.IsPlatformAdminAsync(authenticatedUserId, ct))
            throw new ServiceException("NotAllowed", "Platform administrators only.");
        return new PlatformAdmin(authenticatedUserId);
    }
}

public enum DisputeResolution { IncumbentWins, ClaimantWins }

public sealed record DisputeResolutionResult(Guid DisputeId, DisputeStatus Status, DomainStatus IncumbentStatus, DomainStatus ClaimantStatus);

public sealed record DisputeSummary(
    Guid DisputeId, string DomainName,
    Guid IncumbentOrganizationId, string IncumbentOrganizationName, Guid IncumbentDomainId, DomainStatus IncumbentStatus,
    Guid ClaimantOrganizationId, string ClaimantOrganizationName, Guid ClaimantDomainId,
    DateTimeOffset OpenedAt);

/// <summary>
/// Resolves competing ownership claims. Every resolution runs in one transaction under the same advisory
/// lock on the domain NAME that claim completion uses, so it can never interleave with a new claim.
/// The name is freed (the loser's evidence is revoked and its domain recalculated) BEFORE the winner is
/// recalculated, because the database allows only one Verified/AtRisk holder per name.
/// </summary>
public sealed class DisputeService
{
    private const int MaxNoteLength = 2000;
    private const string AutoNote = "Automatic takeover: the previous holder's proof lapsed.";

    private readonly IDbContextFactory<CipherSurfaceDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly AuditLogWriter _audit;

    public DisputeService(IDbContextFactory<CipherSurfaceDbContext> factory, TimeProvider time, AuditLogWriter audit)
    {
        _factory = factory;
        _time = time;
        _audit = audit;
    }

    public async Task<IReadOnlyList<DisputeSummary>> ListOpenAsync(PlatformAdmin admin, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(admin);
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.DomainDisputes.AsNoTracking()
            .Where(d => d.Status == DisputeStatus.Open)
            .OrderBy(d => d.OpenedAt)
            .Select(d => new DisputeSummary(
                d.Id, d.ClaimantDomain.Name,
                d.IncumbentDomain.OrganizationId, d.IncumbentDomain.Organization.Name, d.IncumbentDomainId, d.IncumbentDomain.Status,
                d.ClaimantDomain.OrganizationId, d.ClaimantDomain.Organization.Name, d.ClaimantDomainId,
                d.OpenedAt))
            .ToListAsync(ct);
    }

    /// <summary>A platform administrator decides a dispute in either direction. A note is required.</summary>
    public async Task<DisputeResolutionResult> ResolveAsync(PlatformAdmin admin, Guid disputeId, DisputeResolution resolution, string note, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(admin);
        if (string.IsNullOrWhiteSpace(note))
            throw new ServiceException("NoteRequired", "Explain the decision in a note.");
        if (note.Length > MaxNoteLength)
            throw new ServiceException("NoteTooLong", $"The note can be at most {MaxNoteLength} characters.");

        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            var name = await db.DomainDisputes.Where(d => d.Id == disputeId).Select(d => d.ClaimantDomain.Name).SingleOrDefaultAsync(ct)
                       ?? throw new ServiceException("NotFound", "Dispute not found.");

            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(db, $"domain:{name}", ct);

            var dispute = await LoadAsync(db, disputeId, ct)
                          ?? throw new ServiceException("NotFound", "Dispute not found.");
            if (dispute.Status != DisputeStatus.Open)
                throw new ServiceException("DisputeNotOpen", "This dispute was already resolved.");

            var result = await ApplyAsync(db, dispute, resolution, admin.UserId, "PlatformAdmin", note.Trim(), ct);
            await tx.CommitAsync(ct);
            return result;
        }
        catch (DbUpdateConcurrencyException)
        {
            throw new ServiceException("Busy", "This dispute is being changed right now. Try again.");
        }
    }

    /// <summary>
    /// The claimant takes over when the holder's proof is gone (the holder is no longer Verified or AtRisk)
    /// and the claimant has valid proof of its own. Safe to run repeatedly. Returns how many were resolved.
    /// </summary>
    public async Task<int> AutoResolveAsync(CancellationToken ct)
    {
        List<Guid> candidates;
        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            candidates = await db.DomainDisputes
                .Where(d => d.Status == DisputeStatus.Open
                            && d.IncumbentDomain.Status != DomainStatus.Verified
                            && d.IncumbentDomain.Status != DomainStatus.AtRisk)
                .OrderBy(d => d.OpenedAt)
                .Select(d => d.Id)
                .ToListAsync(ct);
        }

        var resolved = 0;
        foreach (var id in candidates)
        {
            try
            {
                if (await TryAutoResolveAsync(id, ct)) resolved++;
            }
            catch (DbUpdateConcurrencyException)
            {
                // changed under us: the next run decides
            }
        }
        return resolved;
    }

    private async Task<bool> TryAutoResolveAsync(Guid disputeId, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var name = await db.DomainDisputes.Where(d => d.Id == disputeId).Select(d => d.ClaimantDomain.Name).SingleOrDefaultAsync(ct);
        if (name is null) return false;

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DbLocks.AcquireAsync(db, $"domain:{name}", ct);

        // Everything is re-checked under the lock: another resolution or a new claim may have just run.
        var dispute = await LoadAsync(db, disputeId, ct);
        if (dispute is null || dispute.Status != DisputeStatus.Open) return false;

        // If anyone currently holds the name, the claimant must not take over. When that holder is not the
        // dispute's original incumbent (a newcomer verified after the incumbent lapsed), the dispute now
        // faces the newcomer, and that change is audited.
        var holder = await db.Domains
            .Where(d => d.Name == name && d.Id != dispute.ClaimantDomainId
                        && (d.Status == DomainStatus.Verified || d.Status == DomainStatus.AtRisk))
            .FirstOrDefaultAsync(ct);
        if (holder is not null)
        {
            if (holder.Id != dispute.IncumbentDomainId)
            {
                var entries = RetargetEntries(dispute, dispute.IncumbentDomainId, holder, null, "System", null).ToList();
                dispute.IncumbentDomainId = holder.Id;
                await db.SaveChangesAsync(ct);
                await AppendInFixedOrderAsync(db, entries, ct);
                await tx.CommitAsync(ct);
            }
            return false;
        }

        if (dispute.ClaimantDomain.Status != DomainStatus.Disputed) return false;
        var claimantHasValidProof = await db.VerificationEvidence
            .AnyAsync(e => e.DomainId == dispute.ClaimantDomainId && e.Status == EvidenceStatus.Active, ct);
        if (!claimantHasValidProof) return false;

        await ApplyAsync(db, dispute, DisputeResolution.ClaimantWins, null, "System", AutoNote, ct);
        await tx.CommitAsync(ct);
        return true;
    }

    private static Task<DomainDispute?> LoadAsync(CipherSurfaceDbContext db, Guid disputeId, CancellationToken ct) =>
        db.DomainDisputes.Include(d => d.IncumbentDomain).Include(d => d.ClaimantDomain)
            .SingleOrDefaultAsync(d => d.Id == disputeId, ct);

    private async Task<DisputeResolutionResult> ApplyAsync(
        CipherSurfaceDbContext db, DomainDispute dispute, DisputeResolution resolution,
        Guid? resolvedBy, string actorType, string note, CancellationToken ct)
    {
        var incumbent = dispute.IncumbentDomain;
        var claimant = dispute.ClaimantDomain;
        var now = _time.GetUtcNow();
        var pending = new List<AuditEntry>();
        int revoked;

        if (resolution == DisputeResolution.ClaimantWins)
        {
            // A claimant with no valid proof cannot be made the holder.
            var hasValidProof = await db.VerificationEvidence
                .AnyAsync(e => e.DomainId == claimant.Id && e.Status == EvidenceStatus.Active, ct);
            if (!hasValidProof)
                throw new ServiceException("ClaimantHasNoValidProof", "The claimant has no valid proof. It must verify again first.");

            // The database allows one Verified/AtRisk holder per name, so EVERY current holder must lose its
            // proof first: the dispute's incumbent and anyone who became holder since the dispute opened.
            var losers = await db.Domains
                .Where(d => d.Name == claimant.Name && d.Id != claimant.Id
                            && (d.Status == DomainStatus.Verified || d.Status == DomainStatus.AtRisk))
                .ToListAsync(ct);
            if (losers.All(d => d.Id != incumbent.Id)) losers.Add(incumbent);

            revoked = 0;
            foreach (var loser in losers) revoked += await RevokeEvidenceAsync(db, loser.Id, ct);
            Close(dispute, DisputeStatus.ResolvedClaimant, now, resolvedBy, note);
            await db.SaveChangesAsync(ct);

            foreach (var loser in losers) await DomainStatusService.RecalculateAsync(db, loser, ct);   // frees the name

            // Other open claims against a loser now face the new holder. Each change is audited.
            var loserIds = losers.Select(l => l.Id).ToList();
            var others = await db.DomainDisputes.Include(d => d.ClaimantDomain)
                .Where(d => d.Status == DisputeStatus.Open && loserIds.Contains(d.IncumbentDomainId)
                            && d.Id != dispute.Id && d.ClaimantDomainId != claimant.Id)
                .ToListAsync(ct);
            foreach (var other in others)
            {
                pending.AddRange(RetargetEntries(other, other.IncumbentDomainId, claimant, dispute.Id, actorType, resolvedBy));
                other.IncumbentDomainId = claimant.Id;
            }
            if (others.Count > 0) await db.SaveChangesAsync(ct);

            await DomainStatusService.RecalculateAsync(db, claimant, ct);                              // Verified
        }
        else
        {
            revoked = await RevokeEvidenceAsync(db, claimant.Id, ct);
            Close(dispute, DisputeStatus.ResolvedIncumbent, now, resolvedBy, note);
            await db.SaveChangesAsync(ct);
            await DomainStatusService.RecalculateAsync(db, claimant, ct);                              // Lapsed: a new challenge is needed
        }

        foreach (var orgId in new[] { incumbent.OrganizationId, claimant.OrganizationId }.Distinct())
        {
            pending.Add(new AuditEntry(orgId, actorType, resolvedBy, "dispute.resolved", "DomainDispute", dispute.Id,
                new Dictionary<string, object?>
                {
                    ["domain"] = claimant.Name,
                    ["resolution"] = resolution.ToString(),
                    ["note"] = note,
                    ["revokedEvidence"] = revoked,
                    ["incumbentDomainId"] = incumbent.Id.ToString("D"),
                    ["claimantDomainId"] = claimant.Id.ToString("D")
                }));
        }

        await AppendInFixedOrderAsync(db, pending, ct);
        return new DisputeResolutionResult(dispute.Id, dispute.Status, incumbent.Status, claimant.Status);
    }

    /// <summary>One entry in the chain of each organization affected when a claim is pointed at a new holder.</summary>
    private static IEnumerable<AuditEntry> RetargetEntries(
        DomainDispute disputed, Guid previousIncumbentDomainId, Domain newHolder, Guid? causedByDispute, string actorType, Guid? actorId)
    {
        foreach (var orgId in new[] { disputed.ClaimantDomain.OrganizationId, newHolder.OrganizationId }.Distinct())
        {
            yield return new AuditEntry(orgId, actorType, actorId, "dispute.retargeted", "DomainDispute", disputed.Id,
                new Dictionary<string, object?>
                {
                    ["domain"] = newHolder.Name,
                    ["previousIncumbentDomainId"] = previousIncumbentDomainId.ToString("D"),
                    ["newIncumbentDomainId"] = newHolder.Id.ToString("D"),
                    ["causedByDispute"] = causedByDispute?.ToString("D")
                });
        }
    }

    /// <summary>Always appends in the same organization order, so concurrent resolutions cannot deadlock on audit locks.</summary>
    private async Task AppendInFixedOrderAsync(CipherSurfaceDbContext db, IEnumerable<AuditEntry> entries, CancellationToken ct)
    {
        foreach (var entry in entries.OrderBy(e => e.OrganizationId))
            await _audit.AppendAsync(db, entry, ct);
    }

    private static void Close(DomainDispute dispute, DisputeStatus status, DateTimeOffset now, Guid? resolvedBy, string note)
    {
        dispute.Status = status;
        dispute.ResolvedAt = now;
        dispute.ResolvedByUserId = resolvedBy;
        dispute.Note = note;
    }

    private static async Task<int> RevokeEvidenceAsync(CipherSurfaceDbContext db, Guid domainId, CancellationToken ct)
    {
        var live = await db.VerificationEvidence
            .Where(e => e.DomainId == domainId && (e.Status == EvidenceStatus.Active || e.Status == EvidenceStatus.AtRisk))
            .ToListAsync(ct);
        foreach (var evidence in live) evidence.Status = EvidenceStatus.Revoked;
        return live.Count;
    }
}
