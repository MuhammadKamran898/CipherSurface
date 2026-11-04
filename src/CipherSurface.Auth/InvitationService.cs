using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace CipherSurface.Auth;

/// <summary>The invitation as a manager sees it. There is no token and no token hash here, ever.</summary>
public sealed record InvitationView(Guid Id, string Email, MembershipRole Role, InvitationState State, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, Guid CreatedByUserId);

/// <summary>Pending and Expired are derived: an invitation stays Pending in the database and is Expired once its time has passed.</summary>
public enum InvitationState { Pending, Expired, Accepted, Revoked, Superseded }

/// <summary>What the person who issues an invitation receives. The raw token appears here and nowhere else.</summary>
public sealed record InvitationIssued(Guid InvitationId, string Email, MembershipRole Role, DateTimeOffset ExpiresAt, string Token);

/// <summary>What someone who opens the link may see before deciding. Opening never changes anything.</summary>
public sealed record InvitationPreview(string OrganizationName, string Email, MembershipRole Role, DateTimeOffset ExpiresAt, bool AccountExists);

public sealed record InvitationAccepted(Guid UserId, Guid OrganizationId, MembershipRole Role, bool NewAccount);

/// <summary>
/// Invitation-only membership. Owners and Admins invite an email as Admin, Analyst or Viewer (never Owner: the first
/// Owner comes from setup). The invitation carries a one-time token whose SHA-256 hash is all the database keeps.
///
/// Everything that changes one (organization, email) pair runs in a transaction under one advisory lock for that pair, so
/// issuing, revoking and accepting cannot interleave. Issuing also takes an organization-wide lock first, because the
/// limit on open invitations spans emails. Locks are always taken in one order (organization, then pair, then account
/// email), so they cannot deadlock. Acceptance re-reads the invitation under that lock and re-checks
/// its status, expiry, the organization and that the inviter may still invite. Accepting never marks an email verified:
/// there is no email provider, so nothing has proven the person controls the mailbox beyond holding the token.
/// Scoped: it shares the request's database context with Identity so a new account and its membership are one transaction.
/// </summary>
public sealed class InvitationService
{
    private static readonly MembershipRole[] Invitable = [MembershipRole.Admin, MembershipRole.Analyst, MembershipRole.Viewer];
    private const int MaxTokenLength = 256;

    private readonly CipherSurfaceDbContext _db;
    private readonly UserManager<User> _users;
    private readonly AuditLogWriter _audit;
    private readonly TimeProvider _time;
    private readonly InvitationOptions _options;

    public InvitationService(CipherSurfaceDbContext db, UserManager<User> users, AuditLogWriter audit, TimeProvider time, InvitationOptions options)
    {
        if (options.Lifetime < InvitationOptions.MinLifetime || options.Lifetime > InvitationOptions.MaxLifetime)
            throw new ArgumentOutOfRangeException(nameof(options), "The invitation lifetime must be between 1 and 30 days.");
        if (options.MaxPendingPerOrganization < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "At least one open invitation must be allowed.");

        _db = db;
        _users = users;
        _audit = audit;
        _time = time;
        _options = options;
    }

    // ------------------------------------------------------------------ issue

    /// <summary>
    /// Invites an email to the actor's organization. An earlier pending invitation for the same email (expired or not) is
    /// superseded in the same transaction, so its token stops working.
    /// </summary>
    public async Task<InvitationIssued> IssueAsync(Actor actor, string? email, MembershipRole role, CancellationToken ct)
    {
        try
        {
            await Access.RequireManagerAsync(_db, actor, ct);
            if (!Invitable.Contains(role))
                throw new ServiceException("InvalidRole", "You can invite someone as an Admin, Analyst or Viewer.");
            var normalized = AccountService.NormalizeEmail(email);
            var now = _time.GetUtcNow();

            await using var tx = await _db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(_db, OrganizationLock(actor.OrganizationId), ct);   // the limit is organization-wide
            await DbLocks.AcquireAsync(_db, PairLock(actor.OrganizationId, normalized), ct);
            await Access.RequireManagerAsync(_db, actor, ct);   // again, under the locks

            var existingUser = await _db.Users.AsNoTracking().Where(u => u.Email == normalized).Select(u => (Guid?)u.Id).SingleOrDefaultAsync(ct);
            if (existingUser is { } userId
                && await _db.Memberships.AsNoTracking().AnyAsync(m => m.OrganizationId == actor.OrganizationId && m.UserId == userId, ct))
                throw new ServiceException("AlreadyMember", "This person is already a member of the organization.");

            var open = await _db.Invitations
                .Where(i => i.OrganizationId == actor.OrganizationId && i.Status == InvitationStatus.Pending)
                .ToListAsync(ct);
            var earlier = open.SingleOrDefault(i => i.Email == normalized);
            if (open.Count(i => i.Email != normalized && i.ExpiresAt > now) >= _options.MaxPendingPerOrganization)
                throw new ServiceException("TooManyInvitations", $"An organization can have at most {_options.MaxPendingPerOrganization} open invitations. Revoke one first.");

            // The old invitation has to stop being Pending before the new one is inserted (one pending per email).
            if (earlier is not null)
            {
                earlier.Status = InvitationStatus.Superseded;
                earlier.ResolvedAt = now;
                earlier.ResolvedByUserId = actor.UserId;
                await _db.SaveChangesAsync(ct);
            }

            var token = OpaqueTokens.New();
            var invitation = new Invitation
            {
                Id = Guid.NewGuid(),
                OrganizationId = actor.OrganizationId,
                Email = normalized,
                Role = role,
                TokenHash = OpaqueTokens.Hash(token),
                Status = InvitationStatus.Pending,
                CreatedByUserId = actor.UserId,
                CreatedAt = now,
                ExpiresAt = now + _options.Lifetime
            };
            _db.Invitations.Add(invitation);
            await _db.SaveChangesAsync(ct);

            var detail = new Dictionary<string, object?>
            {
                ["email"] = normalized,
                ["role"] = role.ToString(),
                ["expiresAt"] = invitation.ExpiresAt.ToString("O")
            };
            if (earlier is not null) detail["supersededInvitationId"] = earlier.Id.ToString("D");
            await _audit.AppendAsync(_db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "invitation.created", "Invitation", invitation.Id, detail, actor.Ip), ct);

            await tx.CommitAsync(ct);
            return new InvitationIssued(invitation.Id, normalized, role, invitation.ExpiresAt, token);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw Busy();
        }
    }

    // ------------------------------------------------------------------ revoke and list

    /// <summary>Cancels a pending invitation, so its token stops working.</summary>
    public async Task RevokeAsync(Actor actor, Guid invitationId, CancellationToken ct)
    {
        try
        {
            await Access.RequireManagerAsync(_db, actor, ct);
            // Only an invitation of the actor's own organization is visible. Another organization's id looks missing.
            var found = await _db.Invitations.AsNoTracking()
                .Where(i => i.Id == invitationId && i.OrganizationId == actor.OrganizationId)
                .Select(i => new { i.Email })
                .SingleOrDefaultAsync(ct) ?? throw new ServiceException("NotFound", "Invitation not found.");

            await using var tx = await _db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(_db, PairLock(actor.OrganizationId, found.Email), ct);
            await Access.RequireManagerAsync(_db, actor, ct);

            var invitation = await _db.Invitations.SingleAsync(i => i.Id == invitationId, ct);
            if (invitation.Status != InvitationStatus.Pending)
                throw NotPending();

            invitation.Status = InvitationStatus.Revoked;
            invitation.ResolvedAt = _time.GetUtcNow();
            invitation.ResolvedByUserId = actor.UserId;
            await _db.SaveChangesAsync(ct);

            await _audit.AppendAsync(_db, new AuditEntry(actor.OrganizationId, "User", actor.UserId, "invitation.revoked", "Invitation", invitation.Id,
                new Dictionary<string, object?> { ["email"] = invitation.Email, ["role"] = invitation.Role.ToString() }, actor.Ip), ct);

            await tx.CommitAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw Busy();
        }
    }

    /// <summary>The organization's most recent invitations (200 at most), newest first.</summary>
    public async Task<IReadOnlyList<InvitationView>> ListAsync(Actor actor, CancellationToken ct)
    {
        await Access.RequireManagerAsync(_db, actor, ct);
        var now = _time.GetUtcNow();
        var rows = await _db.Invitations.AsNoTracking()
            .Where(i => i.OrganizationId == actor.OrganizationId)
            .OrderByDescending(i => i.CreatedAt).ThenBy(i => i.Id)
            .Take(200)
            .ToListAsync(ct);
        return rows.Select(i => new InvitationView(i.Id, i.Email, i.Role, StateOf(i, now), i.CreatedAt, i.ExpiresAt, i.CreatedByUserId)).ToList();
    }

    // ------------------------------------------------------------------ preview

    /// <summary>What the link is for. Read-only: looking never consumes the invitation.</summary>
    public async Task<InvitationPreview> PreviewAsync(string? token, CancellationToken ct)
    {
        var invitation = await FindByTokenAsync(token, ct);
        var now = _time.GetUtcNow();
        if (invitation.Status != InvitationStatus.Pending) throw NotPending();
        if (now >= invitation.ExpiresAt) throw Expired();

        var organization = await _db.Organizations.AsNoTracking().Where(o => o.Id == invitation.OrganizationId).Select(o => o.Name).SingleAsync(ct);
        var accountExists = await _db.Users.AsNoTracking().AnyAsync(u => u.Email == invitation.Email, ct);
        return new InvitationPreview(organization, invitation.Email, invitation.Role, invitation.ExpiresAt, accountExists);
    }

    // ------------------------------------------------------------------ accept

    /// <summary>
    /// Accepts as a brand-new person: creates the account for the invited email with the chosen password, adds the
    /// membership and consumes the invitation, all in one transaction. The email is NOT marked verified.
    /// </summary>
    public async Task<InvitationAccepted> AcceptAsNewAccountAsync(string? token, string? password, string? ip, CancellationToken ct)
    {
        try
        {
            var found = await FindByTokenAsync(token, ct);

            await using var tx = await _db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(_db, PairLock(found.OrganizationId, found.Email), ct);
            await DbLocks.AcquireAsync(_db, AccountLock(found.Email), ct);   // always after the pair lock: one global order

            var invitation = await _db.Invitations.SingleAsync(i => i.Id == found.Id, ct);
            var now = _time.GetUtcNow();
            await RequireAcceptableAsync(invitation, now, ct);

            if (await _db.Users.AsNoTracking().AnyAsync(u => u.Email == invitation.Email, ct))
                throw new ServiceException("AccountExists", "An account with this email already exists. Sign in to accept the invitation.");

            var user = new User { Id = Guid.NewGuid(), UserName = invitation.Email, Email = invitation.Email, EmailConfirmed = false, Status = UserStatus.Active, CreatedAt = now };
            var created = await _users.CreateAsync(user, password ?? string.Empty);
            if (!created.Succeeded) throw AccountService.Translate(created);

            await CompleteAsync(invitation, user.Id, now, newAccount: true, ip, ct);
            await tx.CommitAsync(ct);
            return new InvitationAccepted(user.Id, invitation.OrganizationId, invitation.Role, NewAccount: true);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw Busy();
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw new ServiceException("AccountExists", "An account with this email already exists. Sign in to accept the invitation.");
        }
    }

    /// <summary>
    /// Accepts as an existing, signed-in account. The account's email must be the invited email, and the account must not
    /// already belong to the organization.
    /// </summary>
    public async Task<InvitationAccepted> AcceptAsExistingAccountAsync(Guid userId, string? token, string? ip, CancellationToken ct)
    {
        try
        {
            var found = await FindByTokenAsync(token, ct);

            await using var tx = await _db.Database.BeginTransactionAsync(ct);
            await DbLocks.AcquireAsync(_db, PairLock(found.OrganizationId, found.Email), ct);

            var invitation = await _db.Invitations.SingleAsync(i => i.Id == found.Id, ct);
            var now = _time.GetUtcNow();
            await RequireAcceptableAsync(invitation, now, ct);

            var user = await _db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == userId, ct)
                       ?? throw new ServiceException("Unauthorized", "Authentication is required.");
            if (user.Status != UserStatus.Active)
                throw new ServiceException("AccountDisabled", "This account is disabled.");
            if (!string.Equals(user.Email?.Trim(), invitation.Email, StringComparison.OrdinalIgnoreCase))
                throw new ServiceException("InvitationEmailMismatch", "This invitation was sent to a different email address.");
            if (await _db.Memberships.AsNoTracking().AnyAsync(m => m.OrganizationId == invitation.OrganizationId && m.UserId == userId, ct))
                throw new ServiceException("AlreadyMember", "You are already a member of this organization.");

            await CompleteAsync(invitation, userId, now, newAccount: false, ip, ct);
            await tx.CommitAsync(ct);
            return new InvitationAccepted(userId, invitation.OrganizationId, invitation.Role, NewAccount: false);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw Busy();
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw new ServiceException("AlreadyMember", "You are already a member of this organization.");
        }
    }

    // ------------------------------------------------------------------ helpers

    private static string OrganizationLock(Guid organizationId) => $"invitations:{organizationId:D}";
    private static string PairLock(Guid organizationId, string email) => $"invitations:{organizationId:D}:{email}";
    private static string AccountLock(string email) => $"account-email:{email}";

    private async Task<Invitation> FindByTokenAsync(string? token, CancellationToken ct)
    {
        var presented = (token ?? string.Empty).Trim();
        if (presented.Length is 0 or > MaxTokenLength)
            throw InvalidInvitation();

        var hash = OpaqueTokens.Hash(presented);
        return await _db.Invitations.AsNoTracking().SingleOrDefaultAsync(i => i.TokenHash == hash, ct) ?? throw InvalidInvitation();
    }

    /// <summary>
    /// The checks that must hold at the moment of acceptance, inside the transaction and under the lock: the invitation is
    /// still pending and unexpired, the organization is active, and whoever issued it may still invite.
    /// </summary>
    private async Task RequireAcceptableAsync(Invitation invitation, DateTimeOffset now, CancellationToken ct)
    {
        if (invitation.Status != InvitationStatus.Pending) throw NotPending();
        if (now >= invitation.ExpiresAt) throw Expired();

        var status = await _db.Organizations.AsNoTracking().Where(o => o.Id == invitation.OrganizationId).Select(o => o.Status).SingleAsync(ct);
        if (status != OrganizationStatus.Active)
            throw new ServiceException("OrganizationSuspended", "This organization is suspended.");

        var inviterMayStillInvite =
            await _db.Memberships.AsNoTracking().AnyAsync(m => m.OrganizationId == invitation.OrganizationId && m.UserId == invitation.CreatedByUserId
                                                               && (m.Role == MembershipRole.Owner || m.Role == MembershipRole.Admin), ct)
            && await _db.Users.AsNoTracking().AnyAsync(u => u.Id == invitation.CreatedByUserId && u.Status == UserStatus.Active, ct);
        if (!inviterMayStillInvite)
            throw new ServiceException("InvitationNoLongerValid", "This invitation is no longer valid. Ask for a new one.");
    }

    private async Task CompleteAsync(Invitation invitation, Guid userId, DateTimeOffset now, bool newAccount, string? ip, CancellationToken ct)
    {
        _db.Memberships.Add(new Membership
        {
            Id = Guid.NewGuid(),
            OrganizationId = invitation.OrganizationId,
            UserId = userId,
            Role = invitation.Role,
            CreatedAt = now
        });
        invitation.Status = InvitationStatus.Accepted;
        invitation.ResolvedAt = now;
        invitation.ResolvedByUserId = userId;
        await _db.SaveChangesAsync(ct);

        await _audit.AppendAsync(_db, new AuditEntry(invitation.OrganizationId, "User", userId, "invitation.accepted", "Invitation", invitation.Id,
            new Dictionary<string, object?> { ["role"] = invitation.Role.ToString(), ["newAccount"] = newAccount }, ip), ct);
    }

    private static InvitationState StateOf(Invitation invitation, DateTimeOffset now) => invitation.Status switch
    {
        InvitationStatus.Accepted => InvitationState.Accepted,
        InvitationStatus.Revoked => InvitationState.Revoked,
        InvitationStatus.Superseded => InvitationState.Superseded,
        _ => now >= invitation.ExpiresAt ? InvitationState.Expired : InvitationState.Pending
    };

    private static ServiceException InvalidInvitation() => new("InvalidInvitation", "This invitation link is not valid.");
    private static ServiceException Expired() => new("InvitationExpired", "This invitation has expired. Ask for a new one.");
    private static ServiceException NotPending() => new("InvitationNotPending", "This invitation was already used, revoked or replaced.");
    private static ServiceException Busy() => new("Busy", "The invitation was changed at the same time. Try again.");
}
