using System.Net.Mail;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using CipherSurface.Data.Enums;
using CipherSurface.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Auth;

public sealed record AuthTokens(string AccessToken, DateTimeOffset AccessTokenExpiresAt, string RefreshToken, DateTimeOffset RefreshTokenExpiresAt);
public sealed record RegistrationResult(Guid UserId, Guid OrganizationId);

/// <summary>
/// Registration, login, refresh, logout and password change, on top of ASP.NET Core Identity (password hashing and lockout)
/// and the CipherSurface token services. Scoped: it shares the request's database context with Identity's stores so that
/// registration (user, organization, Owner membership) is one transaction.
/// </summary>
public sealed class AccountService
{
    private readonly CipherSurfaceDbContext _db;
    private readonly UserManager<User> _users;
    private readonly AccessTokenService _accessTokens;
    private readonly RefreshTokenService _refreshTokens;
    private readonly AuditLogWriter _audit;
    private readonly TimeProvider _time;
    private readonly string _dummyHash;

    public AccountService(
        CipherSurfaceDbContext db, UserManager<User> users, AccessTokenService accessTokens,
        RefreshTokenService refreshTokens, AuditLogWriter audit, TimeProvider time)
    {
        _db = db;
        _users = users;
        _accessTokens = accessTokens;
        _refreshTokens = refreshTokens;
        _audit = audit;
        _time = time;
        // Used to spend the same time on an unknown email as on a wrong password.
        _dummyHash = _users.PasswordHasher.HashPassword(new User(), Guid.NewGuid().ToString("N"));
    }

    // ------------------------------------------------------------------ register

    /// <summary>Creates the account, its organization and the Owner membership in one transaction.</summary>
    public Task<RegistrationResult> RegisterAsync(string? email, string? password, string? organizationName, CancellationToken ct) =>
        RegisterCoreAsync(email, password, organizationName, onlyIfNoUsersExist: false, ct);

    /// <summary>
    /// Controlled setup: creates the very first account and its organization, and only while no account exists at all.
    /// Two simultaneous calls cannot both win. Once any account exists this always fails with SetupClosed, so the
    /// setup path cannot be used to open registration. Callers must authenticate the setup request themselves.
    /// </summary>
    public Task<RegistrationResult> RegisterFirstOwnerAsync(string? email, string? password, string? organizationName, CancellationToken ct) =>
        RegisterCoreAsync(email, password, organizationName, onlyIfNoUsersExist: true, ct);

    private async Task<RegistrationResult> RegisterCoreAsync(string? email, string? password, string? organizationName, bool onlyIfNoUsersExist, CancellationToken ct)
    {
        var normalizedEmail = NormalizeEmail(email);
        var orgName = (organizationName ?? string.Empty).Trim();
        if (orgName.Length == 0) throw new ServiceException("OrganizationNameRequired", "Enter your organization's name.");
        if (orgName.Length > 200) throw new ServiceException("OrganizationNameTooLong", "The organization name can be at most 200 characters.");

        var now = _time.GetUtcNow();
        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        if (onlyIfNoUsersExist)
        {
            await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtextextended({"setup:first-owner"}, 0))", ct);
            if (await _db.Users.AnyAsync(ct))
                throw new ServiceException("SetupClosed", "Setup is already complete.");
        }

        var user = new User { Id = Guid.NewGuid(), UserName = normalizedEmail, Email = normalizedEmail, Status = UserStatus.Active, CreatedAt = now };
        var created = await _users.CreateAsync(user, password ?? string.Empty);
        if (!created.Succeeded) throw Translate(created);

        var organization = new Organization { Id = Guid.NewGuid(), Name = orgName, Status = OrganizationStatus.Active, CreatedAt = now };
        _db.Organizations.Add(organization);
        await _db.SaveChangesAsync(ct);
        _db.Memberships.Add(new Membership { Id = Guid.NewGuid(), OrganizationId = organization.Id, UserId = user.Id, Role = MembershipRole.Owner, CreatedAt = now });
        await _db.SaveChangesAsync(ct);

        var detail = new Dictionary<string, object?> { ["name"] = orgName };
        if (onlyIfNoUsersExist) detail["setup"] = "first-owner";
        await _audit.AppendAsync(_db, new AuditEntry(organization.Id, "User", user.Id, "organization.created", "Organization", organization.Id, detail), ct);
        await tx.CommitAsync(ct);
        return new RegistrationResult(user.Id, organization.Id);
    }

    // ------------------------------------------------------------------ login, refresh, logout

    public async Task<AuthTokens> LoginAsync(string? email, string? password, string ip, CancellationToken ct)
    {
        var normalized = (email ?? string.Empty).Trim().ToLowerInvariant();
        var user = normalized.Length == 0 ? null : await _users.FindByEmailAsync(normalized);
        if (user is null)
        {
            _users.PasswordHasher.VerifyHashedPassword(new User(), _dummyHash, password ?? string.Empty);   // same cost as a real check
            throw InvalidCredentials();
        }

        if (await _users.IsLockedOutAsync(user)) throw LockedOut();
        if (!await _users.CheckPasswordAsync(user, password ?? string.Empty))
        {
            await _users.AccessFailedAsync(user);
            throw await _users.IsLockedOutAsync(user) ? LockedOut() : InvalidCredentials();
        }
        await _users.ResetAccessFailedCountAsync(user);

        // Checked only after the password is right, so the response never reveals that an account exists.
        if (user.Status != UserStatus.Active) throw new ServiceException("AccountDisabled", "This account is disabled.");

        var session = await _refreshTokens.StartSessionAsync(user.Id, ip, ct);
        return Pair(user, session);
    }

    public async Task<AuthTokens> RefreshAsync(string? refreshToken, string ip, CancellationToken ct)
    {
        var rotated = await _refreshTokens.RotateAsync(refreshToken, ip, ct);
        var user = await _users.FindByIdAsync(rotated.UserId.ToString("D"));
        if (user is null || user.Status != UserStatus.Active || await _users.IsLockedOutAsync(user))
        {
            await _refreshTokens.RevokeSessionByIdAsync(rotated.FamilyId, "AccountDisabled", ct);
            throw new ServiceException("InvalidRefreshToken", "The session is not valid.");
        }
        return Pair(user, rotated);
    }

    public Task LogoutAsync(string? refreshToken, CancellationToken ct) =>
        _refreshTokens.RevokeSessionAsync(refreshToken, "LoggedOut", ct);

    /// <summary>Changing the password ends every session, so a stolen refresh token stops working.</summary>
    public async Task ChangePasswordAsync(Guid userId, string? currentPassword, string? newPassword, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(userId.ToString("D")) ?? throw new ServiceException("NotFound", "Account not found.");
        var result = await _users.ChangePasswordAsync(user, currentPassword ?? string.Empty, newPassword ?? string.Empty);
        if (!result.Succeeded)
            throw result.Errors.Any(e => e.Code == "PasswordMismatch")
                ? new ServiceException("InvalidCredentials", "The current password is wrong.")
                : Translate(result);
        await _refreshTokens.RevokeAllForUserAsync(userId, "PasswordChanged", ct);
    }

    // ------------------------------------------------------------------ helpers

    private AuthTokens Pair(User user, IssuedRefreshToken session)
    {
        var access = _accessTokens.Issue(user, session.FamilyId);
        return new AuthTokens(access.Token, access.ExpiresAt, session.Token, session.ExpiresAt);
    }

    private static string NormalizeEmail(string? email)
    {
        var candidate = (email ?? string.Empty).Trim().ToLowerInvariant();
        if (candidate.Length is 0 or > 320 || !MailAddress.TryCreate(candidate, out var parsed) || parsed.Address != candidate || !candidate.Contains('.'))
            throw new ServiceException("EmailInvalid", "Enter a valid email address.");
        return candidate;
    }

    private static ServiceException Translate(IdentityResult result)
    {
        var codes = result.Errors.Select(e => e.Code).ToList();
        if (codes.Any(c => c is "DuplicateEmail" or "DuplicateUserName"))
            return new ServiceException("EmailTaken", "An account with this email already exists.");
        if (codes.Any(c => c.StartsWith("Password", StringComparison.Ordinal)))
            return new ServiceException("WeakPassword", string.Join(" ", result.Errors.Where(e => e.Code.StartsWith("Password", StringComparison.Ordinal)).Select(e => e.Description)));
        if (codes.Any(c => c is "InvalidEmail" or "InvalidUserName"))
            return new ServiceException("EmailInvalid", "Enter a valid email address.");
        return new ServiceException("AccountError", string.Join(" ", result.Errors.Select(e => e.Description)));
    }

    private static ServiceException InvalidCredentials() => new("InvalidCredentials", "The email or password is wrong.");
    private static ServiceException LockedOut() => new("AccountLockedOut", "Too many failed attempts. Try again later.");
}
