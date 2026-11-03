using CipherSurface.Data.Enums;

namespace CipherSurface.Api.Contracts;

// Requests carry only what the caller may decide. There is no user id, organization id or role in any request body:
// those come from the validated token and the database.
public sealed record SetupRequest(string? Email, string? Password, string? OrganizationName);
public sealed record LoginRequest(string? Email, string? Password);
public sealed record RefreshRequest(string? RefreshToken);
public sealed record ChangePasswordRequest(string? CurrentPassword, string? NewPassword);

public sealed record SetupResponse(Guid UserId, Guid OrganizationId);
public sealed record MembershipView(Guid OrganizationId, string Name, OrganizationStatus Status, MembershipRole Role);
public sealed record MeResponse(Guid UserId, string Email, bool IsPlatformAdmin, IReadOnlyList<MembershipView> Organizations);
public sealed record OrganizationResponse(Guid OrganizationId, string Name, OrganizationStatus Status, MembershipRole Role);
