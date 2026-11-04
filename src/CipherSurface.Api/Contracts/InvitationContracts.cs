using CipherSurface.Auth;
using CipherSurface.Data.Enums;

namespace CipherSurface.Api.Contracts;

public sealed record CreateInvitationRequest(string? Email, string? Role);
public sealed record InvitationTokenRequest(string? Token);
public sealed record AcceptNewAccountRequest(string? Token, string? Password);

/// <summary>The only response that ever contains the raw token. It is not stored and cannot be shown again.</summary>
public sealed record InvitationCreatedResponse(Guid InvitationId, string Email, MembershipRole Role, DateTimeOffset ExpiresAt, string Token, string? Link);

public sealed record InvitationItem(Guid Id, string Email, MembershipRole Role, InvitationState State, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, Guid CreatedByUserId);
public sealed record InvitationPreviewResponse(string OrganizationName, string Email, MembershipRole Role, DateTimeOffset ExpiresAt, bool AccountExists);
public sealed record InvitationAcceptedResponse(Guid UserId, Guid OrganizationId, MembershipRole Role, bool NewAccount);
