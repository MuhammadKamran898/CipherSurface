using CipherSurface.Data.Enums;
using CipherSurface.Services;
using CipherSurface.Verification.Email;

namespace CipherSurface.Api.Contracts;

// Requests carry only what the caller may decide. The organization comes from the token and the X-Organization-Id
// header (checked against the database), the role from the database, the authorization text from the server.
public sealed record CreateDomainRequest(string? Name, string? AttestationVersion, bool? Accepted);
public sealed record IssueChallengeRequest(string? Method, string? Host);
public sealed record IssueEmailChallengeRequest(string? Recipient);

/// <summary>The one-time token from the confirmation email. It travels only in this body, never in a URL.</summary>
public sealed record ConfirmEmailRequest(string? Token);

public sealed record AttestationResponse(string Version, string Text);

public sealed record EvidenceSummaryResponse(VerificationMethod Method, EvidenceStatus Status, DateTimeOffset? ExpiresAt);
public sealed record DomainListItemResponse(Guid Id, string Name, DomainStatus Status, DateTimeOffset CreatedAt, IReadOnlyList<EvidenceSummaryResponse> Evidence);
public sealed record DomainListResponse(IReadOnlyList<DomainListItemResponse> Items, int Page, int PageSize, int Total);

public sealed record DomainAuthorizationResponse(GrantStatus Status, string AttestationVersion, DateTimeOffset AcceptedAt, DateTimeOffset? RevokedAt);

public sealed record DomainEvidenceResponse(
    Guid Id, VerificationMethod Method, AssuranceLevel Assurance, ScopeCeilingType ScopeCeiling, string Host, EvidenceStatus Status,
    DateTimeOffset EstablishedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? LastValidAt, DateTimeOffset? FailingSince);

/// <summary>Instruction is present only for an Owner or Admin, and only for DNS, HTTP-file and meta-tag challenges. Email challenges never show a token or a hash.</summary>
public sealed record OpenChallengeResponse(
    Guid Id, VerificationMethod Method, string Host, ChallengeStatus Status, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt,
    int FailedAttempts, int MaxAttempts, string? Instruction);

public sealed record DomainDisputeResponse(Guid Id, DisputeRole Role, DisputeStatus Status, DateTimeOffset OpenedAt, DateTimeOffset? ResolvedAt);

public sealed record DomainDetailResponse(
    Guid Id, string Name, DomainStatus Status, DateTimeOffset CreatedAt, Guid CreatedByUserId,
    DomainAuthorizationResponse? Authorization,
    IReadOnlyList<DomainEvidenceResponse> Evidence,
    IReadOnlyList<OpenChallengeResponse> OpenChallenges,
    IReadOnlyList<DomainDisputeResponse> Disputes,
    bool EmailVerificationAvailable);

public sealed record IssuedChallengeResponse(Guid ChallengeId, VerificationMethod Method, string Host, string Instruction, DateTimeOffset ExpiresAt);
public sealed record IssuedEmailChallengeResponse(Guid ChallengeId, string Recipient, DateTimeOffset ExpiresAt);

public sealed record VerifyChallengeResponse(
    CheckOutcome Outcome, string Reason, ChallengeStatus ChallengeStatus, DomainStatus DomainStatus,
    bool DisputeOpened, int FailedAttempts, int MaxAttempts);

public sealed record EmailLinkPreviewResponse(EmailLinkState State, string DomainName);
public sealed record ConfirmEmailResponse(DomainStatus DomainStatus, bool DisputeOpened);
