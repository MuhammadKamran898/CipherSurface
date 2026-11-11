using CipherSurface.Api.Configuration;
using CipherSurface.Api.Contracts;
using CipherSurface.Api.Security;
using CipherSurface.Data.Enums;
using CipherSurface.Services;

namespace CipherSurface.Api.Endpoints;

/// <summary>
/// Domains and ownership verification over the existing services. Reading is open to every member of the organization;
/// every write needs an Owner or Admin (checked first, see ManagerAccess). A domain or challenge of another organization
/// answers NotFound, exactly like one that does not exist. Challenge and email-challenge routes are keyed by the challenge
/// id alone because the confirmation email link carries only that id.
///
/// The Verify click makes real DNS or HTTP requests and can take several seconds (DNS propagation retries). The service
/// limits attempts per user and per address; the "verification" policy adds a per-client request limit on top.
/// </summary>
public static class DomainEndpoints
{
    public const string RateLimitPolicy = "verification";

    public static void Map(RouteGroupBuilder api)
    {
        // The statement the user is shown and accepts. The server owns the text, so the stored hash is of what was really displayed.
        api.MapGet("/attestation", () => Results.Ok(new AttestationResponse(AttestationStatement.CurrentVersion, AttestationStatement.Text)));

        var domains = api.MapGroup("/domains");

        domains.MapPost("/", async (OrganizationContext org, CreateDomainRequest request, DomainOnboardingService onboarding,
            DomainQueryService queries, EmailVerificationService email, ApiSettings settings, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);
            if (request.Accepted != true)
                throw new ServiceException("AttestationRequired", "You must accept the authorization statement.");
            if (!string.Equals(request.AttestationVersion, AttestationStatement.CurrentVersion, StringComparison.Ordinal))
                throw new ServiceException("AttestationOutdated", "The authorization statement has changed. Read the current statement and accept it again.");

            var id = await onboarding.AddDomainAsync(org.Actor, request.Name ?? string.Empty, AttestationStatement.CurrentVersion, AttestationStatement.Text, ct);
            var details = await queries.GetAsync(org.Actor, id, ct);
            return Results.Created($"/api/v1/domains/{id}", ToResponse(details, EmailAvailable(email, settings)));
        });

        domains.MapGet("/", async (OrganizationContext org, DomainQueryService queries, int? page, int? pageSize, string? status, CancellationToken ct) =>
        {
            DomainStatus? statusFilter = status is null
                ? null
                : ParseExact<DomainStatus>(status, "InvalidRequest", "The status filter is not a known domain status.");
            var result = await queries.ListAsync(org.Actor, page ?? 1, pageSize ?? DomainQueryService.DefaultPageSize, statusFilter, ct);

            var items = result.Items
                .Select(i => new DomainListItemResponse(
                    i.Id, i.Name, i.Status, i.CreatedAt,
                    i.Evidence.Select(e => new EvidenceSummaryResponse(e.Method, e.Status, e.ExpiresAt)).ToList()))
                .ToList();
            return Results.Ok(new DomainListResponse(items, result.Page, result.PageSize, result.Total));
        });

        domains.MapGet("/{id:guid}", async (OrganizationContext org, Guid id, DomainQueryService queries, EmailVerificationService email, ApiSettings settings, CancellationToken ct) =>
            Results.Ok(ToResponse(await queries.GetAsync(org.Actor, id, ct), EmailAvailable(email, settings))));

        // DNS TXT, HTTP file and HTML meta tag. Admin email has its own routes below.
        domains.MapPost("/{id:guid}/challenges", async (OrganizationContext org, Guid id, IssueChallengeRequest request, ChallengeService challenges, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);
            var method = ParseExact<VerificationMethod>(request.Method, "MethodNotSupported", "The method must be DnsTxt, HttpFile or HtmlMeta.");
            var issued = await challenges.IssueAsync(org.Actor, id, method, NormalizeHost(request.Host), ct);
            return Results.Json(new IssuedChallengeResponse(issued.ChallengeId, issued.Method, issued.Host, issued.Instruction, issued.ExpiresAt),
                statusCode: StatusCodes.Status201Created);
        }).RequireRateLimiting(RateLimitPolicy);

        domains.MapPost("/{id:guid}/email-challenges", async (OrganizationContext org, Guid id, IssueEmailChallengeRequest request,
            EmailVerificationService email, ApiSettings settings, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);   // before anything about the deployment is revealed
            if (settings.EmailConfirmationPage is not { } page)
                throw new ServiceException("EmailNotConfigured", "Email verification is not available: no confirmation page is configured.");

            var issued = await email.IssueAsync(org.Actor, id, request.Recipient ?? string.Empty, new Uri(page), ct);
            return Results.Json(new IssuedEmailChallengeResponse(issued.ChallengeId, issued.Recipient, issued.ExpiresAt),
                statusCode: StatusCodes.Status201Created);
        }).RequireRateLimiting(RateLimitPolicy);

        // One click is one attempt.
        api.MapPost("/challenges/{id:guid}/verify", async (OrganizationContext org, Guid id, VerificationService verification, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);
            var r = await verification.VerifyAsync(org.Actor, id, ct);
            return Results.Ok(new VerifyChallengeResponse(r.Outcome, r.Reason, r.ChallengeStatus, r.DomainStatus, r.DisputeOpened, r.FailedAttempts, r.MaxAttempts));
        }).RequireRateLimiting(RateLimitPolicy);

        var emailChallenges = api.MapGroup("/email-challenges");

        // The page the email link opens calls this. It never changes anything, so a mail scanner that opens the link cannot use it up.
        emailChallenges.MapGet("/{id:guid}", async (OrganizationContext org, Guid id, EmailVerificationService email, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);
            var preview = await email.PreviewAsync(org.Actor, id, ct);
            return Results.Ok(new EmailLinkPreviewResponse(preview.State, preview.DomainName));
        });

        // Only this POST uses the token. The caller must be signed in as an Owner or Admin of the organization that owns the domain.
        emailChallenges.MapPost("/{id:guid}/confirm", async (OrganizationContext org, Guid id, ConfirmEmailRequest request, EmailVerificationService email, CancellationToken ct) =>
        {
            ManagerAccess.Require(org);
            var confirmed = await email.ConfirmAsync(org.Actor, id, request.Token, ct);
            return Results.Ok(new ConfirmEmailResponse(confirmed.DomainStatus, confirmed.DisputeOpened));
        }).RequireRateLimiting(RateLimitPolicy);
    }

    private static bool EmailAvailable(EmailVerificationService email, ApiSettings settings) =>
        settings.EmailConfirmationPage is not null && email.IsAvailable;

    /// <summary>Lower-case, no trailing dot. Blank means "the domain itself". The service decides whether the host is allowed.</summary>
    private static string? NormalizeHost(string? host)
    {
        var trimmed = host?.Trim().TrimEnd('.').ToLowerInvariant();
        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }

    /// <summary>Exact name only (any letter case). Numbers and comma lists, which Enum.TryParse would accept, are refused.</summary>
    private static T ParseExact<T>(string? raw, string code, string message) where T : struct, Enum
    {
        var text = raw?.Trim();
        foreach (var candidate in Enum.GetValues<T>())
            if (string.Equals(candidate.ToString(), text, StringComparison.OrdinalIgnoreCase)) return candidate;
        throw new ServiceException(code, message);
    }

    private static DomainDetailResponse ToResponse(DomainDetails d, bool emailAvailable) => new(
        d.Id, d.Name, d.Status, d.CreatedAt, d.CreatedByUserId,
        d.Authorization is null
            ? null
            : new DomainAuthorizationResponse(d.Authorization.Status, d.Authorization.AttestationVersion, d.Authorization.AcceptedAt, d.Authorization.RevokedAt),
        d.Evidence.Select(e => new DomainEvidenceResponse(e.Id, e.Method, e.Assurance, e.ScopeCeiling, e.Host, e.Status, e.EstablishedAt, e.ExpiresAt, e.LastValidAt, e.FailingSince)).ToList(),
        d.OpenChallenges.Select(c => new OpenChallengeResponse(c.Id, c.Method, c.Host, c.Status, c.IssuedAt, c.ExpiresAt, c.FailedAttempts, c.MaxAttempts, c.Instruction)).ToList(),
        d.Disputes.Select(x => new DomainDisputeResponse(x.Id, x.Role, x.Status, x.OpenedAt, x.ResolvedAt)).ToList(),
        emailAvailable);
}
