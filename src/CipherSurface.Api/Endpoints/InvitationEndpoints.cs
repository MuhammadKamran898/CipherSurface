using System.Security.Claims;
using CipherSurface.Api.Configuration;
using CipherSurface.Api.Contracts;
using CipherSurface.Api.Security;
using CipherSurface.Auth;
using CipherSurface.Data.Enums;
using CipherSurface.Services;

namespace CipherSurface.Api.Endpoints;

/// <summary>
/// Invitation-only membership over InvitationService. Owners and Admins create, list and revoke invitations. A person
/// previews and accepts with the one-time token, which travels only in a request body (never in a URL), so it does not
/// end up in access logs, browser history or referrers. Previewing never consumes an invitation; accepting is an
/// explicit POST. The link the inviter receives puts the token after "#", which browsers never send to a server.
/// </summary>
public static class InvitationEndpoints
{
    public const string RateLimitPolicy = "invitations";

    public static void Map(RouteGroupBuilder api)
    {
        var group = api.MapGroup("/invitations");

        group.MapPost("/", async (CreateInvitationRequest request, HttpContext http, OrganizationContextResolver resolver, InvitationService invitations, ApiSettings settings, CancellationToken ct) =>
        {
            var context = await resolver.ResolveAsync(http, ct);
            var issued = await invitations.IssueAsync(context.Actor, request.Email, ParseRole(request.Role), ct);
            var link = settings.InvitationAcceptBaseUrl is { } baseUrl ? $"{baseUrl}#token={issued.Token}" : null;
            return Results.Json(new InvitationCreatedResponse(issued.InvitationId, issued.Email, issued.Role, issued.ExpiresAt, issued.Token, link),
                statusCode: StatusCodes.Status201Created);
        });

        group.MapGet("/", async (HttpContext http, OrganizationContextResolver resolver, InvitationService invitations, CancellationToken ct) =>
        {
            var context = await resolver.ResolveAsync(http, ct);
            var items = (await invitations.ListAsync(context.Actor, ct))
                .Select(i => new InvitationItem(i.Id, i.Email, i.Role, i.State, i.CreatedAt, i.ExpiresAt, i.CreatedByUserId));
            return Results.Ok(items);
        });

        group.MapDelete("/{id:guid}", async (Guid id, HttpContext http, OrganizationContextResolver resolver, InvitationService invitations, CancellationToken ct) =>
        {
            var context = await resolver.ResolveAsync(http, ct);
            await invitations.RevokeAsync(context.Actor, id, ct);
            return Results.NoContent();
        });

        // The three endpoints below take the token from the request body and are rate-limited per client.
        group.MapPost("/preview", async (InvitationTokenRequest request, InvitationService invitations, CancellationToken ct) =>
        {
            var preview = await invitations.PreviewAsync(request.Token, ct);
            return Results.Ok(new InvitationPreviewResponse(preview.OrganizationName, preview.Email, preview.Role, preview.ExpiresAt, preview.AccountExists));
        }).AllowAnonymous().RequireRateLimiting(RateLimitPolicy);

        group.MapPost("/accept", async (AcceptNewAccountRequest request, HttpContext http, InvitationService invitations, CancellationToken ct) =>
        {
            var accepted = await invitations.AcceptAsNewAccountAsync(request.Token, request.Password, ClientIp.Of(http), ct);
            return Results.Json(new InvitationAcceptedResponse(accepted.UserId, accepted.OrganizationId, accepted.Role, accepted.NewAccount),
                statusCode: StatusCodes.Status201Created);
        }).AllowAnonymous().RequireRateLimiting(RateLimitPolicy);

        group.MapPost("/accept/existing", async (InvitationTokenRequest request, ClaimsPrincipal user, HttpContext http, InvitationService invitations, CancellationToken ct) =>
        {
            var accepted = await invitations.AcceptAsExistingAccountAsync(user.Id(), request.Token, ClientIp.Of(http), ct);
            return Results.Ok(new InvitationAcceptedResponse(accepted.UserId, accepted.OrganizationId, accepted.Role, accepted.NewAccount));
        }).RequireRateLimiting(RateLimitPolicy);
    }

    private static MembershipRole ParseRole(string? role) =>
        Enum.TryParse<MembershipRole>(role?.Trim(), ignoreCase: true, out var parsed) && Enum.IsDefined(parsed) && !int.TryParse(role?.Trim(), out _)
            ? parsed
            : throw new ServiceException("InvalidRole", "The role must be Admin, Analyst or Viewer.");
}
