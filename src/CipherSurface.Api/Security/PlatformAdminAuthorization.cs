using CipherSurface.Services;
using Microsoft.AspNetCore.Authorization;

namespace CipherSurface.Api.Security;

public static class ApiPolicies
{
    public const string PlatformAdmin = "PlatformAdmin";
}

public sealed class PlatformAdminRequirement : IAuthorizationRequirement;

/// <summary>
/// Succeeds only when PlatformAdminGate (backed by the configured allowlist) confirms the user id from the validated
/// token. The decision is made on the server on every request; nothing in the request can claim it.
/// </summary>
public sealed class PlatformAdminHandler : AuthorizationHandler<PlatformAdminRequirement>
{
    private readonly PlatformAdminGate _gate;
    public PlatformAdminHandler(PlatformAdminGate gate) => _gate = gate;

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PlatformAdminRequirement requirement)
    {
        try
        {
            await _gate.AuthorizeAsync(context.User.Id(), CancellationToken.None);
            context.Succeed(requirement);
        }
        catch (ServiceException)
        {
            // Not an administrator: the requirement stays unmet and the request is forbidden.
        }
    }
}
