using System.Globalization;
using System.Threading.RateLimiting;
using CipherSurface.Api.Configuration;
using CipherSurface.Api.Errors;
using CipherSurface.Api.Security;

namespace CipherSurface.Api.RateLimiting;

/// <summary>
/// Rate limits for governance changes (scope rules now; grant revocation and organization suspension later). Two layers:
///
/// 1. By client address, as a named built-in policy. It runs before authentication, like the other policies, so it also
///    covers a flood of requests with bad or no tokens.
/// 2. By signed-in user, in a small middleware that runs AFTER authentication and authorization but BEFORE the handler,
///    so a refused request costs no database lookup. The built-in limiter cannot do this because it runs before
///    authentication and cannot see who the caller is.
///
/// Address-only limiting punishes a shared office; user-only limiting cannot see unauthenticated floods. The global
/// per-address limit for everything stays as it was. Both layers answer 429 RateLimited with a Retry-After header.
/// </summary>
public static class GovernanceRateLimit
{
    public const string Policy = "governance";

    /// <summary>Marks a governance endpoint for both layers.</summary>
    public static TBuilder RequireGovernanceLimits<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder =>
        builder.RequireRateLimiting(Policy).WithMetadata(GovernanceActorLimited.Instance);
}

/// <summary>Endpoint metadata: the per-user layer applies to this endpoint.</summary>
public sealed class GovernanceActorLimited
{
    public static readonly GovernanceActorLimited Instance = new();
    private GovernanceActorLimited() { }
}

/// <summary>One fixed window per user id. Registered as a singleton, disposed with the host.</summary>
public sealed class GovernanceActorLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<Guid> _limiter;

    public GovernanceActorLimiter(ApiSettings settings)
    {
        var permits = settings.GovernanceActorRequestsPerMinute;
        _limiter = PartitionedRateLimiter.Create<Guid, Guid>(user =>
            RateLimitPartition.GetFixedWindowLimiter(user, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
    }

    /// <summary>Null when the request may go on; otherwise how long the caller should wait.</summary>
    public TimeSpan? TryAcquire(Guid userId)
    {
        using var lease = _limiter.AttemptAcquire(userId);
        if (lease.IsAcquired) return null;
        return lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : TimeSpan.FromMinutes(1);
    }

    public void Dispose() => _limiter.Dispose();
}

public sealed class GovernanceActorRateLimitMiddleware
{
    private readonly RequestDelegate _next;

    public GovernanceActorRateLimitMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, GovernanceActorLimiter limiter)
    {
        var limited = context.GetEndpoint()?.Metadata.GetMetadata<GovernanceActorLimited>() is not null;
        if (limited && context.User.Identity?.IsAuthenticated == true && limiter.TryAcquire(context.User.Id()) is { } wait)
        {
            context.Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
            await ProblemWriter.WriteAsync(context, 429, "RateLimited", ProblemWriter.GenericDetail(429));
            return;
        }

        await _next(context);
    }
}
