using CipherSurface.Data;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

internal static class AttemptRateLimit
{
    /// <summary>Hourly limits per user and per IP, counted over all verification attempts.</summary>
    public static async Task EnsureAsync(CipherSurfaceDbContext db, Actor actor, DateTimeOffset now, VerificationOptions options, CancellationToken ct)
    {
        var since = now.AddHours(-1);
        var byUser = await db.VerificationAttempts.CountAsync(a => a.UserId == actor.UserId && a.StartedAt > since, ct);
        var byIp = await db.VerificationAttempts.CountAsync(a => a.Ip == actor.Ip && a.StartedAt > since, ct);
        if (byUser >= options.MaxAttemptsPerUserPerHour || byIp >= options.MaxAttemptsPerIpPerHour)
            throw new ServiceException("RateLimited", "Too many verification attempts. Try again later.");
    }
}
