namespace CipherSurface.Auth;

public sealed record InvitationOptions
{
    public static readonly TimeSpan MinLifetime = TimeSpan.FromDays(1);
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromDays(30);

    /// <summary>How long an invitation can be accepted. Seven days by default.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromDays(7);

    /// <summary>Open (pending and not yet expired) invitations one organization may have at a time.</summary>
    public int MaxPendingPerOrganization { get; init; } = 100;
}
