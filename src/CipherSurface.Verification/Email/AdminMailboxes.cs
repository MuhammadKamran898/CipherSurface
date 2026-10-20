namespace CipherSurface.Verification.Email;

/// <summary>The role mailboxes certificate authorities also accept. Root domain only.</summary>
public static class AdminMailboxes
{
    public static readonly IReadOnlyList<string> LocalParts =
        new[] { "admin", "administrator", "webmaster", "hostmaster", "postmaster" };

    public static IReadOnlyList<string> For(string rootDomain) =>
        LocalParts.Select(local => $"{local}@{rootDomain}").ToArray();

    /// <summary>
    /// True only for exactly "role@rootDomain". Display names, plus-addressing, subdomains and
    /// look-alike domains are all rejected, so a user cannot redirect the link elsewhere.
    /// </summary>
    public static bool IsAllowed(string? address, string rootDomain)
    {
        if (string.IsNullOrWhiteSpace(address) || string.IsNullOrWhiteSpace(rootDomain)) return false;
        if (address != address.Trim()) return false;

        var parts = address.Split('@');
        if (parts.Length != 2) return false;

        return LocalParts.Contains(parts[0], StringComparer.OrdinalIgnoreCase)
            && string.Equals(parts[1], rootDomain, StringComparison.OrdinalIgnoreCase);
    }
}
