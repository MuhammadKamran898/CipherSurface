namespace CipherSurface.Policy;

/// <summary>
/// The one public way to normalize and check a scope pattern. It uses the same rules the scope calculator applies when
/// it reads stored rules. That matters: the calculator fails closed on a stored rule it cannot parse, so a rule that
/// passes here can never make every scan of its domain fail later.
/// </summary>
public static class ScopePatterns
{
    public const string OutsideDomain = "PatternOutsideDomain";

    /// <summary>
    /// Trims and lower-cases the pattern, converts IDN labels to ASCII, drops one trailing dot, and requires either a
    /// host or "*." followed by a host. The result must be the domain itself or fall under it.
    /// </summary>
    /// <returns>True with the normalized pattern; false with a stable error code.</returns>
    public static bool TryNormalize(string? pattern, string? domainName, out string normalized, out string? errorCode)
    {
        normalized = string.Empty;

        if (!HostPattern.TryNormalizeHost(domainName, out var root, out _))
        {
            errorCode = "InvalidDomainName";
            return false;
        }

        if (!HostPattern.TryNormalizePattern(pattern, out var candidate, out var error))
        {
            errorCode = error ?? "InvalidPattern";
            return false;
        }

        if (!HostPattern.IsPatternWithinDomain(candidate, root))
        {
            errorCode = OutsideDomain;
            return false;
        }

        normalized = candidate;
        errorCode = null;
        return true;
    }
}
