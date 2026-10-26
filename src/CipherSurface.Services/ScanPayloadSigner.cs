using System.Security.Cryptography;
using System.Text;

namespace CipherSurface.Services;

/// <summary>
/// What the control plane hands a worker. The worker must verify the signature, check that ExpiresAt has not passed,
/// and refuse any host that is not in Targets and inside ScopeSnapshot, before it makes a single outbound request.
/// ExpiresAt is a START-BY deadline (the policy decision's expiry); it does not limit how long a running scan may last.
/// </summary>
public sealed record ScanWorkOrder(
    Guid ScanRunId, Guid DecisionId, IReadOnlyList<string> Targets, string ScopeSnapshot,
    DateTimeOffset ExpiresAt, DateTimeOffset LeaseExpiresAt, string Signature);

/// <summary>
/// HMAC-SHA256 over a canonical string. The Python worker recomputes the same string:
/// "cs-scan-v1" \n runId \n decisionId \n expiresAt.UtcTicks \n targets sorted ordinally and joined by "," \n
/// lower-case hex SHA-256 of the scope snapshot text.
/// The lease is deliberately not signed: it changes with every continuation check.
/// </summary>
public sealed class ScanPayloadSigner
{
    private readonly byte[] _key;

    public ScanPayloadSigner(byte[] key)
    {
        if (key is null || key.Length < 32)
            throw new ArgumentException("The signing key must be at least 32 bytes.", nameof(key));
        _key = (byte[])key.Clone();
    }

    public string Sign(Guid scanRunId, Guid decisionId, IReadOnlyCollection<string> targets, string scopeSnapshot, DateTimeOffset expiresAt) =>
        Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(Canonical(scanRunId, decisionId, targets, scopeSnapshot, expiresAt)))).ToLowerInvariant();

    public bool Verify(ScanWorkOrder order)
    {
        ArgumentNullException.ThrowIfNull(order);
        byte[] presented;
        try { presented = Convert.FromHexString(order.Signature ?? string.Empty); }
        catch (FormatException) { return false; }

        var expected = HMACSHA256.HashData(_key,
            Encoding.UTF8.GetBytes(Canonical(order.ScanRunId, order.DecisionId, order.Targets, order.ScopeSnapshot, order.ExpiresAt)));
        return CryptographicOperations.FixedTimeEquals(presented, expected);
    }

    private static string Canonical(Guid scanRunId, Guid decisionId, IReadOnlyCollection<string> targets, string scopeSnapshot, DateTimeOffset expiresAt) =>
        string.Join("\n",
            "cs-scan-v1",
            scanRunId.ToString("D"),
            decisionId.ToString("D"),
            expiresAt.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            string.Join(",", targets.OrderBy(t => t, StringComparer.Ordinal)),
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(scopeSnapshot))).ToLowerInvariant());
}

internal static class TargetNames
{
    /// <summary>Same normalization the gates use: trim, drop a trailing dot, IDNA to ASCII, lower-case.</summary>
    public static string Normalize(string host)
    {
        var candidate = (host ?? string.Empty).Trim();
        if (candidate.EndsWith('.')) candidate = candidate[..^1];
        try
        {
            return new System.Globalization.IdnMapping { UseStd3AsciiRules = true }.GetAscii(candidate).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return candidate.ToLowerInvariant();
        }
    }
}
