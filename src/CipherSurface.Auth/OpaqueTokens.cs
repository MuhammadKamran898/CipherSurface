using System.Security.Cryptography;
using System.Text;

namespace CipherSurface.Auth;

/// <summary>
/// One-time secrets handed to a person (an invitation link). 256 random bits, URL-safe. The database keeps only the
/// SHA-256 hash, so the secret cannot be read back from the database or a backup, and it is returned exactly once.
/// </summary>
internal static class OpaqueTokens
{
    public static string New() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Lower-case hex SHA-256 (64 characters).</summary>
    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
}
