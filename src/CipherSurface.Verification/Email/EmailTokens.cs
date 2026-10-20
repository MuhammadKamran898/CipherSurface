using System.Security.Cryptography;
using System.Text;

namespace CipherSurface.Verification.Email;

/// <summary>
/// The admin-email token is a real secret (it proves mailbox access), so unlike the public DNS,
/// file and meta proofs it is stored ONLY as a SHA-256 hash and compared in constant time.
/// 256 random bits make a salted or slow hash unnecessary.
/// </summary>
public static class EmailTokens
{
    /// <summary>256-bit random token, base64url (43 characters, no padding).</summary>
    public static string Generate() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Lower-case hex SHA-256 (64 characters).</summary>
    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    public static bool Matches(string? presentedToken, string? storedHash)
    {
        if (string.IsNullOrEmpty(presentedToken) || string.IsNullOrEmpty(storedHash)) return false;
        byte[] stored;
        try { stored = Convert.FromHexString(storedHash); }
        catch (FormatException) { return false; }

        var presented = SHA256.HashData(Encoding.UTF8.GetBytes(presentedToken));
        return CryptographicOperations.FixedTimeEquals(presented, stored);
    }
}
