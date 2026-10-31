using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace CipherSurface.Auth;

/// <summary>
/// The RSA key pair behind the access tokens. The private key signs (only the API that issues tokens has it);
/// the public key validates (the API, the Python workers and anything else that must trust a token).
/// </summary>
public sealed class TokenKeys
{
    private const int MinimumKeySize = 2048;

    public string KeyId { get; }
    /// <summary>Null on a validate-only instance (it holds the public key only).</summary>
    public RsaSecurityKey? SigningKey { get; }
    public RsaSecurityKey ValidationKey { get; }
    public string PublicPem { get; }

    private TokenKeys(string keyId, RsaSecurityKey? signingKey, RsaSecurityKey validationKey, string publicPem)
    {
        KeyId = keyId;
        SigningKey = signingKey;
        ValidationKey = validationKey;
        PublicPem = publicPem;
    }

    public static TokenKeys FromPrivatePem(string privatePem, string keyId)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(privatePem);
        return FromPrivateRsa(rsa, keyId);
    }

    public static TokenKeys FromPublicPem(string publicPem, string keyId)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(publicPem);
        RequireStrong(rsa);
        return new TokenKeys(keyId, null, new RsaSecurityKey(rsa) { KeyId = keyId }, publicPem);
    }

    /// <summary>A fresh 2048-bit pair for development and tests. Production keys come from secret storage.</summary>
    public static (TokenKeys Keys, string PrivatePem, string PublicPem) Generate(string keyId = "dev")
    {
        var rsa = RSA.Create(MinimumKeySize);
        var privatePem = rsa.ExportPkcs8PrivateKeyPem();
        var keys = FromPrivateRsa(rsa, keyId);
        return (keys, privatePem, keys.PublicPem);
    }

    private static TokenKeys FromPrivateRsa(RSA rsa, string keyId)
    {
        RequireStrong(rsa);
        var publicOnly = RSA.Create();
        publicOnly.ImportRSAPublicKey(rsa.ExportRSAPublicKey(), out _);
        return new TokenKeys(
            keyId,
            new RsaSecurityKey(rsa) { KeyId = keyId },
            new RsaSecurityKey(publicOnly) { KeyId = keyId },
            publicOnly.ExportSubjectPublicKeyInfoPem());
    }

    private static void RequireStrong(RSA rsa)
    {
        if (rsa.KeySize < MinimumKeySize)
            throw new ArgumentException($"The RSA key must be at least {MinimumKeySize} bits.");
    }
}
