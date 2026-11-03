using CipherSurface.Auth;

namespace CipherSurface.Api.Configuration;

/// <summary>
/// Reads the signing key from a file outside the repository (the path comes from configuration, typically an
/// environment variable). Key material is never logged and never appears in an exception message. In production the
/// file can be a mounted secret from a secrets manager; nothing here changes.
/// </summary>
public static class JwtKeyLoader
{
    public static TokenKeys Load(ApiSettings settings)
    {
        RequireProtectedFile(settings.JwtPrivateKeyFile, "private key");

        TokenKeys keys;
        try
        {
            keys = TokenKeys.FromPrivatePem(File.ReadAllText(settings.JwtPrivateKeyFile), settings.JwtKeyId);
        }
        catch (Exception)
        {
            throw new ApiConfigurationException(["The JWT private key file is not an RSA private key in PEM format of at least 2048 bits."]);
        }

        foreach (var retired in settings.RetiredKeys)
        {
            if (!File.Exists(retired.File))
                throw new ApiConfigurationException([$"The retired JWT public key file for key id '{retired.KeyId}' does not exist."]);
            try
            {
                keys = keys.WithRetiredPublicKey(File.ReadAllText(retired.File), retired.KeyId);
            }
            catch (Exception)
            {
                throw new ApiConfigurationException([$"The retired JWT public key file for key id '{retired.KeyId}' is not an RSA public key in PEM format of at least 2048 bits."]);
            }
        }

        return keys;
    }

    private static void RequireProtectedFile(string path, string what)
    {
        if (!File.Exists(path))
            throw new ApiConfigurationException([$"The JWT {what} file does not exist."]);

        // On Unix the private key must not be readable by other accounts. Windows access is controlled by its ACLs.
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(path);
            const UnixFileMode others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                                        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
            if ((mode & others) != 0)
                throw new ApiConfigurationException([$"The JWT {what} file must not be accessible to group or other users (use mode 600)."]);
        }
    }
}
