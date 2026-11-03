using CipherSurface.Api.Configuration;
using CipherSurface.Services.Tests;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class ConfigurationTests
{
    private readonly PostgresFixture _postgres;
    public ConfigurationTests(PostgresFixture postgres) => _postgres = postgres;

    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    private static (string, string?)[] Valid(string keyFile = "/tmp/key.pem") =>
    [
        ("ConnectionStrings:CipherSurface", "Host=localhost;Database=x"),
        ("CipherSurface:Jwt:PrivateKeyFile", keyFile),
        ("CipherSurface:Jwt:KeyId", "key-1")
    ];

    private static (string, string?)[] With(IEnumerable<(string, string?)> baseValues, params (string, string?)[] extra) => [.. baseValues, .. extra];

    [Fact]
    public void AMinimalValidConfiguration_LoadsWithTheMostRestrictiveDefaults()
    {
        var settings = ApiSettings.Load(Config(Valid()));

        Assert.Empty(settings.PlatformAdminUserIds);
        Assert.Empty(settings.CorsOrigins);
        Assert.Empty(settings.KnownProxies);
        Assert.Null(settings.SetupToken);
        Assert.Equal(10, settings.AuthRequestsPerMinute);
        Assert.Equal(300, settings.GlobalRequestsPerMinute);
    }

    [Fact]
    public void MissingRequiredSettings_AreAllReportedTogether()
    {
        var ex = Assert.Throws<ApiConfigurationException>(() => ApiSettings.Load(Config()));

        Assert.Equal(3, ex.Problems.Count);
        Assert.Contains(ex.Problems, p => p.Contains("ConnectionStrings:CipherSurface"));
        Assert.Contains(ex.Problems, p => p.Contains("PrivateKeyFile"));
        Assert.Contains(ex.Problems, p => p.Contains("KeyId"));
    }

    [Fact]
    public void AShortSetupToken_IsRejected_WithoutEchoingIt()
    {
        var ex = Assert.Throws<ApiConfigurationException>(() => ApiSettings.Load(Config(With(Valid(), ("CipherSurface:Setup:Token", "hunter2")))));

        Assert.Contains("Setup:Token", ex.Message);
        Assert.DoesNotContain("hunter2", ex.Message);
    }

    [Theory]
    [InlineData("bad key id")]
    [InlineData("bad/key")]
    [InlineData("")]
    public void AnInvalidKeyId_IsRejected(string keyId)
    {
        var values = Valid().Where(v => v.Item1 != "CipherSurface:Jwt:KeyId").Append(("CipherSurface:Jwt:KeyId", keyId));

        Assert.Throws<ApiConfigurationException>(() => ApiSettings.Load(Config([.. values])));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("many")]
    public void ARateLimitThatIsNotAPositiveNumber_IsRejected(string value)
    {
        Assert.Throws<ApiConfigurationException>(() => ApiSettings.Load(Config(With(Valid(), ("CipherSurface:RateLimiting:AuthRequestsPerMinute", value)))));
    }

    [Fact]
    public void AnInvalidProxyAddress_IsRejected()
    {
        Assert.Throws<ApiConfigurationException>(() => ApiSettings.Load(Config(With(Valid(), ("CipherSurface:ForwardedHeaders:KnownProxies:0", "not-an-ip")))));
    }

    [Fact]
    public void ARetiredKeyThatRepeatsAKeyId_IsRejected()
    {
        var values = With(Valid(),
            ("CipherSurface:Jwt:RetiredPublicKeys:0:KeyId", "key-1"),
            ("CipherSurface:Jwt:RetiredPublicKeys:0:File", "/tmp/old.pem"));

        Assert.Throws<ApiConfigurationException>(() => ApiSettings.Load(Config(values)));
    }

    // ------------------------------------------------------------------ the key file

    private static ApiSettings SettingsFor(string keyFile, params (string, string?)[] extra) => ApiSettings.Load(Config(With(Valid(keyFile), extra)));

    [Fact]
    public void AMissingKeyFile_StopsTheApiFromStarting()
    {
        var ex = Assert.Throws<ApiConfigurationException>(() => JwtKeyLoader.Load(SettingsFor("/nonexistent/jwt.pem")));

        Assert.Contains("does not exist", ex.Message);
    }

    [Fact]
    public void AFileThatIsNotAnRsaKey_IsRejected_WithoutLeakingItsContent()
    {
        var path = Path.Combine(Path.GetTempPath(), "cs-bad-key-" + Guid.NewGuid().ToString("N") + ".pem");
        ApiHost.WritePrivateKey(path, "TOP-SECRET-CONTENT-NOT-A-KEY");
        try
        {
            var ex = Assert.Throws<ApiConfigurationException>(() => JwtKeyLoader.Load(SettingsFor(path)));

            Assert.DoesNotContain("TOP-SECRET", ex.Message);
            Assert.Contains("RSA private key", ex.Message);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void AnRsaKeyShorterThan2048Bits_IsRejected()
    {
        var path = Path.Combine(Path.GetTempPath(), "cs-weak-key-" + Guid.NewGuid().ToString("N") + ".pem");
        using (var weak = System.Security.Cryptography.RSA.Create(1024))
            ApiHost.WritePrivateKey(path, weak.ExportPkcs8PrivateKeyPem());
        try
        {
            Assert.Throws<ApiConfigurationException>(() => JwtKeyLoader.Load(SettingsFor(path)));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void APrivateKeyReadableByOtherUsers_IsRejected_OnUnix()
    {
        if (OperatingSystem.IsWindows()) return;   // Windows protects the file with ACLs, which this check does not read.
        var path = Path.Combine(Path.GetTempPath(), "cs-open-key-" + Guid.NewGuid().ToString("N") + ".pem");
        var (_, pem) = ApiHost.Generate();
        File.WriteAllText(path, pem);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        try
        {
            var ex = Assert.Throws<ApiConfigurationException>(() => JwtKeyLoader.Load(SettingsFor(path)));

            Assert.Contains("mode 600", ex.Message);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void AMissingRetiredKeyFile_IsRejected()
    {
        var path = Path.Combine(Path.GetTempPath(), "cs-key-" + Guid.NewGuid().ToString("N") + ".pem");
        var (_, pem) = ApiHost.Generate();
        ApiHost.WritePrivateKey(path, pem);
        try
        {
            var settings = SettingsFor(path, ("CipherSurface:Jwt:RetiredPublicKeys:0:KeyId", "key-0"), ("CipherSurface:Jwt:RetiredPublicKeys:0:File", "/nonexistent/old.pem"));

            Assert.Throws<ApiConfigurationException>(() => JwtKeyLoader.Load(settings));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task TheApiRefusesToStart_WithABrokenConfiguration()
    {
        var ex = await Assert.ThrowsAsync<ApiConfigurationException>(() =>
            ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["ConnectionStrings:CipherSurface"] = null }));

        Assert.Contains("ConnectionStrings:CipherSurface", ex.Message);
    }
}
