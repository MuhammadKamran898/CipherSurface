using CipherSurface.Api.Configuration;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CipherSurface.Api.Tests;

/// <summary>Configuration of the governance limits and the domain quota: defaults, accepted values and refused values.</summary>
public class GovernanceSettingsTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    private static (string, string?)[] Valid(params (string, string?)[] extra) =>
    [
        ("ConnectionStrings:CipherSurface", "Host=localhost;Database=x"),
        ("CipherSurface:Jwt:PrivateKeyFile", "/tmp/key.pem"),
        ("CipherSurface:Jwt:KeyId", "key-1"),
        .. extra
    ];

    [Fact]
    public void TheDefaultsAreConservative()
    {
        var settings = ApiSettings.Load(Config(Valid()));

        Assert.Equal(60, settings.GovernanceRequestsPerMinute);
        Assert.Equal(30, settings.GovernanceActorRequestsPerMinute);
        Assert.Equal(100, settings.MaxDomainsPerOrganization);
    }

    [Fact]
    public void ConfiguredValuesAreUsed()
    {
        var settings = ApiSettings.Load(Config(Valid(
            ("CipherSurface:RateLimiting:GovernanceRequestsPerMinute", "120"),
            ("CipherSurface:RateLimiting:GovernanceActorRequestsPerMinute", "15"),
            ("CipherSurface:Governance:MaxDomainsPerOrganization", "250"))));

        Assert.Equal(120, settings.GovernanceRequestsPerMinute);
        Assert.Equal(15, settings.GovernanceActorRequestsPerMinute);
        Assert.Equal(250, settings.MaxDomainsPerOrganization);
    }

    [Theory]
    [InlineData("CipherSurface:RateLimiting:GovernanceRequestsPerMinute", "0")]
    [InlineData("CipherSurface:RateLimiting:GovernanceRequestsPerMinute", "-1")]
    [InlineData("CipherSurface:RateLimiting:GovernanceRequestsPerMinute", "many")]
    [InlineData("CipherSurface:RateLimiting:GovernanceActorRequestsPerMinute", "0")]
    [InlineData("CipherSurface:RateLimiting:GovernanceActorRequestsPerMinute", "-5")]
    [InlineData("CipherSurface:RateLimiting:GovernanceActorRequestsPerMinute", "1.5")]
    [InlineData("CipherSurface:Governance:MaxDomainsPerOrganization", "0")]
    [InlineData("CipherSurface:Governance:MaxDomainsPerOrganization", "-3")]
    [InlineData("CipherSurface:Governance:MaxDomainsPerOrganization", "lots")]
    [InlineData("CipherSurface:Governance:MaxDomainsPerOrganization", "10001")]
    public void ANonsensicalValueIsRefusedAtStartup(string key, string value)
    {
        var ex = Assert.Throws<ApiConfigurationException>(() => ApiSettings.Load(Config(Valid((key, value)))));

        Assert.Contains(key.Replace("CipherSurface:", ""), string.Join(" ", ex.Problems));
    }

    [Fact]
    public void TheDomainQuotaMayBeExactlyTenThousand()
    {
        var settings = ApiSettings.Load(Config(Valid(("CipherSurface:Governance:MaxDomainsPerOrganization", "10000"))));

        Assert.Equal(10_000, settings.MaxDomainsPerOrganization);
    }
}
