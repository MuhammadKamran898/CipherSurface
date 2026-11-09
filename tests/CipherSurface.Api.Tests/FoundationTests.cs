using CipherSurface.Api.Configuration;
using CipherSurface.Api.Security;
using CipherSurface.Auth;
using CipherSurface.Services;
using CipherSurface.Services.Tests;
using CipherSurface.Verification;
using CipherSurface.Verification.Email;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CipherSurface.Api.Tests;

/// <summary>The API host wires everything the next steps need, and refuses to start when a safety dependency is missing.</summary>
[Collection("postgres")]
public class FoundationTests
{
    private readonly PostgresFixture _postgres;
    public FoundationTests(PostgresFixture postgres) => _postgres = postgres;

    private static readonly Type[] RequiredServices =
    [
        typeof(AuditLogWriter), typeof(ClaimService), typeof(DomainNameValidator), typeof(DomainOnboardingService),
        typeof(ChallengeService), typeof(VerificationService), typeof(EmailVerificationService),
        typeof(EvidenceReverificationService), typeof(EvidenceLifecycleService), typeof(GrantService),
        typeof(OrganizationService), typeof(DisputeService), typeof(ScanStartService), typeof(ScopeRuleService),
        typeof(PlatformAdminGate), typeof(IPlatformAdminPolicy), typeof(IPublicSuffixCheck), typeof(VerifierRegistry),
        typeof(IEmailSender), typeof(IWebProofClient), typeof(AccountService), typeof(InvitationService),
        typeof(AccessTokenService), typeof(RefreshTokenService), typeof(OrganizationContextResolver), typeof(ApiSettings)
    ];

    [Fact]
    public async Task TheHostCanResolveEveryServiceTheApplicationNeeds()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await using var scope = host.Services.CreateAsyncScope();

        var missing = new List<string>();
        foreach (var type in RequiredServices)
        {
            try
            {
                Assert.NotNull(scope.ServiceProvider.GetRequiredService(type));
            }
            catch (InvalidOperationException ex)
            {
                missing.Add($"{type.Name}: {ex.Message}");
            }
        }

        Assert.True(missing.Count == 0, string.Join(Environment.NewLine, missing));
    }

    [Fact]
    public async Task OnboardingUsesTheConfiguredPublicSuffixList()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await using var scope = host.Services.CreateAsyncScope();

        Assert.IsType<PublicSuffixList>(scope.ServiceProvider.GetRequiredService<IPublicSuffixCheck>());
        var validator = scope.ServiceProvider.GetRequiredService<DomainNameValidator>();
        Assert.Equal("DomainIsPublicSuffix", Assert.Throws<ServiceException>(() => validator.Normalize("github.io")).Code);
        Assert.Equal("DomainIsPublicSuffix", Assert.Throws<ServiceException>(() => validator.Normalize("co.uk")).Code);
        Assert.Equal("mysite.github.io", validator.Normalize("MySite.github.io"));
    }

    [Fact]
    public async Task TheEmailMethodStaysUnavailable_WithoutAProvider()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        await using var scope = host.Services.CreateAsyncScope();

        Assert.IsType<NotConfiguredEmailSender>(scope.ServiceProvider.GetRequiredService<IEmailSender>());
        Assert.False(scope.ServiceProvider.GetRequiredService<EmailVerificationService>().IsAvailable);
    }

    [Fact]
    public async Task TheDnsResolversDefaultToTwoPublicOnes_AndCanBeConfigured()
    {
        await using var defaults = await ApiHost.StartAsync(_postgres);
        var settings = defaults.Services.GetRequiredService<ApiSettings>();
        Assert.Equal(new[] { "1.1.1.1", "8.8.8.8" }, settings.DnsServers.Select(s => s.ToString()).ToArray());
        Assert.Equal(5, settings.DnsTimeoutSeconds);

        await using var custom = await ApiHost.StartAsync(_postgres, new Dictionary<string, string?>
        {
            ["CipherSurface:Verification:DnsServers:0"] = "9.9.9.9",
            ["CipherSurface:Verification:DnsServers:1"] = "2606:4700:4700::1111",
            ["CipherSurface:Verification:DnsTimeoutSeconds"] = "10"
        });
        var configured = custom.Services.GetRequiredService<ApiSettings>();
        Assert.Equal(new[] { "9.9.9.9", "2606:4700:4700::1111" }, configured.DnsServers.Select(s => s.ToString()).ToArray());
        Assert.Equal(10, configured.DnsTimeoutSeconds);
    }

    [Fact]
    public async Task StartUpLogsWhichListWasLoaded_WhenAFileOverridesTheBundledOne()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var line = Assert.Single(host.Logs.Lines, l => l.Contains("Public Suffix List loaded"));
        Assert.Contains("public_suffix_list.dat", line);   // the override file's path
        Assert.DoesNotContain("embedded resource", line);
    }

    // ------------------------------------------------------------------ fail closed

    [Fact]
    public async Task TheApiRefusesToStart_WhenThePublicSuffixListIsMissing()
    {
        var missing = Path.Combine(Path.GetTempPath(), "no-such-list-" + Guid.NewGuid().ToString("N") + ".dat");

        var ex = await Assert.ThrowsAsync<ApiConfigurationException>(() =>
            ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:Verification:PublicSuffixListFile"] = missing }));

        Assert.Contains("Public Suffix List", ex.Message);
    }

    [Theory]
    [InlineData("// nothing but a comment\n")]
    [InlineData("com\na..b\nco.uk\n")]
    public async Task TheApiRefusesToStart_WhenThePublicSuffixListIsEmptyOrMalformed(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), "bad-list-" + Guid.NewGuid().ToString("N") + ".dat");
        await File.WriteAllTextAsync(path, content);
        try
        {
            var ex = await Assert.ThrowsAsync<ApiConfigurationException>(() =>
                ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:Verification:PublicSuffixListFile"] = path }));

            Assert.Contains("Public Suffix List", ex.Message);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task TheApiStartsWithTheBundledList_WithoutAnySettingAndWithoutDownloadingAnything()
    {
        // No override: the host reads the list embedded in CipherSurface.Services.dll. If the data file was never fetched this
        // fails with the command to run, exactly as a real start-up would.
        await using var host = await ApiHost.StartAsync(_postgres, new Dictionary<string, string?> { ["CipherSurface:Verification:PublicSuffixListFile"] = null });

        var list = Assert.IsType<PublicSuffixList>(host.Services.GetRequiredService<IPublicSuffixCheck>());
        Assert.True(list.RuleCount > 5000);
        Assert.True(list.IsPublicSuffix("co.uk"));

        // The start-up log says which list was used and how many rules it has: the signal to look for in a deployment.
        var line = Assert.Single(host.Logs.Lines, l => l.Contains("Public Suffix List loaded"));
        Assert.Contains("the embedded resource", line);
        Assert.Contains($"{list.RuleCount} rules", line);
        await using var scope = host.Services.CreateAsyncScope();
        var validator = scope.ServiceProvider.GetRequiredService<DomainNameValidator>();
        Assert.Equal("DomainIsPublicSuffix", Assert.Throws<ServiceException>(() => validator.Normalize("com.pk")).Code);
    }
}
