using System.Net;
using CipherSurface.Data;
using CipherSurface.Data.Enums;
using CipherSurface.Verification;
using CipherSurface.Verification.Email;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CipherSurface.Services.Tests;

/// <summary>
/// The registration extensions wire the application the same way in every host. No database is needed: the container
/// is built with scope and construction validation on, so a mis-wired service fails here the way it would fail at startup.
/// </summary>
public class ServiceRegistrationTests
{
    private static ServiceProvider Build(Action<IServiceCollection>? before = null, VerificationSetup? setup = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        before?.Invoke(services);
        services.AddCipherSurfaceData("Host=unused;Database=unused");
        services.AddSingleton<IPublicSuffixCheck>(new BasicPublicSuffixCheck());
        services.AddCipherSurfaceVerification(setup);
        services.AddCipherSurfaceServices();
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }

    private static readonly Type[] ApplicationServices =
    [
        typeof(AuditLogWriter), typeof(ClaimService), typeof(DomainNameValidator), typeof(DomainOnboardingService),
        typeof(ChallengeService), typeof(VerificationService), typeof(EmailVerificationService),
        typeof(EvidenceReverificationService), typeof(EvidenceLifecycleService), typeof(GrantService),
        typeof(OrganizationService), typeof(DisputeService), typeof(ScanStartService), typeof(ScopeRuleService)
    ];

    [Fact]
    public void EveryApplicationServiceResolvesInAScope()
    {
        using var provider = Build();
        using var scope = provider.CreateScope();

        foreach (var type in ApplicationServices)
            Assert.NotNull(scope.ServiceProvider.GetRequiredService(type));
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<VerifierRegistry>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IEmailSender>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IWebProofClient>());
    }

    [Fact]
    public void ServicesThatUseTheDatabaseAreScoped_SoTheyCannotBeResolvedFromTheRoot()
    {
        using var provider = Build();

        // The context factory is scoped (Identity shares its options), so anything using it must be scoped as well.
        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<ScanStartService>());
        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<DomainOnboardingService>());
    }

    [Fact]
    public void StatelessHelpersAreSharedAcrossScopes()
    {
        using var provider = Build();
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();

        Assert.Same(first.ServiceProvider.GetRequiredService<AuditLogWriter>(), second.ServiceProvider.GetRequiredService<AuditLogWriter>());
        Assert.Same(first.ServiceProvider.GetRequiredService<VerifierRegistry>(), second.ServiceProvider.GetRequiredService<VerifierRegistry>());
        Assert.NotSame(first.ServiceProvider.GetRequiredService<ScanStartService>(), second.ServiceProvider.GetRequiredService<ScanStartService>());
    }

    [Fact]
    public void TheRegistryKnowsTheThreeOutsideMethods_AndNotAdminEmail()
    {
        using var provider = Build();
        var registry = provider.GetRequiredService<VerifierRegistry>();

        Assert.True(registry.TryGet(VerificationMethod.DnsTxt, out _));
        Assert.True(registry.TryGet(VerificationMethod.HttpFile, out _));
        Assert.True(registry.TryGet(VerificationMethod.HtmlMeta, out _));
        Assert.False(registry.TryGet(VerificationMethod.AdminEmail, out _));   // email is confirmed by a link, not observed
    }

    [Fact]
    public void WithoutAProvider_TheEmailSenderRefuses_AndTheEmailMethodIsUnavailable()
    {
        using var provider = Build();
        using var scope = provider.CreateScope();

        Assert.IsType<NotConfiguredEmailSender>(scope.ServiceProvider.GetRequiredService<IEmailSender>());
        Assert.False(scope.ServiceProvider.GetRequiredService<EmailVerificationService>().IsAvailable);
    }

    [Fact]
    public async Task TheNotConfiguredSenderNeverSends()
    {
        var message = new EmailMessage("a@example.com", "subject", "body");

        await Assert.ThrowsAsync<InvalidOperationException>(() => new NotConfiguredEmailSender().SendAsync(message, CancellationToken.None));
    }

    [Fact]
    public void ARealSenderRegisteredFirstWins_AndMakesTheEmailMethodAvailable()
    {
        var sender = new RecordingEmailSender();
        using var provider = Build(services => services.AddSingleton<IEmailSender>(sender));
        using var scope = provider.CreateScope();

        Assert.Same(sender, scope.ServiceProvider.GetRequiredService<IEmailSender>());
        Assert.True(scope.ServiceProvider.GetRequiredService<EmailVerificationService>().IsAvailable);
    }

    [Fact]
    public void OptionsRegisteredFirstAreUsed()
    {
        var options = new VerificationOptions();
        var time = new FakeTime(TestWorld.Start);
        using var provider = Build(services =>
        {
            services.AddSingleton(options);
            services.AddSingleton<TimeProvider>(time);
        });

        Assert.Same(options, provider.GetRequiredService<VerificationOptions>());
        Assert.Same(time, provider.GetRequiredService<TimeProvider>());
    }

    [Fact]
    public void TheDefaultResolversAreTwoIndependentPublicOnes()
    {
        var setup = new VerificationSetup();

        Assert.Equal(new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8") }, setup.DnsServers);
        Assert.Equal(TimeSpan.FromSeconds(5), setup.DnsTimeout);
    }

    [Fact]
    public void ACustomResolverListIsAccepted()
    {
        using var provider = Build(setup: new VerificationSetup { DnsServers = [IPAddress.Parse("9.9.9.9")], DnsTimeout = TimeSpan.FromSeconds(10) });

        Assert.NotNull(provider.GetRequiredService<VerifierRegistry>());
    }

    [Fact]
    public void ANoResolverSetupIsRefused()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddCipherSurfaceVerification(new VerificationSetup { DnsServers = [] }));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    public void ATimeoutOutsideOneToThirtySecondsIsRefused(int seconds)
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddCipherSurfaceVerification(new VerificationSetup { DnsTimeout = TimeSpan.FromSeconds(seconds) }));
    }

    [Fact]
    public void WithoutAPublicSuffixCheck_TheContainerCannotBeBuilt()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCipherSurfaceData("Host=unused;Database=unused");
        services.AddCipherSurfaceVerification();
        services.AddCipherSurfaceServices();

        // No fallback list exists, so onboarding cannot be wired up without a real one.
        Assert.Throws<AggregateException>(() => services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true }));
    }
}

[Collection("postgres")]
public class EmailNotConfiguredTests
{
    private readonly PostgresFixture _postgres;
    public EmailNotConfiguredTests(PostgresFixture postgres) => _postgres = postgres;

    [Fact]
    public async Task IssuingFailsClosed_BeforeAnythingIsCreated()
    {
        var world = await TestWorld.CreateAsync(_postgres);
        var owner = await world.NewOrgAsync("Org");
        var domainId = await world.AddDomainAsync(owner, "example.com");
        var service = new EmailVerificationService(world.Db, world.Time, new ClaimService(world.Time, world.Audit), world.Audit,
            new NotConfiguredEmailSender(), null, new VerificationOptions());

        Assert.False(service.IsAvailable);
        var ex = await Assert.ThrowsAsync<ServiceException>(() =>
            service.IssueAsync(owner, domainId, "admin@example.com", new Uri("https://app.example.com/verify-email"), CancellationToken.None));

        Assert.Equal("EmailNotConfigured", ex.Code);
        await using var db = world.Db.CreateDbContext();
        Assert.Empty(db.VerificationChallenges);                       // no failed-challenge row, no noise
        Assert.False(db.AuditLogs.Any(a => a.Action.StartsWith("challenge.") || a.Action.StartsWith("email.")));
        Assert.True(world.Email.IsAvailable);                          // the world's recording sender is a real one
    }
}
