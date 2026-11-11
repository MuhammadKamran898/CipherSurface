using CipherSurface.Verification;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CipherSurface.Services;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the application services, so every host (API, workers) wires them the same way.
    ///
    /// Services that use the database are SCOPED: AddCipherSurfaceData registers the context factory as scoped (Identity
    /// shares its options), and a singleton may not depend on a scoped service. They keep no state of their own, so a new
    /// instance per request or per background job costs nothing. Stateless helpers are singletons.
    ///
    /// The host must also register: the Data layer (AddCipherSurfaceData), the Verification layer (AddCipherSurfaceVerification:
    /// verifier registry and email sender) and an IPublicSuffixCheck. Registrations here use TryAdd, so a host can replace any
    /// service or option before calling this.
    ///
    /// ScanRunService (the worker side: begin, continue, complete) is not registered: it needs the scan-payload signing key,
    /// which only the worker channel has.
    /// </summary>
    public static IServiceCollection AddCipherSurfaceServices(this IServiceCollection services, VerificationOptions? verification = null, EmailVerificationOptions? email = null)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(verification ?? new VerificationOptions());
        services.TryAddSingleton(email ?? new EmailVerificationOptions());

        services.TryAddSingleton<AuditLogWriter>();
        services.TryAddSingleton<ClaimService>();
        services.TryAddSingleton<DomainNameValidator>();

        services.TryAddScoped<DomainOnboardingService>();
        services.TryAddScoped<ChallengeService>();
        services.TryAddScoped<VerificationService>();
        services.TryAddScoped<EmailVerificationService>();
        services.TryAddScoped<EvidenceReverificationService>();
        services.TryAddScoped<EvidenceLifecycleService>();
        services.TryAddScoped<GrantService>();
        services.TryAddScoped<OrganizationService>();
        services.TryAddScoped<DisputeService>();
        services.TryAddScoped<ScanStartService>();
        services.TryAddScoped<ScopeRuleService>();
        services.TryAddScoped<DomainQueryService>();
        return services;
    }
}
