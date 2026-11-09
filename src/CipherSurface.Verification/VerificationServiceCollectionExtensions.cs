using System.Net;
using CipherSurface.Verification.Email;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CipherSurface.Verification;

/// <summary>How proof of ownership is checked from the outside.</summary>
public sealed record VerificationSetup
{
    /// <summary>
    /// Two independent public resolvers. A resolver that is down never invalidates a proof another one confirms (the
    /// token is accepted if any resolver sees it), but with no resolver seeing it, one failure makes the check inconclusive.
    /// </summary>
    public static IReadOnlyList<IPAddress> DefaultDnsServers { get; } = [IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8")];

    public IReadOnlyList<IPAddress> DnsServers { get; init; } = DefaultDnsServers;
    public TimeSpan DnsTimeout { get; init; } = TimeSpan.FromSeconds(5);
}

public static class VerificationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the verifier registry (DNS TXT, HTTP file, HTML meta), the SSRF-guarded web client, and an email sender
    /// that refuses to send until a real provider replaces it (TryAdd: register your IEmailSender first to override).
    /// </summary>
    public static IServiceCollection AddCipherSurfaceVerification(this IServiceCollection services, VerificationSetup? setup = null)
    {
        setup ??= new VerificationSetup();
        if (setup.DnsServers.Count == 0)
            throw new ArgumentException("At least one DNS server is required.", nameof(setup));
        if (setup.DnsTimeout < TimeSpan.FromSeconds(1) || setup.DnsTimeout > TimeSpan.FromSeconds(30))
            throw new ArgumentException("The DNS timeout must be between 1 and 30 seconds.", nameof(setup));

        services.TryAddSingleton<IEmailSender, NotConfiguredEmailSender>();
        services.TryAddSingleton<IWebProofClient>(_ => SafeWebClient.CreateDefault());
        services.TryAddSingleton(provider =>
        {
            var resolvers = setup.DnsServers.Select(server => (IDnsTxtResolver)new DnsClientTxtResolver(server, setup.DnsTimeout)).ToList();
            var web = provider.GetRequiredService<IWebProofClient>();
            return new VerifierRegistry([new DnsTxtVerifier(resolvers), new HttpFileVerifier(web), new HtmlMetaVerifier(web)]);
        });
        return services;
    }
}
