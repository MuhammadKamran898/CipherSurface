using System.Globalization;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using CipherSurface.Api.Configuration;
using CipherSurface.Api.Endpoints;
using CipherSurface.Api.Errors;
using CipherSurface.Api.RateLimiting;
using CipherSurface.Api.Security;
using CipherSurface.Auth;
using CipherSurface.Data;
using CipherSurface.Services;
using CipherSurface.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;

namespace CipherSurface.Api;

public static class ApiApplication
{
    public const long MaxRequestBodyBytes = 64 * 1024;

    /// <param name="configureBuilder">Lets tests supply configuration and the listening address before settings are read.</param>
    /// <param name="mapExtraEndpoints">Lets tests add endpoints that exercise the pipeline (a platform-admin route, a failing route).</param>
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configureBuilder = null, Action<WebApplication>? mapExtraEndpoints = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        configureBuilder?.Invoke(builder);

        var settings = ApiSettings.Load(builder.Configuration);
        var keys = JwtKeyLoader.Load(settings);
        var jwt = new JwtOptions();
        if (settings.JwtIssuer is not null) jwt = jwt with { Issuer = settings.JwtIssuer };
        if (settings.JwtAudience is not null) jwt = jwt with { Audience = settings.JwtAudience };

        builder.WebHost.ConfigureKestrel(o =>
        {
            o.AddServerHeader = false;
            o.Limits.MaxRequestBodySize = MaxRequestBodyBytes;
        });

        // Fail fast on a mis-wired container: every registration must be constructible and no singleton may hold a scoped service.
        builder.Host.UseDefaultServiceProvider(o =>
        {
            o.ValidateOnBuild = true;
            o.ValidateScopes = true;
        });

        var suffixes = LoadPublicSuffixList(settings);

        var services = builder.Services;
        services.AddSingleton(settings);
        services.AddCipherSurfaceData(settings.ConnectionString);
        services.AddCipherSurfaceAuth(jwt, keys, new InvitationOptions
        {
            Lifetime = TimeSpan.FromDays(settings.InvitationLifetimeDays),
            MaxPendingPerOrganization = settings.MaxPendingInvitationsPerOrganization
        });
        services.AddSingleton<IPublicSuffixCheck>(suffixes);
        services.AddCipherSurfaceVerification(new VerificationSetup
        {
            DnsServers = settings.DnsServers,
            DnsTimeout = TimeSpan.FromSeconds(settings.DnsTimeoutSeconds)
        });
        services.AddCipherSurfaceServices(governance: new GovernanceOptions { MaxDomainsPerOrganization = settings.MaxDomainsPerOrganization });
        services.AddSingleton<IPlatformAdminPolicy>(new ConfiguredPlatformAdminPolicy(settings.PlatformAdminUserIds));
        services.AddSingleton<PlatformAdminGate>();
        services.AddScoped<OrganizationContextResolver>();

        services.AddAuthentication(BearerDefaults.Scheme)
            .AddScheme<AuthenticationSchemeOptions, BearerAuthenticationHandler>(BearerDefaults.Scheme, _ => { });
        services.AddSingleton<IAuthorizationHandler, PlatformAdminHandler>();
        services.AddAuthorizationBuilder()
            .AddPolicy(ApiPolicies.PlatformAdmin, p => p.RequireAuthenticatedUser().AddRequirements(new PlatformAdminRequirement()));

        services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
        services.AddProblemDetails();
        services.AddExceptionHandler<ApiExceptionHandler>();

        AddRateLimiting(services, settings);
        services.AddSingleton<GovernanceActorLimiter>();

        if (settings.CorsOrigins.Count > 0)
        {
            services.AddCors(o => o.AddDefaultPolicy(p => p
                .WithOrigins([.. settings.CorsOrigins])
                .WithMethods("GET", "POST", "PUT", "DELETE")
                .WithHeaders("Authorization", "Content-Type", OrganizationContextResolver.HeaderName)
                .WithExposedHeaders("Retry-After")
                .SetPreflightMaxAge(TimeSpan.FromMinutes(10))));
        }

        if (settings.KnownProxies.Count > 0)
        {
            services.Configure<ForwardedHeadersOptions>(o =>
            {
                o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                o.KnownProxies.Clear();
                o.KnownIPNetworks.Clear();
                foreach (var proxy in settings.KnownProxies) o.KnownProxies.Add(proxy);
                o.ForwardLimit = 1;
            });
        }

        var app = builder.Build();
        app.Logger.LogInformation("Public Suffix List loaded: {RuleCount} rules from {Source}",
            suffixes.RuleCount, settings.PublicSuffixListFile ?? "the embedded resource");

        // Only configured proxies are trusted to say who the client is. With none configured the header is ignored.
        if (settings.KnownProxies.Count > 0) app.UseForwardedHeaders();

        app.UseExceptionHandler();
        app.UseStatusCodePages(context =>
        {
            var status = context.HttpContext.Response.StatusCode;
            return ProblemWriter.WriteAsync(context.HttpContext, status, ErrorCatalog.CodeForStatus(status), ProblemWriter.GenericDetail(status));
        });
        app.Use(async (context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                headers.CacheControl = "no-store";
                headers.XContentTypeOptions = "nosniff";
                headers["Referrer-Policy"] = "no-referrer";
                headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";
                return Task.CompletedTask;
            });
            await next();
        });

        app.UseRouting();
        if (settings.CorsOrigins.Count > 0) app.UseCors();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseMiddleware<GovernanceActorRateLimitMiddleware>();   // per-user governance limit: needs the signed-in user, so it comes after authentication

        // Secure by default: everything under /api/v1 requires a login unless an endpoint says AllowAnonymous. Unknown
        // routes, wrong methods and unsupported content types still get their plain 404, 405 and 415 problem responses
        // (a test lists every anonymous endpoint, so a new one cannot be opened by accident).
        var api = app.MapGroup("/api/v1").RequireAuthorization();
        AuthEndpoints.Map(api);
        InvitationEndpoints.Map(api);
        DomainEndpoints.Map(api);
        ScopeRuleEndpoints.Map(api);
        mapExtraEndpoints?.Invoke(app);
        return app;
    }

    /// <summary>The Public Suffix List decides which names nobody owns. There is no fallback list: without it the API does not start.</summary>
    private static PublicSuffixList LoadPublicSuffixList(ApiSettings settings)
    {
        try
        {
            return settings.PublicSuffixListFile is { } file ? PublicSuffixList.LoadFile(file) : PublicSuffixList.LoadEmbedded();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or InvalidOperationException)
        {
            throw new ApiConfigurationException([$"The Public Suffix List could not be loaded. {ex.Message}"]);
        }
    }

    private static void AddRateLimiting(IServiceCollection services, ApiSettings settings)
    {
        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.OnRejected = async (context, _) =>
            {
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                    context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
                await ProblemWriter.WriteAsync(context.HttpContext, 429, "RateLimited", ProblemWriter.GenericDetail(429));
            };

            // Both limits are per client address. Behind a proxy, configure KnownProxies, or every client shares one address.
            o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(http =>
                RateLimitPartition.GetFixedWindowLimiter(ClientIp.Of(http), _ => Window(settings.GlobalRequestsPerMinute)));
            o.AddPolicy(AuthEndpoints.RateLimitPolicy, http =>
                RateLimitPartition.GetFixedWindowLimiter(ClientIp.Of(http), _ => Window(settings.AuthRequestsPerMinute)));
            // Preview and accept take a secret token, so they get their own per-client limit, separate from login.
            o.AddPolicy(InvitationEndpoints.RateLimitPolicy, http =>
                RateLimitPartition.GetFixedWindowLimiter(ClientIp.Of(http), _ => Window(settings.InvitationRequestsPerMinute)));
            // Verify clicks make outside DNS and HTTP requests; email confirmation takes a secret token. Their own per-client limit.
            o.AddPolicy(DomainEndpoints.RateLimitPolicy, http =>
                RateLimitPartition.GetFixedWindowLimiter(ClientIp.Of(http), _ => Window(settings.VerificationRequestsPerMinute)));
            // Governance changes: per client address here, per signed-in user in GovernanceActorRateLimitMiddleware.
            o.AddPolicy(GovernanceRateLimit.Policy, http =>
                RateLimitPartition.GetFixedWindowLimiter(ClientIp.Of(http), _ => Window(settings.GovernanceRequestsPerMinute)));
        });
    }

    private static FixedWindowRateLimiterOptions Window(int permits) => new()
    {
        PermitLimit = permits,
        Window = TimeSpan.FromMinutes(1),
        QueueLimit = 0,
        AutoReplenishment = true
    };
}
