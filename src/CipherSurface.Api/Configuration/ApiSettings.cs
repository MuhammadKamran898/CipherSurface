using System.Net;
using CipherSurface.Verification;

namespace CipherSurface.Api.Configuration;

/// <summary>The configuration is wrong or incomplete. The API refuses to start rather than run with a weaker setup.</summary>
public sealed class ApiConfigurationException : Exception
{
    public ApiConfigurationException(IReadOnlyList<string> problems)
        : base("The API configuration is not valid: " + string.Join(" ", problems)) => Problems = problems;

    public IReadOnlyList<string> Problems { get; }
}

public sealed record RetiredKeySetting(string KeyId, string File);

/// <summary>
/// Everything the API reads from configuration (appsettings or environment variables such as
/// CipherSurface__Jwt__PrivateKeyFile). Secrets are never part of an error message, and a missing optional list means
/// the most restrictive behaviour: nobody is a platform administrator, no browser origin is allowed, no proxy is trusted.
/// </summary>
public sealed class ApiSettings
{
    public const string SectionName = "CipherSurface";
    public const int MinimumSetupTokenLength = 32;

    public string ConnectionString { get; private init; } = "";
    public string? JwtIssuer { get; private init; }
    public string? JwtAudience { get; private init; }
    public string JwtPrivateKeyFile { get; private init; } = "";
    public string JwtKeyId { get; private init; } = "";
    public IReadOnlyList<RetiredKeySetting> RetiredKeys { get; private init; } = [];
    public string? SetupToken { get; private init; }
    public IReadOnlyList<Guid> PlatformAdminUserIds { get; private init; } = [];
    public IReadOnlyList<string> CorsOrigins { get; private init; } = [];
    public IReadOnlyList<IPAddress> KnownProxies { get; private init; } = [];
    public int AuthRequestsPerMinute { get; private init; } = 10;
    public int InvitationRequestsPerMinute { get; private init; } = 10;
    public int GlobalRequestsPerMinute { get; private init; } = 300;
    public IReadOnlyList<IPAddress> DnsServers { get; private init; } = VerificationSetup.DefaultDnsServers;
    public int DnsTimeoutSeconds { get; private init; } = 5;

    /// <summary>The web app page that email confirmation links open (https only). Unset means the email method stays unavailable.</summary>
    public string? EmailConfirmationPage { get; private init; }

    /// <summary>A Public Suffix List file to use instead of the one bundled in the build.</summary>
    public string? PublicSuffixListFile { get; private init; }

    public int InvitationLifetimeDays { get; private init; } = 7;
    public int MaxPendingInvitationsPerOrganization { get; private init; } = 100;

    /// <summary>Where the web app handles invitation links, for example https://app.example.com/accept-invitation. The token is appended after "#" so it never travels to a server in a URL.</summary>
    public string? InvitationAcceptBaseUrl { get; private init; }

    public static ApiSettings Load(IConfiguration configuration)
    {
        var problems = new List<string>();
        var section = configuration.GetSection(SectionName);

        var connection = configuration.GetConnectionString("CipherSurface");
        if (string.IsNullOrWhiteSpace(connection))
            problems.Add("ConnectionStrings:CipherSurface is required.");

        var keyFile = section["Jwt:PrivateKeyFile"];
        if (string.IsNullOrWhiteSpace(keyFile))
            problems.Add($"{SectionName}:Jwt:PrivateKeyFile is required.");

        var keyId = section["Jwt:KeyId"];
        if (!IsValidKeyId(keyId))
            problems.Add($"{SectionName}:Jwt:KeyId is required (1 to 64 letters, digits, '.', '_' or '-').");

        var retired = new List<RetiredKeySetting>();
        foreach (var item in section.GetSection("Jwt:RetiredPublicKeys").GetChildren())
        {
            var id = item["KeyId"];
            var file = item["File"];
            if (!IsValidKeyId(id) || string.IsNullOrWhiteSpace(file))
                problems.Add($"{SectionName}:Jwt:RetiredPublicKeys:{item.Key} needs a KeyId and a File.");
            else if (id == keyId || retired.Any(r => r.KeyId == id))
                problems.Add($"{SectionName}:Jwt:RetiredPublicKeys:{item.Key} repeats a key id.");
            else
                retired.Add(new RetiredKeySetting(id!, file!));
        }

        var setupToken = section["Setup:Token"];
        if (!string.IsNullOrEmpty(setupToken) && setupToken.Length < MinimumSetupTokenLength)
            problems.Add($"{SectionName}:Setup:Token must be at least {MinimumSetupTokenLength} characters, or left unset to disable setup.");

        var admins = new List<Guid>();
        foreach (var item in section.GetSection("PlatformAdmins:UserIds").GetChildren())
        {
            if (Guid.TryParse(item.Value, out var id) && id != Guid.Empty) admins.Add(id);
            else problems.Add($"{SectionName}:PlatformAdmins:UserIds:{item.Key} is not a valid user id.");
        }

        var origins = new List<string>();
        foreach (var item in section.GetSection("Cors:AllowedOrigins").GetChildren())
        {
            var origin = NormalizeOrigin(item.Value);
            if (origin is null) problems.Add($"{SectionName}:Cors:AllowedOrigins:{item.Key} must be an origin such as https://app.example.com (no wildcard, no path).");
            else if (!origins.Contains(origin)) origins.Add(origin);
        }

        var proxies = new List<IPAddress>();
        foreach (var item in section.GetSection("ForwardedHeaders:KnownProxies").GetChildren())
        {
            if (IPAddress.TryParse(item.Value, out var address)) proxies.Add(address);
            else problems.Add($"{SectionName}:ForwardedHeaders:KnownProxies:{item.Key} is not a valid IP address.");
        }

        var authLimit = ReadPositive(section, "RateLimiting:AuthRequestsPerMinute", 10, problems);
        var dnsServers = new List<IPAddress>();
        foreach (var item in section.GetSection("Verification:DnsServers").GetChildren())
        {
            if (IPAddress.TryParse(item.Value, out var server) && !server.Equals(IPAddress.Any) && !server.Equals(IPAddress.IPv6Any) && !dnsServers.Contains(server))
                dnsServers.Add(server);
            else
                problems.Add($"{SectionName}:Verification:DnsServers:{item.Key} must be a unique, valid IP address.");
        }
        if (dnsServers.Count > 5) problems.Add($"{SectionName}:Verification:DnsServers can list at most 5 servers.");

        var dnsTimeout = ReadPositive(section, "Verification:DnsTimeoutSeconds", 5, problems);
        if (dnsTimeout > 30) problems.Add($"{SectionName}:Verification:DnsTimeoutSeconds must be between 1 and 30.");

        var emailPage = section["Verification:EmailConfirmationPage"];
        string? emailConfirmationPage = null;
        if (!string.IsNullOrWhiteSpace(emailPage))
        {
            emailConfirmationPage = NormalizeHttpsPage(emailPage);
            if (emailConfirmationPage is null)
                problems.Add($"{SectionName}:Verification:EmailConfirmationPage must be an https URL without a query string or fragment.");
        }

        var suffixFile = NullIfBlank(section["Verification:PublicSuffixListFile"]);

        var invitationLimit = ReadPositive(section, "RateLimiting:InvitationRequestsPerMinute", 10, problems);
        var globalLimit = ReadPositive(section, "RateLimiting:GlobalRequestsPerMinute", 300, problems);

        var lifetimeDays = ReadPositive(section, "Invitations:LifetimeDays", 7, problems);
        if (lifetimeDays > 30) problems.Add($"{SectionName}:Invitations:LifetimeDays must be between 1 and 30.");
        var maxPending = ReadPositive(section, "Invitations:MaxPendingPerOrganization", 100, problems);
        if (maxPending > 1000) problems.Add($"{SectionName}:Invitations:MaxPendingPerOrganization must be between 1 and 1000.");

        var acceptBase = section["Invitations:AcceptBaseUrl"];
        string? acceptBaseUrl = null;
        if (!string.IsNullOrWhiteSpace(acceptBase))
        {
            acceptBaseUrl = NormalizeAcceptBaseUrl(acceptBase);
            if (acceptBaseUrl is null)
                problems.Add($"{SectionName}:Invitations:AcceptBaseUrl must be an https URL (http only for localhost) without a query string or fragment.");
        }

        if (problems.Count > 0) throw new ApiConfigurationException(problems);

        return new ApiSettings
        {
            ConnectionString = connection!,
            JwtIssuer = NullIfBlank(section["Jwt:Issuer"]),
            JwtAudience = NullIfBlank(section["Jwt:Audience"]),
            JwtPrivateKeyFile = keyFile!,
            JwtKeyId = keyId!,
            RetiredKeys = retired,
            SetupToken = string.IsNullOrEmpty(setupToken) ? null : setupToken,
            PlatformAdminUserIds = admins,
            CorsOrigins = origins,
            KnownProxies = proxies,
            AuthRequestsPerMinute = authLimit,
            InvitationRequestsPerMinute = invitationLimit,
            GlobalRequestsPerMinute = globalLimit,
            DnsServers = dnsServers.Count == 0 ? VerificationSetup.DefaultDnsServers : dnsServers,
            DnsTimeoutSeconds = dnsTimeout,
            EmailConfirmationPage = emailConfirmationPage,
            PublicSuffixListFile = suffixFile,
            InvitationLifetimeDays = lifetimeDays,
            MaxPendingInvitationsPerOrganization = maxPending,
            InvitationAcceptBaseUrl = acceptBaseUrl
        };
    }

    private static bool IsValidKeyId(string? id) =>
        !string.IsNullOrEmpty(id) && id.Length <= 64 && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string? NormalizeOrigin(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains('*')) return null;
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme is not ("http" or "https")) return null;
        if (uri.PathAndQuery != "/" || !string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.UserInfo)) return null;
        return uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
    }

    private static string? NormalizeHttpsPage(string value)
    {
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme != Uri.UriSchemeHttps) return null;
        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.UserInfo)) return null;
        return uri.GetLeftPart(UriPartial.Path);
    }

    private static string? NormalizeAcceptBaseUrl(string value)
    {
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)) return null;
        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.UserInfo)) return null;
        var secure = uri.Scheme == Uri.UriSchemeHttps;
        var localHttp = uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
        if (!secure && !localHttp) return null;
        return uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
    }

    private static int ReadPositive(IConfigurationSection section, string key, int fallback, List<string> problems)
    {
        var raw = section[key];
        if (string.IsNullOrWhiteSpace(raw)) return fallback;
        if (int.TryParse(raw, out var value) && value > 0) return value;
        problems.Add($"{SectionName}:{key} must be a positive whole number.");
        return fallback;
    }
}
