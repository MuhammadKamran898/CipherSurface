using System.Text.RegularExpressions;
using CipherSurface.Data.Enums;

namespace CipherSurface.Verification;

internal static class WebProof
{
    /// <summary>https first. Only a transport Failure falls back to http; a definite answer never does.</summary>
    public static async Task<WebFetchResult> FetchAsync(IWebProofClient client, string host, string path, int maxBytes, CancellationToken ct)
    {
        var https = await client.FetchAsync(new Uri($"https://{host}{path}"), maxBytes, ct).ConfigureAwait(false);
        if (https.Status != WebFetchStatus.Failure) return https;

        var http = await client.FetchAsync(new Uri($"http://{host}{path}"), maxBytes, ct).ConfigureAwait(false);
        return http;
    }

    /// <summary>Maps a fetch result to the three-outcome contract.</summary>
    public static VerificationObservation Map(WebFetchResult result, Func<WebFetchResult, bool> bodyContainsProof) =>
        result.Status switch
        {
            WebFetchStatus.Ok => bodyContainsProof(result)
                ? VerificationObservation.Valid()
                : VerificationObservation.Absent(Reasons.ContentMismatch),
            WebFetchStatus.NotFound => VerificationObservation.Absent(Reasons.NotFound),
            WebFetchStatus.HostNotFound => VerificationObservation.Absent(Reasons.HostNotFound),
            WebFetchStatus.RedirectRefused => VerificationObservation.Absent(Reasons.RedirectRefused),
            WebFetchStatus.TooManyRedirects => VerificationObservation.Absent(Reasons.TooManyRedirects),
            WebFetchStatus.Blocked => VerificationObservation.Inconclusive(Reasons.DestinationBlocked),
            WebFetchStatus.HttpError => VerificationObservation.Inconclusive($"{Reasons.HttpStatusPrefix}{result.StatusCode}"),
            _ => VerificationObservation.Inconclusive(Reasons.ConnectionFailure)
        };

    public static bool IsValid(VerificationRequest request, VerificationMethod expected) =>
        request.Method == expected && ProofFormat.IsValidHost(request.Host) && ProofFormat.IsValidToken(request.Token);
}

/// <summary>Fetches /.well-known/ciphersurface-verify.txt and expects exactly "ciphersurface-verify=TOKEN".</summary>
public sealed class HttpFileVerifier : IOwnershipVerifier
{
    private const int MaxBytes = 4096;
    private readonly IWebProofClient _client;

    public HttpFileVerifier(IWebProofClient client) => _client = client ?? throw new ArgumentNullException(nameof(client));

    public VerificationMethod Method => VerificationMethod.HttpFile;

    public async Task<VerificationObservation> CheckAsync(VerificationRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!WebProof.IsValid(request, Method))
            return VerificationObservation.Inconclusive(Reasons.InvalidRequest);

        var expected = ProofFormat.ExpectedValue(request.Token);
        try
        {
            var result = await WebProof.FetchAsync(_client, request.Host, ProofFormat.WellKnownPath, MaxBytes, ct).ConfigureAwait(false);
            return WebProof.Map(result, r =>
                !r.BodyTruncated && string.Equals(r.Body?.Trim(), expected, StringComparison.Ordinal));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return VerificationObservation.Inconclusive(Reasons.VerifierError);
        }
    }
}

/// <summary>
/// Fetches the homepage and looks for &lt;meta name="ciphersurface-verify" content="TOKEN"&gt; inside
/// the head. A tag after &lt;/head&gt; is ignored, because user-generated content in the body is the
/// usual way a third party could inject one.
/// </summary>
public sealed class HtmlMetaVerifier : IOwnershipVerifier
{
    private const int MaxBytes = 512 * 1024;
    private readonly IWebProofClient _client;

    public HtmlMetaVerifier(IWebProofClient client) => _client = client ?? throw new ArgumentNullException(nameof(client));

    public VerificationMethod Method => VerificationMethod.HtmlMeta;

    public async Task<VerificationObservation> CheckAsync(VerificationRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!WebProof.IsValid(request, Method))
            return VerificationObservation.Inconclusive(Reasons.InvalidRequest);

        try
        {
            var result = await WebProof.FetchAsync(_client, request.Host, "/", MaxBytes, ct).ConfigureAwait(false);
            return WebProof.Map(result, r => MetaTagParser.HasProofMeta(r.Body ?? string.Empty, request.Token));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return VerificationObservation.Inconclusive(Reasons.VerifierError);
        }
    }
}

internal static class MetaTagParser
{
    private static readonly Regex MetaTag = new(@"<meta\s[^>]*>", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(1));
    private static readonly Regex Attribute = new(
        @"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s""'=<>`]+))",
        RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    public static bool HasProofMeta(string html, string token)
    {
        var headEnd = html.IndexOf("</head", StringComparison.OrdinalIgnoreCase);
        var head = headEnd >= 0 ? html[..headEnd] : html;

        foreach (Match tag in MetaTag.Matches(head))
        {
            string? name = null;
            string? content = null;
            foreach (Match attr in Attribute.Matches(tag.Value))
            {
                var key = attr.Groups[1].Value.ToLowerInvariant();
                var value = attr.Groups[2].Success ? attr.Groups[2].Value
                          : attr.Groups[3].Success ? attr.Groups[3].Value
                          : attr.Groups[4].Value;
                if (key == "name") name = value;
                else if (key == "content") content = value;
            }

            if (string.Equals(name, ProofFormat.MetaName, StringComparison.OrdinalIgnoreCase) &&
                content is not null && string.Equals(content.Trim(), token, StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}
