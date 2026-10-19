using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;

namespace CipherSurface.Verification;

public enum WebFetchStatus
{
    Ok,
    NotFound,          // 404 / 410
    HttpError,         // any other non-2xx (403, 429, 5xx ...)
    HostNotFound,      // NXDOMAIN / no address
    Blocked,           // SSRF protection refused the destination
    Failure,           // timeout, connection reset, TLS failure ...
    RedirectRefused,   // cross-host, downgrade, odd port, userinfo
    TooManyRedirects
}

public sealed record WebFetchResult(WebFetchStatus Status, int? StatusCode, string? Body, string? FinalHost, bool BodyTruncated);

public interface IWebProofClient
{
    Task<WebFetchResult> FetchAsync(Uri url, int maxBytes, CancellationToken ct);
}

public sealed record SafeWebClientOptions
{
    public TimeSpan TotalTimeout { get; init; } = TimeSpan.FromSeconds(10);
    public int MaxRedirects { get; init; } = 3;
}

/// <summary>
/// Bounded, SSRF-hardened GET. Redirects are followed manually: same host only, http to https
/// allowed, no downgrade, default ports only. Body size and total time are capped.
/// Use CreateDefault() in production so every connection goes through PinnedConnector.
/// </summary>
public sealed class SafeWebClient : IWebProofClient
{
    private readonly HttpClient _http;
    private readonly SafeWebClientOptions _options;

    public SafeWebClient(HttpClient http, SafeWebClientOptions? options = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _options = options ?? new SafeWebClientOptions();
    }

    public static SafeWebClient CreateDefault(IHostResolver? resolver = null, SafeWebClientOptions? options = null)
    {
        var connector = new PinnedConnector(resolver);
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,                       // a proxy would bypass the pinned connection
            AllowAutoRedirect = false,              // redirects are validated manually
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(1),
            ConnectCallback = connector.ConnectAsync
        };
        return new SafeWebClient(new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan }, options);
    }

    public async Task<WebFetchResult> FetchAsync(Uri url, int maxBytes, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (maxBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        if (!IsAllowedStart(url)) return Of(WebFetchStatus.Blocked);

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(_options.TotalTimeout);
        var current = url;

        for (var hop = 0; hop <= _options.MaxRedirects; hop++)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, current);
                request.Headers.UserAgent.ParseAdd("CipherSurface-Verifier/1.0");
                using var response = await _http
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, budget.Token)
                    .ConfigureAwait(false);
                var code = (int)response.StatusCode;

                if (code is >= 300 and < 400)
                {
                    var location = response.Headers.Location;
                    if (location is null) return Of(WebFetchStatus.HttpError, code);
                    var next = location.IsAbsoluteUri ? location : new Uri(current, location);
                    if (!IsAllowedRedirect(current, next)) return Of(WebFetchStatus.RedirectRefused, code);
                    current = next;
                    continue;
                }

                if (code is 404 or 410) return Of(WebFetchStatus.NotFound, code);
                if (code is < 200 or >= 300) return Of(WebFetchStatus.HttpError, code);

                var (body, truncated) = await ReadBoundedAsync(response.Content, maxBytes, budget.Token).ConfigureAwait(false);
                return new WebFetchResult(WebFetchStatus.Ok, code, body, current.DnsSafeHost, truncated);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw; // the caller cancelled; a timeout of our own budget falls through to Classify
            }
            catch (Exception ex)
            {
                return Classify(ex);
            }
        }

        return Of(WebFetchStatus.TooManyRedirects);
    }

    private static bool IsAllowedStart(Uri url) =>
        url.IsAbsoluteUri
        && (url.Scheme == Uri.UriSchemeHttp || url.Scheme == Uri.UriSchemeHttps)
        && string.IsNullOrEmpty(url.UserInfo)
        && url.IsDefaultPort
        && ProofFormat.IsValidHost(url.DnsSafeHost);

    private static bool IsAllowedRedirect(Uri current, Uri next)
    {
        if (next.Scheme != Uri.UriSchemeHttp && next.Scheme != Uri.UriSchemeHttps) return false;
        if (!string.Equals(current.DnsSafeHost, next.DnsSafeHost, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrEmpty(next.UserInfo)) return false;
        if (!next.IsDefaultPort) return false;
        if (current.Scheme == Uri.UriSchemeHttps && next.Scheme == Uri.UriSchemeHttp) return false; // no downgrade
        return true;
    }

    private static async Task<(string Text, bool Truncated)> ReadBoundedAsync(HttpContent content, int maxBytes, CancellationToken ct)
    {
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var ms = new MemoryStream();
        var buffer = new byte[8192];
        var total = 0;
        while (total <= maxBytes)
        {
            var want = Math.Min(buffer.Length, maxBytes + 1 - total);
            var read = await stream.ReadAsync(buffer.AsMemory(0, want), ct).ConfigureAwait(false);
            if (read == 0) break;
            ms.Write(buffer, 0, read);
            total += read;
        }
        var truncated = total > maxBytes;
        var length = (int)Math.Min(ms.Length, maxBytes);
        return (Encoding.UTF8.GetString(ms.GetBuffer(), 0, length), truncated);
    }

    private static WebFetchResult Classify(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
        {
            if (e is BlockedDestinationException)
                return Of(WebFetchStatus.Blocked);
            if (e is SocketException { SocketErrorCode: SocketError.HostNotFound or SocketError.NoData })
                return Of(WebFetchStatus.HostNotFound);
        }
        return Of(WebFetchStatus.Failure);
    }

    private static WebFetchResult Of(WebFetchStatus status, int? code = null) => new(status, code, null, null, false);
}
