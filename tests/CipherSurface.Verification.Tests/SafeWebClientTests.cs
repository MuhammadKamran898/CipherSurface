using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace CipherSurface.Verification.Tests;

public class SafeWebClientTests
{
    private sealed class FuncHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public List<Uri> Requests { get; } = new();
        public FuncHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request.RequestUri!);
            return Task.FromResult(_respond(request));
        }
    }

    private static HttpResponseMessage Ok(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8) };

    private static HttpResponseMessage Redirect(string location)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Found);
        response.Headers.Location = new Uri(location, UriKind.RelativeOrAbsolute);
        return response;
    }

    private static SafeWebClient Client(FuncHandler handler) => new(new HttpClient(handler));

    [Fact]
    public async Task Ok_ReturnsBodyAndFinalHost()
    {
        var result = await Client(new FuncHandler(_ => Ok("hello")))
            .FetchAsync(new Uri("https://example.com/x"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.Ok, result.Status);
        Assert.Equal("hello", result.Body);
        Assert.Equal("example.com", result.FinalHost);
        Assert.False(result.BodyTruncated);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, WebFetchStatus.NotFound)]
    [InlineData(HttpStatusCode.Gone, WebFetchStatus.NotFound)]
    [InlineData(HttpStatusCode.Forbidden, WebFetchStatus.HttpError)]
    [InlineData(HttpStatusCode.TooManyRequests, WebFetchStatus.HttpError)]
    [InlineData(HttpStatusCode.InternalServerError, WebFetchStatus.HttpError)]
    [InlineData(HttpStatusCode.ServiceUnavailable, WebFetchStatus.HttpError)]
    public async Task StatusCodes_AreClassified(HttpStatusCode code, WebFetchStatus expected)
    {
        var result = await Client(new FuncHandler(_ => new HttpResponseMessage(code)))
            .FetchAsync(new Uri("https://example.com/x"), 1000, CancellationToken.None);

        Assert.Equal(expected, result.Status);
        Assert.Equal((int)code, result.StatusCode);
    }

    [Fact]
    public async Task SameHostHttpToHttpsRedirect_IsFollowed()
    {
        var handler = new FuncHandler(r => r.RequestUri!.Scheme == "http" ? Redirect("https://example.com/x") : Ok("secure"));

        var result = await Client(handler).FetchAsync(new Uri("http://example.com/x"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.Ok, result.Status);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task RelativeRedirectOnSameHost_IsFollowed()
    {
        var handler = new FuncHandler(r => r.RequestUri!.AbsolutePath == "/a" ? Redirect("/b") : Ok("b"));

        var result = await Client(handler).FetchAsync(new Uri("https://example.com/a"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.Ok, result.Status);
    }

    [Theory]
    [InlineData("https://evil.example.net/x")]       // different host
    [InlineData("https://www.example.com/x")]        // subdomain is a different host
    [InlineData("//evil.example.net/x")]             // scheme-relative to another host
    [InlineData("https://example.com:8443/x")]       // non-default port
    [InlineData("https://user:pw@example.com/x")]    // credentials in the URL
    [InlineData("ftp://example.com/x")]              // other scheme
    [InlineData("http://example.com/x")]             // https to http downgrade
    public async Task RefusedRedirects_AreNotFollowed(string location)
    {
        var handler = new FuncHandler(_ => Redirect(location));

        var result = await Client(handler).FetchAsync(new Uri("https://example.com/x"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.RedirectRefused, result.Status);
        Assert.Single(handler.Requests); // the refused target was never requested
    }

    [Fact]
    public async Task RedirectLoop_StopsAfterTheLimit()
    {
        var handler = new FuncHandler(_ => Redirect("/loop"));

        var result = await Client(handler).FetchAsync(new Uri("https://example.com/loop"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.TooManyRedirects, result.Status);
        Assert.Equal(4, handler.Requests.Count); // first request + 3 redirects
    }

    [Fact]
    public async Task OversizedBody_IsTruncatedAtTheCap()
    {
        var result = await Client(new FuncHandler(_ => Ok(new string('a', 10_000))))
            .FetchAsync(new Uri("https://example.com/x"), 100, CancellationToken.None);

        Assert.Equal(WebFetchStatus.Ok, result.Status);
        Assert.True(result.BodyTruncated);
        Assert.Equal(100, result.Body!.Length);
    }

    [Fact]
    public async Task BlockedDestination_FromTheConnector_IsReportedAsBlocked()
    {
        var handler = new FuncHandler(_ => throw new HttpRequestException("x", new BlockedDestinationException("private")));

        var result = await Client(handler).FetchAsync(new Uri("https://example.com/x"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.Blocked, result.Status);
    }

    [Fact]
    public async Task UnresolvableHost_IsHostNotFound()
    {
        var handler = new FuncHandler(_ => throw new HttpRequestException("x", new SocketException((int)SocketError.HostNotFound)));

        var result = await Client(handler).FetchAsync(new Uri("https://example.com/x"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.HostNotFound, result.Status);
    }

    [Fact]
    public async Task TransientDnsFailure_IsAFailureNotHostNotFound()
    {
        var handler = new FuncHandler(_ => throw new HttpRequestException("x", new SocketException((int)SocketError.TryAgain)));

        var result = await Client(handler).FetchAsync(new Uri("https://example.com/x"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.Failure, result.Status);
    }

    [Fact]
    public async Task OwnTimeout_IsAFailure()
    {
        var handler = new FuncHandler(_ => throw new TaskCanceledException());

        var result = await Client(handler).FetchAsync(new Uri("https://example.com/x"), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.Failure, result.Status);
    }

    [Fact]
    public async Task CallerCancellation_Propagates()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var handler = new FuncHandler(_ => throw new OperationCanceledException(cts.Token));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Client(handler).FetchAsync(new Uri("https://example.com/x"), 1000, cts.Token));
    }

    [Theory]
    [InlineData("http://example.com:8080/x")]
    [InlineData("https://user:pw@example.com/x")]
    [InlineData("https://93.184.216.34/x")]
    [InlineData("ftp://example.com/x")]
    public async Task UnsafeStartUrls_AreBlockedWithoutAnyRequest(string url)
    {
        var handler = new FuncHandler(_ => Ok("never"));

        var result = await Client(handler).FetchAsync(new Uri(url), 1000, CancellationToken.None);

        Assert.Equal(WebFetchStatus.Blocked, result.Status);
        Assert.Empty(handler.Requests);
    }
}
