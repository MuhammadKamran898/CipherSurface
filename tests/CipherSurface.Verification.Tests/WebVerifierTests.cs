using CipherSurface.Data.Enums;
using Xunit;

namespace CipherSurface.Verification.Tests;

public class WebVerifierTests
{
    private const string Token = "abcDEF0123456789_-xyz";
    private static readonly string Expected = "ciphersurface-verify=" + Token;

    /// <summary>Returns canned results per scheme and records every URL requested.</summary>
    private sealed class FakeWeb : IWebProofClient
    {
        private readonly WebFetchResult _https;
        private readonly WebFetchResult _http;
        public List<string> Urls { get; } = new();
        public FakeWeb(WebFetchResult https, WebFetchResult? http = null)
        {
            _https = https;
            _http = http ?? https;
        }
        public Task<WebFetchResult> FetchAsync(Uri url, int maxBytes, CancellationToken ct)
        {
            Urls.Add(url.ToString());
            return Task.FromResult(url.Scheme == "https" ? _https : _http);
        }
    }

    private static WebFetchResult Body(string body, bool truncated = false) =>
        new(WebFetchStatus.Ok, 200, body, "example.com", truncated);
    private static WebFetchResult Status(WebFetchStatus status, int? code = null) =>
        new(status, code, null, null, false);

    private static Task<VerificationObservation> CheckFile(FakeWeb web, string token = Token) =>
        new HttpFileVerifier(web).CheckAsync(new VerificationRequest(VerificationMethod.HttpFile, "example.com", token), CancellationToken.None);

    private static Task<VerificationObservation> CheckMeta(FakeWeb web, string token = Token) =>
        new HtmlMetaVerifier(web).CheckAsync(new VerificationRequest(VerificationMethod.HtmlMeta, "example.com", token), CancellationToken.None);

    // ---------------- HTTP file ----------------

    [Fact]
    public async Task File_ExactContent_IsValid_AndUsesTheWellKnownUrl()
    {
        var web = new FakeWeb(Body(Expected));
        var result = await CheckFile(web);
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
        Assert.Equal("https://example.com/.well-known/ciphersurface-verify.txt", Assert.Single(web.Urls));
    }

    [Fact]
    public async Task File_SurroundingWhitespaceAndNewline_IsValid()
    {
        var result = await CheckFile(new FakeWeb(Body("  " + Expected + "\r\n")));
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
    }

    [Theory]
    [InlineData("")]
    [InlineData("something else")]
    [InlineData("ciphersurface-verify=differentTokenValue123456")]
    public async Task File_WrongContent_IsAbsent(string body)
    {
        var result = await CheckFile(new FakeWeb(Body(body)));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
        Assert.Equal(Reasons.ContentMismatch, result.Reason);
    }

    [Fact]
    public async Task File_TokenInsideLongerPage_IsNotAccepted()
    {
        var result = await CheckFile(new FakeWeb(Body("<html>" + Expected + "</html>")));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
    }

    [Fact]
    public async Task File_TruncatedBody_IsAbsent()
    {
        var result = await CheckFile(new FakeWeb(Body(Expected, truncated: true)));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
    }

    [Theory]
    [InlineData(WebFetchStatus.NotFound, Reasons.NotFound)]
    [InlineData(WebFetchStatus.HostNotFound, Reasons.HostNotFound)]
    [InlineData(WebFetchStatus.RedirectRefused, Reasons.RedirectRefused)]
    [InlineData(WebFetchStatus.TooManyRedirects, Reasons.TooManyRedirects)]
    public async Task File_DefiniteFailures_AreAbsent(WebFetchStatus status, string reason)
    {
        var result = await CheckFile(new FakeWeb(Status(status, 404)));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
        Assert.Equal(reason, result.Reason);
    }

    [Theory]
    [InlineData(503)]
    [InlineData(500)]
    [InlineData(403)]
    [InlineData(429)]
    public async Task File_TargetSideErrors_AreInconclusive(int code)
    {
        var result = await CheckFile(new FakeWeb(Status(WebFetchStatus.HttpError, code)));
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
        Assert.Equal($"HttpStatus{code}", result.Reason);
    }

    [Fact]
    public async Task File_BlockedDestination_IsInconclusive_AndDoesNotFallBackToHttp()
    {
        var web = new FakeWeb(Status(WebFetchStatus.Blocked));
        var result = await CheckFile(web);
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
        Assert.Equal(Reasons.DestinationBlocked, result.Reason);
        Assert.Single(web.Urls);
    }

    [Fact]
    public async Task File_HttpsTransportFailure_FallsBackToHttp()
    {
        var web = new FakeWeb(Status(WebFetchStatus.Failure), Body(Expected));
        var result = await CheckFile(web);
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
        Assert.Equal(new[]
        {
            "https://example.com/.well-known/ciphersurface-verify.txt",
            "http://example.com/.well-known/ciphersurface-verify.txt"
        }, web.Urls);
    }

    [Fact]
    public async Task File_BothSchemesFail_IsInconclusive()
    {
        var result = await CheckFile(new FakeWeb(Status(WebFetchStatus.Failure)));
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
        Assert.Equal(Reasons.ConnectionFailure, result.Reason);
    }

    [Fact]
    public async Task File_DefiniteAnswerOverHttps_NeverTriesHttp()
    {
        var web = new FakeWeb(Status(WebFetchStatus.NotFound, 404), Body(Expected));
        var result = await CheckFile(web);
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
        Assert.Single(web.Urls);
    }

    [Theory]
    [InlineData("93.184.216.34", Token)]
    [InlineData("Example.com", Token)]
    [InlineData("example.com", "short")]
    public async Task File_InvalidRequest_IsInconclusive_AndNothingIsFetched(string host, string token)
    {
        var web = new FakeWeb(Body(Expected));
        var result = await new HttpFileVerifier(web).CheckAsync(
            new VerificationRequest(VerificationMethod.HttpFile, host, token), CancellationToken.None);
        Assert.Equal(Reasons.InvalidRequest, result.Reason);
        Assert.Empty(web.Urls);
    }

    [Fact]
    public async Task File_ClientThatThrows_IsInconclusive()
    {
        var verifier = new HttpFileVerifier(new ThrowingWeb());
        var result = await verifier.CheckAsync(
            new VerificationRequest(VerificationMethod.HttpFile, "example.com", Token), CancellationToken.None);
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
        Assert.Equal(Reasons.VerifierError, result.Reason);
    }

    private sealed class ThrowingWeb : IWebProofClient
    {
        public Task<WebFetchResult> FetchAsync(Uri url, int maxBytes, CancellationToken ct) => throw new InvalidOperationException("boom");
    }

    // ---------------- HTML meta tag ----------------

    private static string Page(string head, string body = "") =>
        $"<!doctype html><html><head><title>t</title>{head}</head><body>{body}</body></html>";

    [Theory]
    [InlineData("<meta name=\"ciphersurface-verify\" content=\"" + Token + "\">")]
    [InlineData("<meta content=\"" + Token + "\" name=\"ciphersurface-verify\">")]
    [InlineData("<meta name='ciphersurface-verify' content='" + Token + "'/>")]
    [InlineData("<META NAME=\"CipherSurface-Verify\" CONTENT=\"" + Token + "\" />")]
    [InlineData("<meta charset=\"utf-8\"><meta name=\"ciphersurface-verify\" content=\"  " + Token + "  \">")]
    public async Task Meta_TagInHead_IsValid(string tag)
    {
        var web = new FakeWeb(Body(Page(tag)));
        var result = await CheckMeta(web);
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
        Assert.Equal("https://example.com/", Assert.Single(web.Urls));
    }

    [Fact]
    public async Task Meta_WrongToken_IsAbsent()
    {
        var result = await CheckMeta(new FakeWeb(Body(Page("<meta name=\"ciphersurface-verify\" content=\"otherTokenValue1234567\">"))));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
        Assert.Equal(Reasons.ContentMismatch, result.Reason);
    }

    [Fact]
    public async Task Meta_TagInBodyOnly_IsIgnored()
    {
        var injected = "<meta name=\"ciphersurface-verify\" content=\"" + Token + "\">";
        var result = await CheckMeta(new FakeWeb(Body(Page("", injected))));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
    }

    [Fact]
    public async Task Meta_NameWithOtherContent_IsAbsent()
    {
        var result = await CheckMeta(new FakeWeb(Body(Page("<meta name=\"description\" content=\"" + Token + "\">"))));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
    }

    [Fact]
    public async Task Meta_NotFoundHomepage_IsAbsent()
    {
        var result = await CheckMeta(new FakeWeb(Status(WebFetchStatus.NotFound, 404)));
        Assert.Equal(CheckOutcome.ProofAbsent, result.Outcome);
    }

    [Fact]
    public async Task Meta_ServerError_IsInconclusive()
    {
        var result = await CheckMeta(new FakeWeb(Status(WebFetchStatus.HttpError, 502)));
        Assert.Equal(CheckOutcome.Inconclusive, result.Outcome);
    }

    [Fact]
    public async Task Meta_HttpsFailureThenHttpOk_IsValid()
    {
        var tag = "<meta name=\"ciphersurface-verify\" content=\"" + Token + "\">";
        var web = new FakeWeb(Status(WebFetchStatus.Failure), Body(Page(tag)));
        var result = await CheckMeta(web);
        Assert.Equal(CheckOutcome.ProofValid, result.Outcome);
        Assert.Equal(2, web.Urls.Count);
    }

    [Fact]
    public async Task Meta_InvalidRequest_IsInconclusive()
    {
        var web = new FakeWeb(Body(Page("")));
        var result = await new HtmlMetaVerifier(web).CheckAsync(
            new VerificationRequest(VerificationMethod.HtmlMeta, "localhost", Token), CancellationToken.None);
        Assert.Equal(Reasons.InvalidRequest, result.Reason);
        Assert.Empty(web.Urls);
    }
}
