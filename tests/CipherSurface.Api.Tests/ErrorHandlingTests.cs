using System.Net;
using System.Text;
using CipherSurface.Services;
using CipherSurface.Services.Tests;
using Xunit;

namespace CipherSurface.Api.Tests;

[Collection("postgres")]
public class ErrorHandlingTests
{
    private readonly PostgresFixture _postgres;
    public ErrorHandlingTests(PostgresFixture postgres) => _postgres = postgres;

    private static void MapFailingRoutes(WebApplication app)
    {
        app.MapGet("/test/boom", () => { throw new InvalidOperationException("secret detail: SELECT password_hash FROM users"); }).AllowAnonymous();
        app.MapGet("/test/known", () => { throw new ServiceException("RuleExists", "This rule already exists for the domain."); }).AllowAnonymous();
        app.MapGet("/test/unmapped", () => { throw new ServiceException("BrandNewCode", "Internal wording that must not leak."); }).AllowAnonymous();
    }

    [Fact]
    public async Task AKnownServiceError_BecomesAProblemWithItsStatus_Code_AndSafeMessage()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapFailingRoutes);

        var problem = await Check.ProblemAsync(await host.GetAsync("/test/known"), HttpStatusCode.Conflict, "RuleExists");

        Assert.Equal("Conflict", problem.GetProperty("title").GetString());
        Assert.Equal("This rule already exists for the domain.", problem.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task AnUnexpectedException_IsAGeneric500_WithNothingInternalInTheResponse()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapFailingRoutes);

        var response = await host.GetAsync("/test/boom");
        var problem = await Check.ProblemAsync(response, HttpStatusCode.InternalServerError, "InternalError");

        var text = problem.GetRawText();
        Assert.DoesNotContain("secret detail", text);
        Assert.DoesNotContain("SELECT", text);
        Assert.DoesNotContain("InvalidOperationException", text);
        Assert.DoesNotContain("   at ", text);   // no stack trace
        Assert.Contains(host.Logs.Lines, l => l.Contains("secret detail"));   // the detail goes to the server log only
    }

    [Fact]
    public async Task AServiceErrorWithoutAnHttpStatus_IsAGeneric500_AndIsLogged()
    {
        await using var host = await ApiHost.StartAsync(_postgres, map: MapFailingRoutes);

        var problem = await Check.ProblemAsync(await host.GetAsync("/test/unmapped"), HttpStatusCode.InternalServerError, "InternalError");

        Assert.DoesNotContain("Internal wording", problem.GetRawText());
        Assert.Contains(host.Logs.Lines, l => l.Contains("BrandNewCode"));
    }

    [Fact]
    public async Task AnUnknownRoute_IsAProblemToo()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        await Check.ProblemAsync(await host.GetAsync("/api/v1/does-not-exist"), HttpStatusCode.NotFound, "NotFound");
    }

    [Fact]
    public async Task AWrongMethod_IsAProblemToo()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        await Check.ProblemAsync(await host.GetAsync("/api/v1/auth/login"), HttpStatusCode.MethodNotAllowed, "MethodNotAllowed");
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("[]")]
    [InlineData("\"just a string\"")]
    public async Task ABrokenBody_IsABadRequest(string body)
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", body);

        await Check.ProblemAsync(response, HttpStatusCode.BadRequest, "InvalidRequest");
    }

    [Fact]
    public async Task ABodyWithoutTheJsonContentType_IsUnsupported()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login") { Content = new StringContent("email=a&password=b", Encoding.UTF8, "text/plain") };

        await Check.ProblemAsync(await host.Client.SendAsync(request), HttpStatusCode.UnsupportedMediaType, "UnsupportedMediaType");
    }

    [Fact]
    public async Task ATooLargeBody_IsRejected()
    {
        await using var host = await ApiHost.StartAsync(_postgres);
        var huge = "{\"email\":\"" + new string('a', 70 * 1024) + "\"}";

        await Check.ProblemAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/login", huge), HttpStatusCode.RequestEntityTooLarge, "PayloadTooLarge");
    }

    [Fact]
    public async Task AMissingBody_IsABadRequest()
    {
        await using var host = await ApiHost.StartAsync(_postgres);

        var response = await host.Client.PostAsync("/api/v1/auth/login", content: null);

        Assert.True(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.UnsupportedMediaType);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }
}
