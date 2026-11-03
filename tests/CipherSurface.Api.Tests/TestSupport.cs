using System.Net;
using System.Text;
using System.Text.Json;
using CipherSurface.Auth;
using CipherSurface.Data.Entities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace CipherSurface.Api.Tests;

public static class Check
{
    /// <summary>Asserts an RFC 9457 problem response with the given status and CipherSurface code, and returns its JSON.</summary>
    public static async Task<JsonElement> ProblemAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        var text = await response.Content.ReadAsStringAsync();
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = JsonDocument.Parse(text).RootElement.Clone();
        Assert.Equal((int)status, json.GetProperty("status").GetInt32());
        Assert.Equal(code, json.GetProperty("code").GetString());
        Assert.False(string.IsNullOrWhiteSpace(json.GetProperty("title").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(json.GetProperty("traceId").GetString()));
        return json;
    }

    public static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    public static JsonElement Payload(string jwt) => JsonDocument.Parse(Base64UrlDecode(jwt.Split('.')[1])).RootElement.Clone();
    public static JsonElement Header(string jwt) => JsonDocument.Parse(Base64UrlDecode(jwt.Split('.')[0])).RootElement.Clone();

    public static string Base64UrlEncode(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }
}

public sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}

public static class TokenForge
{
    /// <summary>An access token signed with the given keys, for the given user and session, at the given clock.</summary>
    public static string Issue(TokenKeys keys, Guid userId, Guid sessionId, JwtOptions? options = null, DateTimeOffset? now = null)
    {
        var service = new AccessTokenService(options ?? new JwtOptions(), keys, new FixedTime(now ?? DateTimeOffset.UtcNow));
        return service.Issue(new User { Id = userId, Email = "forged@example.com" }, sessionId).Token;
    }

    /// <summary>A token whose header says alg "none" and that carries no signature at all.</summary>
    public static string Unsigned(Guid userId, Guid sessionId)
    {
        var exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
        var header = Check.Base64UrlEncode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        var payload = Check.Base64UrlEncode($"{{\"sub\":\"{userId:D}\",\"sid\":\"{sessionId:D}\",\"iss\":\"ciphersurface\",\"aud\":\"ciphersurface-api\",\"exp\":{exp}}}");
        return $"{header}.{payload}.";
    }

    /// <summary>The classic confusion attack: sign with HMAC, using the PUBLIC key text as the secret.</summary>
    public static string HmacWithPublicKey(TokenKeys keys, Guid userId, Guid sessionId)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "ciphersurface",
            Audience = "ciphersurface-api",
            Subject = new System.Security.Claims.ClaimsIdentity([new("sub", userId.ToString("D")), new("sid", sessionId.ToString("D"))]),
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keys.PublicPem)), SecurityAlgorithms.HmacSha256)
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }
}
