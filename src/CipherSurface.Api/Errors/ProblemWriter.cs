using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace CipherSurface.Api.Errors;

/// <summary>Writes RFC 9457 problem details (application/problem+json) with a stable "code" extension.</summary>
public static class ProblemWriter
{
    public const string ContentType = "application/problem+json";

    public static Task WriteAsync(HttpContext http, int status, string code, string detail)
    {
        var problem = new ProblemDetails
        {
            Type = "about:blank",
            Title = TitleFor(status),
            Status = status,
            Detail = detail
        };
        problem.Extensions["code"] = code;
        problem.Extensions["traceId"] = Activity.Current?.Id ?? http.TraceIdentifier;

        http.Response.StatusCode = status;
        return http.Response.WriteAsJsonAsync(problem, options: null, contentType: ContentType, cancellationToken: http.RequestAborted);
    }

    public static string TitleFor(int status) => status switch
    {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        _ => status >= 500 ? "Internal Server Error" : "Error"
    };

    public static string GenericDetail(int status) => status switch
    {
        400 => "The request could not be understood.",
        401 => "Authentication is required.",
        403 => "You are not allowed to do this.",
        404 => "The resource was not found.",
        405 => "This method is not allowed here.",
        413 => "The request is too large.",
        415 => "The content type is not supported.",
        429 => "Too many requests. Try again later.",
        _ => "Something went wrong on the server."
    };
}
