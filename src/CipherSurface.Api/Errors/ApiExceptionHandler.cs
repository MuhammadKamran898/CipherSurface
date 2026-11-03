using CipherSurface.Services;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Api.Errors;

/// <summary>
/// Turns every exception into a problem response. A ServiceException has a safe, user-facing message and a code that
/// ErrorCatalog maps to a status. Anything else (and any code the catalog does not know) becomes a generic 500: the
/// exception goes to the server log only, never to the client.
/// </summary>
public sealed class ApiExceptionHandler : IExceptionHandler
{
    private readonly ILogger<ApiExceptionHandler> _logger;
    public ApiExceptionHandler(ILogger<ApiExceptionHandler> logger) => _logger = logger;

    public async ValueTask<bool> TryHandleAsync(HttpContext http, Exception exception, CancellationToken ct)
    {
        if (http.RequestAborted.IsCancellationRequested)
        {
            http.Response.StatusCode = 499;
            return true;
        }

        switch (exception)
        {
            case ServiceException service when ErrorCatalog.TryGetStatus(service.Code, out var status):
                await ProblemWriter.WriteAsync(http, status, service.Code, service.Message);
                return true;

            case ServiceException service:
                _logger.LogError(exception, "A service error code has no HTTP status: {Code}", service.Code);
                break;

            case BadHttpRequestException bad:
                var badStatus = bad.StatusCode is 413 or 415 ? bad.StatusCode : 400;
                await ProblemWriter.WriteAsync(http, badStatus, ErrorCatalog.CodeForStatus(badStatus), ProblemWriter.GenericDetail(badStatus));
                return true;

            case DbUpdateConcurrencyException:
                await ProblemWriter.WriteAsync(http, 409, "Busy", "The data was changed at the same time. Reload and try again.");
                return true;

            default:
                _logger.LogError(exception, "Unhandled exception on {Method} {Path}", http.Request.Method, http.Request.Path);
                break;
        }

        await ProblemWriter.WriteAsync(http, 500, "InternalError", ProblemWriter.GenericDetail(500));
        return true;
    }
}
