using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using VulnManager.Application.Exceptions;
using VulnManager.Domain.Common;

namespace VulnManager.Web.ErrorHandling;

/// <summary>
/// Maps application exceptions to RFC 9457 problem details for /api requests. Clients never receive stack traces or
/// internal messages for unexpected errors (OWASP A10:2025); those are logged with the trace id.
/// </summary>
public sealed partial class GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        // The middleware rewrites Request.Path to the error page before calling handlers; use the original path.
        var path = httpContext.Features.Get<IExceptionHandlerPathFeature>()?.Path ?? httpContext.Request.Path.Value ?? string.Empty;
        if (!path.StartsWith("/api", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var (status, title, detail) = exception switch
        {
            NotFoundException e => (StatusCodes.Status404NotFound, "No encontrado", e.Message),
            ForbiddenException e => (StatusCodes.Status403Forbidden, "Prohibido", e.Message),
            ConflictException e => (StatusCodes.Status409Conflict, "Conflicto", e.Message),
            InvalidInputException e => (StatusCodes.Status400BadRequest, "Solicitud inválida", e.Message),
            DomainException e => (StatusCodes.Status400BadRequest, "Regla de negocio incumplida", e.Message),
            BadHttpRequestException e => (e.StatusCode, "Solicitud inválida", "La solicitud no pudo procesarse (tamaño o formato)."),
            _ => (StatusCodes.Status500InternalServerError, "Error interno", "Ocurrió un error inesperado. Usa el traceId para reportarlo."),
        };

        if (status >= 500)
        {
            LogUnhandled(logger, exception, httpContext.TraceIdentifier);
        }

        // Written directly (not through IProblemDetailsService) so the response never depends on the Accept header.
        httpContext.Response.StatusCode = status;
        await httpContext.Response.WriteAsJsonAsync(
            new ProblemDetails
            {
                Status = status,
                Title = title,
                Detail = detail,
                Instance = path,
                Extensions = { ["traceId"] = httpContext.TraceIdentifier },
            },
            options: null,
            contentType: "application/problem+json",
            cancellationToken);
        return true;
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Unhandled exception (traceId {TraceId})")]
    private static partial void LogUnhandled(ILogger logger, Exception exception, string traceId);
}
