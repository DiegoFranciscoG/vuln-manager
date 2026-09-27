using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using VulnManager.Application.Exceptions;
using VulnManager.Domain.Common;

namespace VulnManager.Web.ErrorHandling;

/// <summary>
/// Maps application exceptions to RFC 9457 problem details for /api requests. Clients never receive stack traces or
/// internal messages for unexpected errors (OWASP A10:2025); those are logged with the trace id.
/// </summary>
public sealed partial class GlobalExceptionHandler(IProblemDetailsService problemDetails, ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        if (!httpContext.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
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

        httpContext.Response.StatusCode = status;
        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            Exception = exception,
            ProblemDetails = new ProblemDetails
            {
                Status = status,
                Title = title,
                Detail = detail,
                Instance = httpContext.Request.Path,
                Extensions = { ["traceId"] = httpContext.TraceIdentifier },
            },
        });
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Unhandled exception (traceId {TraceId})")]
    private static partial void LogUnhandled(ILogger logger, Exception exception, string traceId);
}
