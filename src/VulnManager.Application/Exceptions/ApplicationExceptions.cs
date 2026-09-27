namespace VulnManager.Application.Exceptions;

/// <summary>Base class for errors mapped to HTTP responses by the global exception handler. Messages are client-safe.</summary>
public abstract class AppException : Exception
{
    protected AppException()
    {
    }

    protected AppException(string message) : base(message)
    {
    }

    protected AppException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>404: the resource does not exist or the caller cannot see it (no information leak).</summary>
public sealed class NotFoundException : AppException
{
    public NotFoundException()
    {
    }

    public NotFoundException(string message) : base(message)
    {
    }

    public NotFoundException(string message, Exception innerException) : base(message, innerException)
    {
    }

    public static NotFoundException For(string resource, object id) => new($"{resource} '{id}' no existe.");
}

/// <summary>409: the request conflicts with the current state (duplicate name, concurrent update).</summary>
public sealed class ConflictException : AppException
{
    public ConflictException()
    {
    }

    public ConflictException(string message) : base(message)
    {
    }

    public ConflictException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>403: authenticated but not allowed.</summary>
public sealed class ForbiddenException : AppException
{
    public ForbiddenException()
    {
    }

    public ForbiddenException(string message) : base(message)
    {
    }

    public ForbiddenException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>400: the input is structurally invalid (for example, not a CycloneDX document).</summary>
public sealed class InvalidInputException : AppException
{
    public InvalidInputException()
    {
    }

    public InvalidInputException(string message) : base(message)
    {
    }

    public InvalidInputException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
