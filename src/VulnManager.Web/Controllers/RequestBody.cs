namespace VulnManager.Web.Controllers;

/// <summary>Reads an uploaded document from a multipart "file" field or from a raw JSON body, enforcing size and type.</summary>
internal static class RequestBody
{
    private static readonly string[] AllowedContentTypes = ["application/vnd.cyclonedx+json", "application/json"];

    public static async Task<(ReadOnlyMemory<byte> Content, string? FileName, string? Error)> ReadAsync(HttpRequest request, int maxBytes, CancellationToken cancellationToken)
    {
        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(cancellationToken);
            var file = form.Files.GetFile("file");
            if (file is null || file.Length == 0)
            {
                return (default, null, "Adjunta el SBOM en el campo 'file'.");
            }

            if (file.Length > maxBytes)
            {
                return (default, null, $"El archivo supera {maxBytes / (1024 * 1024)} MiB.");
            }

            if (!Path.GetExtension(file.FileName).Equals(".json", StringComparison.OrdinalIgnoreCase))
            {
                return (default, null, "Solo se aceptan archivos .json (CycloneDX JSON).");
            }

            if (!string.IsNullOrEmpty(file.ContentType) && !AllowedContentTypes.Contains(file.ContentType.Split(';')[0].Trim(), StringComparer.OrdinalIgnoreCase)
                && !file.ContentType.StartsWith("application/octet-stream", StringComparison.OrdinalIgnoreCase))
            {
                return (default, null, "Tipo de contenido no permitido; usa application/vnd.cyclonedx+json o application/json.");
            }

            await using var stream = file.OpenReadStream();
            return (await ReadLimitedAsync(stream, maxBytes, cancellationToken), file.FileName, null);
        }

        var contentType = request.ContentType?.Split(';')[0].Trim();
        if (contentType is null || !AllowedContentTypes.Contains(contentType, StringComparer.OrdinalIgnoreCase))
        {
            return (default, null, "Content-Type debe ser multipart/form-data, application/vnd.cyclonedx+json o application/json.");
        }

        var content = await ReadLimitedAsync(request.Body, maxBytes, cancellationToken);
        return content.Length == 0 ? (default, null, "El cuerpo está vacío.") : (content, null, null);
    }

    private static async Task<ReadOnlyMemory<byte>> ReadLimitedAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > maxBytes)
            {
                throw new BadHttpRequestException("Payload too large", StatusCodes.Status413PayloadTooLarge);
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}
