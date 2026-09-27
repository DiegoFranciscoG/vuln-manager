using System.ComponentModel.DataAnnotations;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions;
using VulnManager.Domain.Entities;

namespace VulnManager.Infrastructure.Notifications;

public sealed class AlertWebhookOptions : IValidatableObject
{
    public const string Section = "AlertWebhook";

    /// <summary>HTTPS incoming-webhook URL (Slack, Discord, Teams...). Configured only by environment: it is a secret and avoids SSRF.</summary>
    public string? Url { get; set; }

    public string? PublicBaseUrl { get; set; }

    /// <summary>Empty disables the webhook; any other value must be an absolute https URL (fail fast on typos).</summary>
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        foreach (var (name, value) in new[] { (nameof(Url), Url), (nameof(PublicBaseUrl), PublicBaseUrl) })
        {
            if (!string.IsNullOrWhiteSpace(value) && (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps))
            {
                yield return new ValidationResult($"AlertWebhook:{name} debe ser una URL https absoluta.", [name]);
            }
        }
    }
}

/// <summary>Posts alerts as {"text", "content"} so the same payload works with Slack and Discord incoming webhooks.</summary>
public sealed class WebhookAlertNotifier(HttpClient http, IOptions<AlertWebhookOptions> options) : IAlertNotifier
{
    private readonly Uri? _url = Uri.TryCreate(options.Value.Url, UriKind.Absolute, out var url) && url.Scheme == Uri.UriSchemeHttps ? url : null;

    public bool IsEnabled => _url is not null;

    public async Task<bool> NotifyAsync(Alert alert, string projectName, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(alert);
        if (_url is null)
        {
            return false;
        }

        var link = options.Value.PublicBaseUrl is { Length: > 0 } baseUrl && alert.FindingId is { } findingId
            ? $" {baseUrl.TrimEnd('/')}/findings/{findingId}"
            : string.Empty;
        var text = $"[vuln-manager] {alert.Type}: {alert.Message}{link}";
        try
        {
            using var response = await http.PostAsJsonAsync(_url, new { text, content = text, project = projectName, type = alert.Type.ToString() }, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }
}
