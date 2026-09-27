using System.Globalization;

namespace VulnManager.Web;

/// <summary>
/// Docker HEALTHCHECK for the chiseled image, which has no shell or curl: "dotnet VulnManager.Web.dll --healthcheck"
/// calls /health/live on the local port and returns 0 (healthy) or 1.
/// </summary>
public static class HealthProbe
{
    public const string Argument = "--healthcheck";

    public static async Task<int> RunAsync()
    {
        var port = (Environment.GetEnvironmentVariable("ASPNETCORE_HTTP_PORTS") ?? "8080").Split(';', ',')[0].Trim();
        if (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
        {
            return 1;
        }

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
        try
        {
            using var response = await http.GetAsync(new Uri($"http://127.0.0.1:{number}/health/live"));
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (HttpRequestException)
        {
            return 1;
        }
        catch (TaskCanceledException)
        {
            return 1;
        }
    }
}
