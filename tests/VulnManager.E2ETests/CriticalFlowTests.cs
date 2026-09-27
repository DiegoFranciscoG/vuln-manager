using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace VulnManager.E2ETests;

/// <summary>
/// Critical UI flows against a running instance (for example "docker compose up"). Skipped unless E2E_BASE_URL is set;
/// credentials come from E2E_USER / E2E_PASSWORD and screenshots are written to E2E_SCREENSHOTS_DIR when defined.
/// Uses the installed Edge/Chrome channel (E2E_BROWSER_CHANNEL, default "msedge") so no browser download is needed.
/// </summary>
public sealed partial class CriticalFlowTests : IAsyncLifetime
{
    private static readonly string? BaseUrl = Environment.GetEnvironmentVariable("E2E_BASE_URL")?.TrimEnd('/');
    private static readonly string? ScreenshotDir = Environment.GetEnvironmentVariable("E2E_SCREENSHOTS_DIR");

    private IPlaywright? playwright;
    private IBrowser? browser;

    public async ValueTask InitializeAsync()
    {
        if (BaseUrl is null)
        {
            return;
        }

        playwright = await Playwright.CreateAsync();
        browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Channel = Environment.GetEnvironmentVariable("E2E_BROWSER_CHANNEL") ?? "msedge",
        });
    }

    public async ValueTask DisposeAsync()
    {
        if (browser is not null)
        {
            await browser.DisposeAsync();
        }

        playwright?.Dispose();
    }

    [Fact]
    public async Task Anonymous_visitors_are_redirected_to_login()
    {
        var page = await NewPageAsync();

        await page.GotoAsync($"{BaseUrl}/findings");

        await Assertions.Expect(page).ToHaveURLAsync(LoginUrl());
        await Assertions.Expect(page.GetByRole(AriaRole.Button, new() { Name = "Entrar" })).ToBeVisibleAsync();
        await CaptureAsync(page, "00-login");
    }

    [Fact]
    public async Task Invalid_credentials_show_a_generic_error()
    {
        var page = await NewPageAsync();
        await page.GotoAsync($"{BaseUrl}/login");

        await page.GetByLabel("Correo").FillAsync("nadie@vulnmanager.test");
        await page.GetByLabel("Contraseña").FillAsync("No-Existe-2026!");
        await page.GetByRole(AriaRole.Button, new() { Name = "Entrar" }).ClickAsync();

        await Assertions.Expect(page.GetByRole(AriaRole.Alert)).ToHaveTextAsync("Correo o contraseña incorrectos.");
    }

    [Fact]
    public async Task Admin_prioritizes_findings_reads_the_explanation_and_logs_out()
    {
        var user = Environment.GetEnvironmentVariable("E2E_USER");
        var password = Environment.GetEnvironmentVariable("E2E_PASSWORD");
        Assert.SkipWhen(user is null || password is null, "Define E2E_USER y E2E_PASSWORD.");
        var page = await NewPageAsync();

        await page.GotoAsync($"{BaseUrl}/login");
        await page.GetByLabel("Correo").FillAsync(user!);
        await page.GetByLabel("Contraseña").FillAsync(password!);
        await page.GetByRole(AriaRole.Button, new() { Name = "Entrar" }).ClickAsync();

        await Assertions.Expect(page.GetByRole(AriaRole.Heading, new() { Name = "Tablero", Exact = true })).ToBeVisibleAsync();
        await Assertions.Expect(page.GetByText("Prioridad P1")).ToBeVisibleAsync();
        await CaptureAsync(page, "01-tablero");

        await page.GotoAsync($"{BaseUrl}/findings?priority=P1");
        var rows = page.Locator("table tbody tr a[href^='/findings/']");
        await Assertions.Expect(rows.First).ToBeVisibleAsync();
        await CaptureAsync(page, "02-hallazgos");

        var log4shell = page.Locator("table tbody tr a[href^='/findings/']", new() { HasText = "CVE-2021-44228" });
        await ((await log4shell.CountAsync()) > 0 ? log4shell.First : rows.First).ClickAsync();
        await Assertions.Expect(page.GetByRole(AriaRole.Heading, new() { Name = "¿Por qué P1?" })).ToBeVisibleAsync();
        await Assertions.Expect(page.GetByRole(AriaRole.Heading, new() { Name = "Plazo de remediación" })).ToBeVisibleAsync();
        await CaptureAsync(page, "03-detalle-hallazgo", fullPage: true);

        await page.GotoAsync($"{BaseUrl}/");
        var projectLink = page.Locator("table a[href^='/projects/']", new() { HasText = "portal-ciudadano-demo" });
        await ((await projectLink.CountAsync()) > 0 ? projectLink.First : page.Locator("table a[href^='/projects/']").First).ClickAsync();
        await Assertions.Expect(page.GetByRole(AriaRole.Tab, new() { Name = "VEX" }).Or(page.GetByRole(AriaRole.Button, new() { Name = "VEX", Exact = true }))).ToBeVisibleAsync();
        await CaptureAsync(page, "04-proyecto");

        await ClickUntilVisibleAsync(page.GetByRole(AriaRole.Button, new() { Name = "VEX", Exact = true }), page.GetByRole(AriaRole.Heading, new() { Name = "Declaraciones VEX" }));
        await CaptureAsync(page, "05-vex", fullPage: true);

        foreach (var (path, heading, name) in new[]
                 {
                     ("/rules", "Reglas de prioridad", "06-reglas"),
                     ("/sync", "Sincronización", "07-sincronizacion"),
                     ("/alerts", "Alertas", "08-alertas"),
                     ("/sources", "Fuentes de datos", "09-fuentes"),
                     ("/audit", "Auditoría", "10-auditoria"),
                 })
        {
            await page.GotoAsync(BaseUrl + path);
            await Assertions.Expect(page.GetByRole(AriaRole.Heading, new() { Name = heading, Level = 1 })).ToBeVisibleAsync();
            await CaptureAsync(page, name);
        }

        await page.GetByRole(AriaRole.Button, new() { Name = "Salir" }).ClickAsync();
        await Assertions.Expect(page).ToHaveURLAsync(LoginUrl());
    }

    private async Task<IPage> NewPageAsync()
    {
        Assert.SkipWhen(browser is null, "Define E2E_BASE_URL para ejecutar las pruebas E2E.");
        var context = await browser!.NewContextAsync(new BrowserNewContextOptions
        {
            ViewportSize = new ViewportSize { Width = 1440, Height = 900 },
            Locale = "es-EC",
            TimezoneId = "America/Guayaquil",
        });
        return await context.NewPageAsync();
    }

    /// <summary>Interactive Server buttons only react once the circuit is connected, so the click is retried briefly.</summary>
    private static async Task ClickUntilVisibleAsync(ILocator button, ILocator expected)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            await button.ClickAsync();
            try
            {
                await expected.WaitForAsync(new LocatorWaitForOptions { Timeout = 1000 });
                return;
            }
            catch (TimeoutException)
            {
                // Circuit not ready yet: try again.
            }
        }

        await Assertions.Expect(expected).ToBeVisibleAsync();
    }

    private static async Task CaptureAsync(IPage page, string name, bool fullPage = false)
    {
        if (ScreenshotDir is null)
        {
            return;
        }

        Directory.CreateDirectory(ScreenshotDir);
        await page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(ScreenshotDir, name + ".png"), FullPage = fullPage });
    }

    [GeneratedRegex("/login")]
    private static partial Regex LoginUrl();
}
