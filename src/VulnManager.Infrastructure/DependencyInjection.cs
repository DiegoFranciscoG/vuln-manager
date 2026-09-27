using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Abstractions.External;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Sync;
using VulnManager.Infrastructure.External;
using VulnManager.Infrastructure.Http;
using VulnManager.Infrastructure.Notifications;
using VulnManager.Infrastructure.Parsing;
using VulnManager.Infrastructure.Persistence;
using VulnManager.Infrastructure.Persistence.Repositories;
using VulnManager.Infrastructure.Sync;

namespace VulnManager.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // Fail fast: no default connection string (credentials only via environment).
        var connectionString = configuration.GetConnectionString("Default");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException("Define ConnectionStrings__Default (environment variable). There is no default value on purpose.");
        }

        services.TryAddSingleton(TimeProvider.System);
        services.AddDbContext<VulnManagerDbContext>(options => options
            .UseNpgsql(connectionString, npgsql => npgsql.EnableRetryOnFailure(3))
            .UseSnakeCaseNamingConvention());

        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IProjectRepository, ProjectRepository>();
        services.AddScoped<IApiKeyRepository, ApiKeyRepository>();
        services.AddScoped<ISbomImportRepository, SbomImportRepository>();
        services.AddScoped<IComponentRepository, ComponentRepository>();
        services.AddScoped<IVulnerabilityRepository, VulnerabilityRepository>();
        services.AddScoped<IKevRepository, KevRepository>();
        services.AddScoped<IFindingRepository, FindingRepository>();
        services.AddScoped<IVexRepository, VexRepository>();
        services.AddScoped<IPriorityRuleRepository, PriorityRuleRepository>();
        services.AddScoped<IAlertRepository, AlertRepository>();
        services.AddScoped<ISyncRunRepository, SyncRunRepository>();
        services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        services.AddScoped<DatabaseInitializer>();
        services.AddOptions<SeedOptions>().Bind(configuration.GetSection(SeedOptions.Section));

        services.AddSingleton<ICycloneDxParser, CycloneDxParser>();
        services.AddSingleton<SyncDispatcher>();
        services.AddSingleton<ISyncDispatcher>(sp => sp.GetRequiredService<SyncDispatcher>());
        services.AddHostedService<SyncWorker>();

        AddExternalClients(services, configuration);
        return services;
    }

    private static void AddExternalClients(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ExternalSourcesOptions>().Bind(configuration.GetSection(ExternalSourcesOptions.Section)).ValidateDataAnnotations().ValidateOnStart();
        services.AddOptions<AlertWebhookOptions>().Bind(configuration.GetSection(AlertWebhookOptions.Section)).ValidateDataAnnotations().ValidateOnStart();
        services.AddSingleton<HttpCallStats>();
        services.AddSingleton<IHttpCallStats>(sp => sp.GetRequiredService<HttpCallStats>());

        services.AddKeyedSingleton(HttpClientNames.Nvd, (sp, _) =>
        {
            var o = sp.GetRequiredService<IOptions<ExternalSourcesOptions>>().Value;
            return new RollingWindowRateLimiter(o.NvdPermitLimit, TimeSpan.FromSeconds(o.NvdWindowSeconds), TimeSpan.FromSeconds(o.NvdMinSpacingSeconds), sp.GetRequiredService<TimeProvider>());
        });
        services.AddKeyedSingleton(HttpClientNames.Cve, (sp, _) => PerMinute(sp, o => o.CveRequestsPerMinute));
        services.AddKeyedSingleton(HttpClientNames.Epss, (sp, _) => PerMinute(sp, o => o.EpssRequestsPerMinute));
        services.AddKeyedSingleton(HttpClientNames.Osv, (sp, _) => PerMinute(sp, o => o.OsvRequestsPerMinute));

        Configure<IOsvClient, OsvClient>(services, HttpClientNames.Osv, o => o.OsvBaseUrl, TimeSpan.FromSeconds(30), limited: true);
        Configure<IKevClient, KevClient>(services, HttpClientNames.Kev, o => o.KevFeedUrl, TimeSpan.FromSeconds(60), limited: false);
        Configure<IEpssClient, EpssClient>(services, HttpClientNames.Epss, o => o.EpssBaseUrl, TimeSpan.FromSeconds(30), limited: true);
        Configure<ICveServicesClient, CveServicesClient>(services, HttpClientNames.Cve, o => o.CveServicesBaseUrl, TimeSpan.FromSeconds(30), limited: true);
        Configure<INvdClient, NvdClient>(services, HttpClientNames.Nvd, o => o.NvdBaseUrl, TimeSpan.FromSeconds(90), limited: true, forbiddenMeansThrottled: true)
            .ConfigureHttpClient((sp, client) =>
            {
                var key = sp.GetRequiredService<IOptions<ExternalSourcesOptions>>().Value.NvdApiKey;
                if (!string.IsNullOrWhiteSpace(key))
                {
                    client.DefaultRequestHeaders.Add("apiKey", key);
                }
            });

        services.AddHttpClient<IAlertNotifier, WebhookAlertNotifier>(HttpClientNames.Webhook, client => client.Timeout = TimeSpan.FromSeconds(10));
    }

    private static IHttpClientBuilder Configure<TClient, TImplementation>(
        IServiceCollection services,
        string name,
        Func<ExternalSourcesOptions, Uri> baseUrl,
        TimeSpan attemptTimeout,
        bool limited,
        bool forbiddenMeansThrottled = false)
        where TClient : class
        where TImplementation : class, TClient
    {
        var builder = services.AddHttpClient<TClient, TImplementation>(name, (sp, client) =>
        {
            var options = sp.GetRequiredService<IOptions<ExternalSourcesOptions>>().Value;
            client.BaseAddress = baseUrl(options);
            client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
            client.Timeout = Timeout.InfiniteTimeSpan;
        });

        // Order matters: resilience (outer) -> stats -> rate limiter (inner), so every retry is counted and rate-limited.
        builder.AddStandardResilienceHandler(options =>
        {
            options.AttemptTimeout.Timeout = attemptTimeout;
            options.TotalRequestTimeout.Timeout = TimeSpan.FromMinutes(10);
            options.CircuitBreaker.SamplingDuration = attemptTimeout * 3;
            options.Retry.MaxRetryAttempts = 3;
            options.Retry.ShouldRetryAfterHeader = true;
            if (forbiddenMeansThrottled)
            {
                // NVD answers rate-limit violations with 403: back off and retry.
                options.Retry.ShouldHandle = args => ValueTask.FromResult(
                    args.Outcome.Result?.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests or HttpStatusCode.RequestTimeout
                    || (int?)args.Outcome.Result?.StatusCode >= 500
                    || args.Outcome.Exception is HttpRequestException or Polly.Timeout.TimeoutRejectedException);
                options.Retry.Delay = TimeSpan.FromSeconds(6);
            }
        });
        builder.AddHttpMessageHandler(sp => new HttpStatsHandler(sp.GetRequiredService<HttpCallStats>(), name, forbiddenMeansThrottled));
        if (limited)
        {
            builder.AddHttpMessageHandler(sp => new RateLimitingHandler(sp.GetRequiredKeyedService<RollingWindowRateLimiter>(name)));
        }

        return builder;
    }

    private static RollingWindowRateLimiter PerMinute(IServiceProvider sp, Func<ExternalSourcesOptions, int> perMinute)
    {
        var options = sp.GetRequiredService<IOptions<ExternalSourcesOptions>>().Value;
        return new RollingWindowRateLimiter(perMinute(options), TimeSpan.FromMinutes(1), TimeSpan.Zero, sp.GetRequiredService<TimeProvider>());
    }
}
