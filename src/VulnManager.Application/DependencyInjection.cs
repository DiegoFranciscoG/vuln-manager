using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VulnManager.Application.Options;
using VulnManager.Application.Services;
using VulnManager.Application.Sync;

namespace VulnManager.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        services.AddOptions<FindingOptions>().Bind(configuration.GetSection(FindingOptions.Section)).ValidateDataAnnotations().ValidateOnStart();
        services.AddOptions<SyncOptions>().Bind(configuration.GetSection(SyncOptions.Section)).ValidateDataAnnotations().ValidateOnStart();
        services.AddOptions<AuditOptions>().Bind(configuration.GetSection(AuditOptions.Section)).ValidateDataAnnotations().ValidateOnStart();

        services.AddScoped<AuditService>();
        services.AddScoped<FindingReconciliationService>();
        services.AddScoped<ProjectService>();
        services.AddScoped<ApiKeyService>();
        services.AddScoped<VexService>();
        services.AddScoped<SbomImportService>();
        services.AddScoped<FindingService>();
        services.AddScoped<PriorityRuleService>();
        services.AddScoped<AlertService>();
        services.AddScoped<DashboardService>();

        services.AddScoped<ISyncJob, KevSyncJob>();
        services.AddScoped<ISyncJob, OsvSyncJob>();
        services.AddScoped<ISyncJob, CveEnrichmentJob>();
        services.AddScoped<ISyncJob, NvdEnrichmentJob>();
        services.AddScoped<ISyncJob, EpssSyncJob>();
        services.AddSingleton<SyncRunner>();
        return services;
    }
}
