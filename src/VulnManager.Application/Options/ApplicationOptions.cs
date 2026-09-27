using System.ComponentModel.DataAnnotations;

namespace VulnManager.Application.Options;

public sealed class FindingOptions
{
    public const string Section = "Findings";

    /// <summary>Maximum risk acceptance window (assumption S1).</summary>
    [Range(1, 365)]
    public int RiskAcceptanceMaxDays { get; set; } = 90;

    /// <summary>An SLA_DUE_SOON alert is raised this many hours before the deadline.</summary>
    [Range(1, 720)]
    public int SlaDueSoonHours { get; set; } = 72;

    [Range(100, 100_000)]
    public int CsvMaxRows { get; set; } = 10_000;
}

public sealed class SyncOptions
{
    public const string Section = "Sync";

    public bool Enabled { get; set; } = true;

    [Range(1, 1440)]
    public int TickMinutes { get; set; } = 15;

    [Range(1, 168)]
    public int KevIntervalHours { get; set; } = 6;

    [Range(1, 720)]
    public int OsvRecheckHours { get; set; } = 24;

    /// <summary>EPSS publishes daily around 13:30 UTC (FIRST FAQ); the API is cached for 24 h.</summary>
    [Range(1, 168)]
    public int EpssIntervalHours { get; set; } = 20;

    [Range(1, 90)]
    public int CveRecheckDays { get; set; } = 7;

    [Range(1, 90)]
    public int NvdRecheckDays { get; set; } = 7;

    [Range(1, 1000)]
    public int OsvBatchSize { get; set; } = 100;

    [Range(1, 50_000)]
    public int OsvMaxComponentsPerRun { get; set; } = 2000;

    [Range(1, 10_000)]
    public int EnrichmentMaxPerRun { get; set; } = 500;

    [Range(5, 1440)]
    public int StaleRunMinutes { get; set; } = 60;
}

public sealed class AuditOptions
{
    public const string Section = "Audit";

    /// <summary>LOPDP art. 10 i): data is kept only as long as needed (assumption S9).</summary>
    [Range(30, 3650)]
    public int RetentionDays { get; set; } = 365;
}
