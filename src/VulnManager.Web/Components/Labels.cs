using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;
using VulnManager.Domain.Vex;

namespace VulnManager.Web.Components;

/// <summary>Spanish labels for the UI (code and API values stay in English).</summary>
public static class Labels
{
    public static string Of(FindingStatus status) => status switch
    {
        FindingStatus.New => "Nuevo",
        FindingStatus.Accepted => "Riesgo aceptado",
        FindingStatus.Mitigated => "Mitigado",
        FindingStatus.FalsePositive => "Falso positivo",
        FindingStatus.NotAffected => "No afectado (VEX)",
        FindingStatus.Fixed => "Corregido",
        _ => status.ToString(),
    };

    public static string Of(Severity severity) => severity switch
    {
        Severity.Critical => "Crítica",
        Severity.High => "Alta",
        Severity.Medium => "Media",
        Severity.Low => "Baja",
        Severity.None => "Ninguna",
        _ => "Desconocida",
    };

    public static string Of(Exposure exposure) => exposure == Exposure.Public ? "Pública (Internet)" : "Interna";

    public static string Of(VexStatus status) => status switch
    {
        VexStatus.NotAffected => "No afectado",
        VexStatus.Affected => "Afectado",
        VexStatus.Fixed => "Corregido",
        VexStatus.UnderInvestigation => "En investigación",
        _ => status.ToString(),
    };

    public static string Of(StatusChangeSource source) => source switch
    {
        StatusChangeSource.User => "Usuario",
        StatusChangeSource.SbomImport => "Importación SBOM",
        StatusChangeSource.Vex => "VEX",
        StatusChangeSource.Sync => "Sincronización",
        StatusChangeSource.Expiry => "Vencimiento",
        _ => source.ToString(),
    };

    public static string Of(AlertType type) => type switch
    {
        AlertType.NewP1 => "Nuevo P1",
        AlertType.NewKevMatch => "KEV detectado",
        AlertType.SlaDueSoon => "SLA por vencer",
        AlertType.SlaOverdue => "SLA vencido",
        AlertType.ForensicTriage => "Triage forense",
        _ => type.ToString(),
    };

    public static string Of(ExploitationSignal signal) => signal switch
    {
        ExploitationSignal.Active => "Confirmada",
        ExploitationSignal.Likely => "Probable (EPSS)",
        _ => "Sin evidencia",
    };

    public static string Of(SsvcDataSource? source) => source switch
    {
        SsvcDataSource.CisaAdp => "CISA Vulnrichment",
        SsvcDataSource.CvssProxy => "inferido de CVSS",
        SsvcDataSource.Default => "valor conservador por defecto",
        _ => "—",
    };

    public static string CssOf(PriorityLevel level) => level switch
    {
        PriorityLevel.P1 => "p1",
        PriorityLevel.P2 => "p2",
        PriorityLevel.P3 => "p3",
        _ => "p4",
    };

    public static string CssOf(Severity severity) => severity switch
    {
        Severity.Critical => "sev-critical",
        Severity.High => "sev-high",
        Severity.Medium => "sev-medium",
        Severity.Low => "sev-low",
        _ => "sev-unknown",
    };
}
