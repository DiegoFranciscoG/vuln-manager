using VulnManager.Domain.Scoring;

namespace VulnManager.Domain.Sla;

/// <summary>One row of CISA BOD 26-04 Table 1 "Remediation Timelines". <see cref="Days"/> is null for "Fix on system upgrade".</summary>
public sealed record Bod2604Row(int Number, bool PubliclyExposed, bool InKev, bool Automatable, TechnicalImpact TechnicalImpact, int? Days, bool ForensicTriage);

/// <summary>CISA Binding Operational Directive 26-04 (June 10, 2026), Appendix A, Table 1. Days are calendar days.</summary>
public static class Bod2604Timeline
{
    public static IReadOnlyList<Bod2604Row> Rows { get; } =
    [
        new(1, true, true, true, TechnicalImpact.Total, 3, true),
        new(2, true, true, true, TechnicalImpact.Partial, 3, false),
        new(3, true, true, false, TechnicalImpact.Total, 3, true),
        new(4, true, true, false, TechnicalImpact.Partial, 14, false),
        new(5, true, false, true, TechnicalImpact.Total, 3, false),
        new(6, true, false, true, TechnicalImpact.Partial, 14, false),
        new(7, true, false, false, TechnicalImpact.Total, 14, false),
        new(8, true, false, false, TechnicalImpact.Partial, 60, false),
        new(9, false, true, true, TechnicalImpact.Total, 3, true),
        new(10, false, true, true, TechnicalImpact.Partial, 14, false),
        new(11, false, true, false, TechnicalImpact.Total, 14, false),
        new(12, false, true, false, TechnicalImpact.Partial, 14, false),
        new(13, false, false, true, TechnicalImpact.Total, 60, false),
        new(14, false, false, true, TechnicalImpact.Partial, 60, false),
        new(15, false, false, false, TechnicalImpact.Total, null, false),
        new(16, false, false, false, TechnicalImpact.Partial, null, false),
    ];

    public static Bod2604Row Lookup(bool publiclyExposed, bool inKev, bool automatable, TechnicalImpact technicalImpact) =>
        Rows.Single(r => r.PubliclyExposed == publiclyExposed
                         && r.InKev == inKev
                         && r.Automatable == automatable
                         && r.TechnicalImpact == technicalImpact);
}
