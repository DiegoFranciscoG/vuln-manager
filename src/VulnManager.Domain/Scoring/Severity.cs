namespace VulnManager.Domain.Scoring;

/// <summary>Qualitative severity rating scale shared by CVSS v3.1 and v4.0 (FIRST specification).</summary>
public enum Severity
{
    Unknown = 0,
    None = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}
