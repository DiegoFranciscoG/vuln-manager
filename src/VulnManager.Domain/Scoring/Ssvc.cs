namespace VulnManager.Domain.Scoring;

/// <summary>SSVC "Exploitation" decision point as published by CISA Vulnrichment.</summary>
public enum SsvcExploitation
{
    None = 0,
    Poc = 1,
    Active = 2,
}

/// <summary>SSVC "Technical Impact": partial or total control of the vulnerable component.</summary>
public enum TechnicalImpact
{
    Partial = 0,
    Total = 1,
}

/// <summary>Where an SSVC value came from.</summary>
public enum SsvcDataSource
{
    /// <summary>CISA ADP container (Vulnrichment) in the CVE record.</summary>
    CisaAdp = 0,

    /// <summary>Inferred from the CVSS vector because CISA did not publish the value (assumption S2).</summary>
    CvssProxy = 1,

    /// <summary>No data at all: conservative default (assumption S3).</summary>
    Default = 2,
}
