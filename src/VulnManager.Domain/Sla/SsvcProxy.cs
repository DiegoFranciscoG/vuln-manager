using VulnManager.Domain.Scoring;

namespace VulnManager.Domain.Sla;

public sealed record SsvcFacts(bool Automatable, SsvcDataSource AutomatableSource, TechnicalImpact TechnicalImpact, SsvcDataSource TechnicalImpactSource);

/// <summary>
/// Resolves the SSVC decision points needed by BOD 26-04. CISA ADP values win; otherwise they are inferred from CVSS
/// (assumption S2): Automatable from CVSS v4 AU (interchangeable per CERT/CC SSVC) or from AV:N/AC:L/PR:N/UI:N,
/// Technical Impact "total" when confidentiality, integrity and availability impacts are all High.
/// With no data at all the conservative default is Automatable = no, Technical Impact = total (assumption S3).
/// </summary>
public static class SsvcProxy
{
    public static SsvcFacts Resolve(bool? cisaAutomatable, TechnicalImpact? cisaTechnicalImpact, string? cvssVector)
    {
        var (proxyAutomatable, proxyImpact) = FromCvss(cvssVector);

        var (automatable, automatableSource) = cisaAutomatable is { } a
            ? (a, SsvcDataSource.CisaAdp)
            : proxyAutomatable is { } pa
                ? (pa, SsvcDataSource.CvssProxy)
                : (false, SsvcDataSource.Default);

        var (impact, impactSource) = cisaTechnicalImpact is { } t
            ? (t, SsvcDataSource.CisaAdp)
            : proxyImpact is { } pi
                ? (pi, SsvcDataSource.CvssProxy)
                : (TechnicalImpact.Total, SsvcDataSource.Default);

        return new SsvcFacts(automatable, automatableSource, impact, impactSource);
    }

    public static (bool? Automatable, TechnicalImpact? TechnicalImpact) FromCvss(string? cvssVector)
    {
        if (CvssV4Vector.TryParse(cvssVector, out var v4))
        {
            bool? automatable = v4["AU"] switch
            {
                "Y" => true,
                "N" => false,
                _ => v4["AV"] == "N" && v4["AC"] == "L" && v4["AT"] == "N" && v4["PR"] == "N" && v4["UI"] == "N",
            };
            var total = v4["VC"] == "H" && v4["VI"] == "H" && v4["VA"] == "H";
            return (automatable, total ? TechnicalImpact.Total : TechnicalImpact.Partial);
        }

        if (CvssV3Vector.TryParse(cvssVector, out var v3))
        {
            var automatable = v3["AV"] == "N" && v3["AC"] == "L" && v3["PR"] == "N" && v3["UI"] == "N";
            var total = v3["C"] == "H" && v3["I"] == "H" && v3["A"] == "H";
            return (automatable, total ? TechnicalImpact.Total : TechnicalImpact.Partial);
        }

        return (null, null);
    }
}
