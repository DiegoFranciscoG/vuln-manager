namespace VulnManager.Domain.Entities;

/// <summary>Local copy of one entry of the CISA Known Exploited Vulnerabilities catalog.</summary>
public sealed class KevEntry
{
    private KevEntry()
    {
    }

    public KevEntry(string cveId)
    {
        CveId = cveId;
    }

    public string CveId { get; private set; } = string.Empty;

    public string VendorProject { get; private set; } = string.Empty;

    public string Product { get; private set; } = string.Empty;

    public string VulnerabilityName { get; private set; } = string.Empty;

    public DateOnly DateAdded { get; private set; }

    public DateOnly? DueDate { get; private set; }

    public string ShortDescription { get; private set; } = string.Empty;

    public string RequiredAction { get; private set; } = string.Empty;

    public bool KnownRansomwareCampaignUse { get; private set; }

    public bool? ForensicTriage { get; private set; }

    public string[] Cwes { get; private set; } = [];

    public string CatalogVersion { get; private set; } = string.Empty;

    public DateTimeOffset? RemovedAt { get; private set; }

    /// <summary>Returns true when any stored value changed.</summary>
    public bool Apply(
        string vendorProject,
        string product,
        string vulnerabilityName,
        DateOnly dateAdded,
        DateOnly? dueDate,
        string shortDescription,
        string requiredAction,
        bool knownRansomware,
        bool? forensicTriage,
        IReadOnlyCollection<string> cwes,
        string catalogVersion)
    {
        ArgumentNullException.ThrowIfNull(cwes);
        var cweArray = cwes.ToArray();
        var changed = VendorProject != vendorProject || Product != product || VulnerabilityName != vulnerabilityName
                      || DateAdded != dateAdded || DueDate != dueDate || ShortDescription != shortDescription
                      || RequiredAction != requiredAction || KnownRansomwareCampaignUse != knownRansomware
                      || ForensicTriage != forensicTriage || !Cwes.SequenceEqual(cweArray) || RemovedAt is not null;

        VendorProject = Clip(vendorProject, 200);
        Product = Clip(product, 200);
        VulnerabilityName = Clip(vulnerabilityName, 300);
        DateAdded = dateAdded;
        DueDate = dueDate;
        ShortDescription = shortDescription;
        RequiredAction = requiredAction;
        KnownRansomwareCampaignUse = knownRansomware;
        ForensicTriage = forensicTriage;
        Cwes = cweArray;
        CatalogVersion = catalogVersion;
        RemovedAt = null;
        return changed;
    }

    public void MarkRemoved(DateTimeOffset now) => RemovedAt ??= now;

    private static string Clip(string value, int max) => value.Length > max ? value[..max] : value;
}
