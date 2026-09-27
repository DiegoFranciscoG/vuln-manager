namespace VulnManager.Domain.Entities;

public enum SbomSource
{
    Api = 0,
    Upload = 1,
}

public enum SbomImportStatus
{
    Pending = 0,
    Processed = 1,
    Failed = 2,
}

public sealed class SbomImport
{
    public const string CycloneDxJson = "CYCLONEDX_JSON";
    public const int MaxSizeBytes = 10 * 1024 * 1024;

    private readonly List<SbomComponent> _components = [];

    private SbomImport()
    {
    }

    public SbomImport(
        Guid projectId,
        string specVersion,
        string? bomSerialNumber,
        int? bomVersion,
        SbomSource source,
        string? sourceRef,
        string? fileName,
        string sha256,
        int sizeBytes,
        string importedBy,
        DateTimeOffset now)
    {
        Id = Guid.CreateVersion7(now);
        ProjectId = projectId;
        Format = CycloneDxJson;
        SpecVersion = specVersion;
        BomSerialNumber = bomSerialNumber;
        BomVersion = bomVersion;
        Source = source;
        SourceRef = sourceRef;
        FileName = fileName;
        Sha256 = sha256;
        SizeBytes = sizeBytes;
        ImportedBy = importedBy;
        ImportedAt = now;
        Status = SbomImportStatus.Pending;
    }

    public Guid Id { get; private set; }

    public Guid ProjectId { get; private set; }

    public string Format { get; private set; } = CycloneDxJson;

    public string SpecVersion { get; private set; } = string.Empty;

    public string? BomSerialNumber { get; private set; }

    public int? BomVersion { get; private set; }

    public SbomSource Source { get; private set; }

    public string? SourceRef { get; private set; }

    public string? FileName { get; private set; }

    public string Sha256 { get; private set; } = string.Empty;

    public int SizeBytes { get; private set; }

    public int ComponentCount { get; private set; }

    public int SkippedCount { get; private set; }

    public SbomImportStatus Status { get; private set; }

    public string? ErrorMessage { get; private set; }

    public string ImportedBy { get; private set; } = string.Empty;

    public DateTimeOffset ImportedAt { get; private set; }

    public DateTimeOffset? ProcessedAt { get; private set; }

    public IReadOnlyList<SbomComponent> Components => _components;

    public void AddComponent(Guid componentId, string? bomRef, string? scope)
    {
        if (_components.Exists(c => c.ComponentId == componentId))
        {
            return;
        }

        _components.Add(new SbomComponent(Id, componentId, bomRef, scope));
        ComponentCount = _components.Count;
    }

    public void SetSkipped(int skipped) => SkippedCount = skipped;

    public void MarkProcessed(DateTimeOffset now)
    {
        Status = SbomImportStatus.Processed;
        ProcessedAt = now;
        ErrorMessage = null;
    }

    public void MarkFailed(string message, DateTimeOffset now)
    {
        Status = SbomImportStatus.Failed;
        ProcessedAt = now;
        ErrorMessage = message.Length > 500 ? message[..500] : message;
    }
}

public sealed class SbomComponent
{
    private SbomComponent()
    {
    }

    public SbomComponent(Guid sbomImportId, Guid componentId, string? bomRef, string? scope)
    {
        SbomImportId = sbomImportId;
        ComponentId = componentId;
        BomRef = bomRef is { Length: > 1000 } ? bomRef[..1000] : bomRef;
        Scope = scope is "required" or "optional" or "excluded" ? scope : null;
    }

    public Guid SbomImportId { get; private set; }

    public Guid ComponentId { get; private set; }

    public string? BomRef { get; private set; }

    public string? Scope { get; private set; }
}
