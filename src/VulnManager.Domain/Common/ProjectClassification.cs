namespace VulnManager.Domain.Common;

/// <summary>BOD 26-04 "Publicly Exposed": reachable by unauthenticated or untrusted entities over a public network.</summary>
public enum Exposure
{
    Internal = 0,
    Public = 1,
}

/// <summary>BOD 26-04 asset tag "Environment (prod/dev)".</summary>
public enum DeploymentEnvironment
{
    Production = 0,
    Development = 1,
}

/// <summary>BOD 26-04 asset tag "Asset type (server, application, or network device)".</summary>
public enum AssetType
{
    Application = 0,
    Server = 1,
    NetworkDevice = 2,
}
