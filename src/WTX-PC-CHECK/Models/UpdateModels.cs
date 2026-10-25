namespace WtxPcCheck.Models;

public enum UpdateState
{
    Idle,
    Disabled,
    NotConfigured,
    Checking,
    UpToDate,
    Downloading,
    ReadyToInstall,
    Failed,
    Applying
}

public sealed class UpdateManifest
{
    public string Version { get; init; } = string.Empty;
    public string Url { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public string SignerThumbprint { get; init; } = string.Empty;
    public string Publisher { get; init; } = string.Empty;
    public string ReleaseNotes { get; init; } = string.Empty;
    public DateTimeOffset? PublishedUtc { get; init; }
}

public sealed class UpdateCheckOutcome
{
    public bool Succeeded { get; init; }
    public bool UpdateAvailable { get; init; }
    public bool NotConfigured { get; init; }
    public string Message { get; init; } = string.Empty;
    public UpdateManifest? Manifest { get; init; }
    public string? StagedExePath { get; init; }
    public string? StagedSha256 { get; init; }
    public long StagedBytes { get; init; }
}

public sealed class UpdateSnapshot
{
    public UpdateState State { get; init; } = UpdateState.Idle;
    public string Message { get; init; } = "Not checked yet.";
    public string? LatestVersion { get; init; }
    public double? ProgressPercent { get; init; }
    public long BytesReceived { get; init; }
    public long? TotalBytes { get; init; }
    public DateTimeOffset? CheckedUtc { get; init; }
    public string? ReleaseNotes { get; init; }
    public string? StagedPath { get; init; }
}

public enum DefenderScanState
{
    Idle,
    Running,
    NoThreats,
    ThreatsFound,
    Failed,
    Cancelled,
    NotAvailable
}

public sealed class DefenderScanResult
{
    public DefenderScanState State { get; init; } = DefenderScanState.Idle;
    public int? ExitCode { get; init; }
    public string Summary { get; init; } = "Windows Defender scan has not been run.";
    public DateTimeOffset? StartedUtc { get; init; }
    public DateTimeOffset? CompletedUtc { get; init; }
    public TimeSpan Duration => StartedUtc is null || CompletedUtc is null
        ? TimeSpan.Zero
        : CompletedUtc.Value - StartedUtc.Value;
    public bool QuickScan { get; init; }
}

