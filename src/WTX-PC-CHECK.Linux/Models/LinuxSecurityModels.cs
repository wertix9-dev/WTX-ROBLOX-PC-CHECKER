namespace WtxPcCheck.Linux.Models;

public enum LinuxSecurityState
{
    NotChecked,
    Checking,
    Available,
    Partial,
    Unavailable
}

public sealed class LinuxFirewallStatus
{
    public bool Available { get; init; }
    public bool? Active { get; init; }
    public string Summary { get; init; } = "Firewall status unavailable";
    public string Detail { get; init; } = string.Empty;
}

public sealed class LinuxUpdateStatus
{
    public bool Available { get; init; }
    public string Kind { get; init; } = "unknown";
    public int? PendingCount { get; init; }
    public string Summary { get; init; } = "Update status unavailable";
    public string Detail { get; init; } = string.Empty;
}

public sealed class LinuxStartupEntry
{
    public required string Name { get; init; }
    public required string Source { get; init; }
    public required string Command { get; init; }
    public string? ExecutablePath { get; init; }
    public bool? ExecutableExists { get; init; }
    public WtxPcCheck.Models.RiskLevel Risk { get; init; }
    public required string Explanation { get; init; }
    public string RiskLabel => Risk switch
    {
        WtxPcCheck.Models.RiskLevel.High => "High attention",
        WtxPcCheck.Models.RiskLevel.Medium => "Review",
        WtxPcCheck.Models.RiskLevel.Low => "Low",
        _ => "Info"
    };
}

public sealed class LinuxProcessInfo
{
    public required string Name { get; init; }
    public int ProcessId { get; init; }
    public string? ExecutablePath { get; init; }
    public WtxPcCheck.Models.RiskLevel Risk { get; init; }
    public string Explanation { get; init; } = string.Empty;
    public string PathDisplay => ExecutablePath ?? "Path unavailable (access denied or kernel process)";
    public string RiskLabel => Risk switch
    {
        WtxPcCheck.Models.RiskLevel.High => "High attention",
        WtxPcCheck.Models.RiskLevel.Medium => "Review",
        WtxPcCheck.Models.RiskLevel.Low => "Low",
        _ => "Info"
    };
}

public sealed class ClamAvStatus
{
    public bool Available { get; init; }
    public string? Executable { get; init; }
    public string? Version { get; init; }
    public string Detail { get; init; } = "ClamAV was not found.";
}

public sealed class ClamAvFinding
{
    public required string Path { get; init; }
    public required string Signature { get; init; }
}

public enum ClamAvScanState
{
    Idle,
    Running,
    NoThreats,
    ThreatsFound,
    Failed,
    Cancelled,
    NotAvailable
}

public sealed class ClamAvScanResult
{
    public ClamAvScanState State { get; init; }
    public string Summary { get; init; } = "ClamAV has not been run.";
    public int? ExitCode { get; init; }
    public int? ScannedFiles { get; init; }
    public int? InfectedFiles { get; init; }
    public List<ClamAvFinding> Findings { get; init; } = [];
    public DateTimeOffset? StartedUtc { get; init; }
    public DateTimeOffset? CompletedUtc { get; init; }
    public TimeSpan Duration => StartedUtc is null || CompletedUtc is null ? TimeSpan.Zero : CompletedUtc.Value - StartedUtc.Value;
}

public sealed class LinuxSecurityOverview
{
    public LinuxSecurityState State { get; set; } = LinuxSecurityState.NotChecked;
    public string Distribution { get; set; } = "Linux";
    public string DistributionId { get; set; } = "unknown";
    public string SupportNote { get; set; } = string.Empty;
    public LinuxFirewallStatus Firewall { get; set; } = new();
    public LinuxUpdateStatus Updates { get; set; } = new();
    public List<LinuxStartupEntry> StartupEntries { get; set; } = [];
    public int StartupEntryCount { get; set; }
    public List<LinuxProcessInfo> Processes { get; set; } = [];
    public int ProcessCount { get; set; }
    public bool ProcessListTruncated { get; set; }
    public ClamAvStatus ClamAv { get; set; } = new();
    public string ProcessNote { get; set; } = string.Empty;
    public DateTimeOffset? CheckedUtc { get; set; }
    public string? ErrorEnglish { get; set; }
}

