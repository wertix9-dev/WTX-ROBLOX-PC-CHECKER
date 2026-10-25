namespace WtxPcCheck.Models;

public enum SecurityQueryState
{
    NotChecked,
    Checking,
    Available,
    Unavailable
}

public sealed class DefenderStatus
{
    public bool Available { get; init; }
    public bool? RealTimeProtectionEnabled { get; init; }
    public bool? AntivirusEnabled { get; init; }
    public bool? AmServiceEnabled { get; init; }
    public bool? TamperProtectionEnabled { get; init; }
    public string? SignatureVersion { get; init; }
    public DateTimeOffset? SignatureUpdated { get; init; }
    public string Note { get; init; } = string.Empty;

    public string Summary
    {
        get
        {
            if (!Available) return "Defender status unavailable";
            if (RealTimeProtectionEnabled == true) return "Real-time protection on";
            if (RealTimeProtectionEnabled == false) return "Real-time protection off";
            return "Status partially available";
        }
    }
}

public sealed class FirewallStatus
{
    public bool Available { get; init; }
    public bool? DomainEnabled { get; init; }
    public bool? PrivateEnabled { get; init; }
    public bool? PublicEnabled { get; init; }
    public string Note { get; init; } = string.Empty;

    public bool? AllEnabled =>
        DomainEnabled is null || PrivateEnabled is null || PublicEnabled is null
            ? null
            : DomainEnabled == true && PrivateEnabled == true && PublicEnabled == true;

    public string Summary
    {
        get
        {
            if (!Available) return "Firewall status unavailable";
            if (AllEnabled == true) return "Firewall on for all profiles";
            if (AllEnabled == false)
            {
                var off = new List<string>();
                if (DomainEnabled == false) off.Add("domain");
                if (PrivateEnabled == false) off.Add("private");
                if (PublicEnabled == false) off.Add("public");
                return $"Firewall off for: {string.Join(", ", off)}";
            }
            return "Firewall status partially available";
        }
    }
}

public sealed class WindowsUpdatesStatus
{
    public bool Available { get; init; }
    public bool SearchSucceeded { get; init; }
    public bool TimedOut { get; init; }
    public int PendingCount { get; init; }
    public int SecurityCount { get; init; }
    public string Note { get; init; } = string.Empty;

    public string Summary
    {
        get
        {
            if (!Available) return "Windows Update status unavailable";
            if (TimedOut) return "Windows Update check timed out";
            if (!SearchSucceeded) return "Windows Update could not be checked";
            if (PendingCount == 0) return "No offered updates found";
            return SecurityCount > 0
                ? $"{SecurityCount} security-related update{(SecurityCount == 1 ? "" : "s")} offered"
                : $"{PendingCount} update{(PendingCount == 1 ? "" : "s")} offered";
        }
    }
}

public sealed class StartupEntry
{
    public required string Name { get; init; }
    public required string Source { get; init; }
    public required string Command { get; init; }
    public string? ExecutablePath { get; init; }
    public bool? ExecutableExists { get; init; }
    public RiskLevel Risk { get; init; }
    public required string Explanation { get; init; }
    public SignatureInfo Signature { get; init; } = SignatureInfo.NotChecked("No executable path was resolved.");
    public string RiskLabel => Risk switch
    {
        RiskLevel.High => "High attention",
        RiskLevel.Medium => "Review",
        RiskLevel.Low => "Low",
        _ => "Info"
    };
}

public sealed class SecurityOverview
{
    public SecurityQueryState State { get; set; } = SecurityQueryState.NotChecked;
    public DefenderStatus Defender { get; set; } = new();
    public FirewallStatus Firewall { get; set; } = new();
    public WindowsUpdatesStatus Updates { get; set; } = new();
    public List<StartupEntry> StartupEntries { get; set; } = [];
    public int StartupEntryCount { get; set; }
    public bool StartupListTruncated { get; set; }
    public string StartupNote { get; set; } = string.Empty;
    public List<string> RegisteredAntivirus { get; set; } = [];
    public DateTimeOffset? CheckedUtc { get; set; }
    public string WindowsDisplay { get; set; } = "Windows";
    public string WindowsBuildDisplay { get; set; } = "Unknown build";
    public bool WindowsSupported { get; set; }
    public string? ErrorEnglish { get; set; }
}

