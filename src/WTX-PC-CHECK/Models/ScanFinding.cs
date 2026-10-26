namespace WtxPcCheck.Models;

public enum FindingClassification
{
    KnownCheatClient,
    PotentiallySuspicious,
    MalwareDetectedByWindowsSecurity,
    MalwareDetectedByLocalScanner,
    UnknownFile,
    LikelyLegitimateMod
}

public enum ConfidenceLevel
{
    Low,
    Medium,
    High
}

public enum RiskLevel
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3
}

public enum FindingCategory
{
    ExecutorIndicator,
    ScriptReview,
    MinecraftReview,
    MalwareIndicator,
    SecurityObservation
}

public sealed class ScanFinding
{
    public required string FileName { get; init; }
    public required string FullPath { get; init; }
    public required string FileType { get; init; }
    public required string Explanation { get; init; }
    public required string DetectionMethod { get; init; }
    public required string Limitations { get; init; }
    public required FindingCategory Category { get; init; }
    public FindingClassification Classification { get; init; } = FindingClassification.PotentiallySuspicious;
    public ConfidenceLevel Confidence { get; init; } = ConfidenceLevel.Low;
    public string Evidence { get; init; } = string.Empty;
    public RiskLevel Risk { get; init; } = RiskLevel.Low;
    public long SizeBytes { get; init; }
    public DateTime ModifiedUtc { get; init; }
    public SignatureInfo Signature { get; init; } = SignatureInfo.NotChecked("Digital signature verification was not needed for this item.");
    public string? Sha256 { get; init; }
    public string? HashNote { get; init; }
    public string? MatchedRule { get; init; }
    public bool IsScriptFile { get; init; }
    public bool IsCloudOnly { get; init; }
    public bool IsArchive { get; init; }

    public string RiskLabel => Risk switch
    {
        RiskLevel.High => "High",
        RiskLevel.Medium => "Medium",
        RiskLevel.Low => "Low",
        _ => "Info"
    };

    public string ConfidenceLabel => Confidence switch
    {
        ConfidenceLevel.High => "High confidence",
        ConfidenceLevel.Medium => "Medium confidence",
        _ => "Low confidence"
    };

    public string ClassificationLabel => Classification switch
    {
        FindingClassification.KnownCheatClient => "Known Cheat Client",
        FindingClassification.PotentiallySuspicious => "Potentially Suspicious",
        FindingClassification.MalwareDetectedByWindowsSecurity => "Malware Detected by Windows Security",
        FindingClassification.MalwareDetectedByLocalScanner => "Malware Detected by Local Scanner",
        FindingClassification.UnknownFile => "Unknown File",
        FindingClassification.LikelyLegitimateMod => "Likely Legitimate Mod",
        _ => "Unknown File"
    };

    public string CategoryLabel => Category switch
    {
        FindingCategory.ExecutorIndicator => "Roblox executor indicator",
        FindingCategory.ScriptReview => "Lua script review",
        FindingCategory.MinecraftReview => "Minecraft review",
        FindingCategory.MalwareIndicator => "Malware indicator",
        FindingCategory.SecurityObservation => "Windows security finding",
        _ => "Finding"
    };

    public string SizeText => AppFormat.Bytes(SizeBytes);
    public string ModifiedText => AppFormat.Date(ModifiedUtc);
    public string RiskSortKey => Risk switch
    {
        RiskLevel.High => "0",
        RiskLevel.Medium => "1",
        RiskLevel.Low => "2",
        _ => "3"
    };
}



