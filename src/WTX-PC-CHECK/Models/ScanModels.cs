namespace WtxPcCheck.Models;

public sealed class ArchiveIssue
{
    public required string Path { get; init; }
    public required string Reason { get; init; }
}

public sealed class ScanRequest
{
    public required IReadOnlyList<string> Roots { get; init; }
    public bool ScanRobloxExecutables { get; init; } = true;
    public bool ScanLuaScripts { get; init; } = true;
    public bool AnalyzeLuaContents { get; init; } = true;
    public bool ScanMinecraftJars { get; init; } = true;
    public bool DetectMinecraftCheatIndicators { get; init; } = true;
    public bool ReviewMinecraftJars { get; init; } = true;
    public int MaxFindings { get; init; } = 1000;
    public int MaxMinecraftReviewFindings { get; init; } = 300;
    public long MaxArchiveBytes { get; init; } = 100L * 1024 * 1024;
    public int MaxArchiveEntries { get; init; } = 20000;
    public long MaxArchiveMetadataBytes { get; init; } = 512L * 1024;
}

public sealed class ScanProgress
{
    public long FilesChecked { get; init; }
    public long DirectoriesChecked { get; init; }
    public string CurrentPath { get; init; } = string.Empty;
    public int FindingCount { get; init; }
    public int InaccessibleCount { get; init; }
    public TimeSpan Elapsed { get; init; }
    public long LuaFilesChecked { get; init; }
    public long JarFilesChecked { get; init; }
    public long ReparsePointsSkipped { get; init; }
    public long CloudFilesSkipped { get; init; }
    public bool Paused { get; init; }
}

public sealed class InaccessibleArea
{
    public required string Path { get; init; }
    public required string Reason { get; init; }
    public bool IsDirectory { get; init; }
}

public sealed class ScanOutcome
{
    public required IReadOnlyList<string> Roots { get; init; }
    public List<ScanFinding> Findings { get; } = [];
    public List<InaccessibleArea> InaccessibleAreas { get; } = [];
    public List<ArchiveIssue> ArchiveIssues { get; } = [];
    public long FilesChecked { get; set; }
    public long DirectoriesChecked { get; set; }
    public long LuaFilesChecked { get; set; }
    public long PeFilesChecked { get; set; }
    public long JarFilesChecked { get; set; }
    public long MinecraftArchivesInspected { get; set; }
    public long MinecraftModsReviewed { get; set; }
    public long HashChecksPerformed { get; set; }
    public long SignatureChecksPerformed { get; set; }
    public long ReparsePointsSkipped { get; set; }
    public long CloudFilesSkipped { get; set; }
    public int InaccessibleTotal { get; set; }
    public int ArchiveIssueTotal { get; set; }
    public bool InaccessibleListTruncated => InaccessibleTotal > InaccessibleAreas.Count;
    public bool ArchiveListTruncated => ArchiveIssueTotal > ArchiveIssues.Count;
    public bool FindingLimitReached { get; set; }
    public bool Cancelled { get; set; }
    public bool PausedAndCancelled { get; set; }
    public bool Failed { get; set; }
    public string? ErrorEnglish { get; set; }
    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset CompletedUtc { get; set; }
    public TimeSpan Duration => CompletedUtc - StartedUtc;
    public int HighCount => Findings.Count(f => f.Risk == RiskLevel.High);
    public int MediumCount => Findings.Count(f => f.Risk == RiskLevel.Medium);
    public int LowCount => Findings.Count(f => f.Risk is RiskLevel.Low or RiskLevel.Info);
    public int KnownCheatCount => Findings.Count(f => f.Classification == FindingClassification.KnownCheatClient);
    public int MinecraftReviewCount => Findings.Count(f => f.Category == FindingCategory.MinecraftReview);
}
