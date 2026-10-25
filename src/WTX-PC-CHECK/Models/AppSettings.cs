namespace WtxPcCheck.Models;

public sealed class AppSettings
{
    public bool AutomaticUpdates { get; set; } = true;
    public int UpdateIntervalHours { get; set; } = 6;
    public bool ReduceMotion { get; set; }
    public DateTimeOffset? LastUpdateCheckUtc { get; set; }

    public AppSettings Clone() => new()
    {
        AutomaticUpdates = AutomaticUpdates,
        UpdateIntervalHours = UpdateIntervalHours,
        ReduceMotion = ReduceMotion,
        LastUpdateCheckUtc = LastUpdateCheckUtc
    };
}

public sealed class SettingsLoadResult
{
    public required AppSettings Settings { get; init; }
    public string? Warning { get; init; }
}
