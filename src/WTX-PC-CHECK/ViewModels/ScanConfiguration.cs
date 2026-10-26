namespace WtxPcCheck.ViewModels;

public enum ScanProfileKind
{
    Roblox,
    Minecraft,
    Quick,
    Full,
    Custom
}

public enum ScanLocationKind
{
    Roblox,
    Minecraft,
    Common,
    Custom
}

public sealed record ScanProfileOption(ScanProfileKind Kind, string Label, string Description);

public sealed class ScanLocationOption : ObservableObject
{
    private bool _isSelected;

    public required string Label { get; init; }
    public required string Path { get; init; }
    public required ScanLocationKind Kind { get; init; }
    public bool IsCustom { get; init; }

    public string KindLabel => Kind switch
    {
        ScanLocationKind.Roblox => "Roblox",
        ScanLocationKind.Minecraft => "Minecraft",
        ScanLocationKind.Common => "Common user folder",
        _ => "Custom folder"
    };

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }
}
