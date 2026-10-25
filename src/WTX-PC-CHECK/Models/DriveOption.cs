using System.IO;

namespace WtxPcCheck.Models;

public sealed class DriveOption : ObservableObject
{
    private bool _isSelected;

    public DriveOption(DriveInfo drive)
    {
        RootPath = drive.Name;
        try
        {
            DriveType = drive.DriveType;
        }
        catch
        {
            DriveType = DriveType.Unknown;
        }

        TypeLabel = DriveType switch
        {
            DriveType.Fixed => "Fixed drive",
            DriveType.Removable => "Removable drive",
            DriveType.Network => "Network drive",
            DriveType.CDRom => "Optical drive",
            _ => "Drive"
        };

        var label = string.Empty;
        long total = 0;
        long free = 0;
        bool ready = false;
        try
        {
            ready = drive.IsReady;
            if (ready)
            {
                label = drive.VolumeLabel;
                total = drive.TotalSize;
                free = drive.AvailableFreeSpace;
            }
        }
        catch
        {
            ready = false;
        }

        IsReady = ready;
        VolumeLabel = label;
        TotalBytes = total;
        FreeBytes = free;
        DisplayName = RootPath;
        Detail = ready
            ? $"{TypeLabel} · {AppFormat.Bytes(free)} free of {AppFormat.Bytes(total)}"
            : $"{TypeLabel} · Not ready";
    }

    public string RootPath { get; }
    public string DisplayName { get; }
    public string Detail { get; }
    public string TypeLabel { get; }
    public DriveType DriveType { get; }
    public bool IsReady { get; }
    public string VolumeLabel { get; }
    public long TotalBytes { get; }
    public long FreeBytes { get; }
    public bool IsFixed => DriveType == DriveType.Fixed;
    public bool IsRemovable => DriveType == DriveType.Removable;
    public bool IsNetwork => DriveType == DriveType.Network;
    public bool CanBeSelected => DriveType is DriveType.Fixed or DriveType.Removable or DriveType.Network;

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }
}

