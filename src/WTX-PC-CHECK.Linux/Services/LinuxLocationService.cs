using System.IO;
using WtxPcCheck.ViewModels;

namespace WtxPcCheck.Linux.Services;

public sealed class LinuxMountOption : ObservableObject
{
    private bool _isSelected;
    public required string MountPoint { get; init; }
    public required string FileSystemType { get; init; }
    public string Label => MountPoint == "/" ? "Root filesystem (/)" : MountPoint;
    public bool IsSelected { get => _isSelected; set => SetProperty(ref _isSelected, value); }
}

public static class LinuxLocationService
{
    public static List<ScanLocationOption> DetectGameFolders()
    {
        var result = new List<ScanLocationOption>();
        var home = LinuxPaths.Home;
        var appData = Environment.GetEnvironmentVariable("XDG_DATA_HOME") is { Length: > 0 } data
            ? data
            : Path.Combine(home, ".local", "share");
        Add(result, "Minecraft .minecraft folder", Path.Combine(home, ".minecraft"), ScanLocationKind.Minecraft);
        Add(result, "Prism Launcher instances", Path.Combine(appData, "PrismLauncher", "instances"), ScanLocationKind.Minecraft);
        Add(result, "Modrinth launcher profiles", Path.Combine(appData, "ModrinthApp", "profiles"), ScanLocationKind.Minecraft);
        Add(result, "MultiMC instances", Path.Combine(appData, "MultiMC", "instances"), ScanLocationKind.Minecraft);
        Add(result, "ATLauncher instances", Path.Combine(appData, "ATLauncher", "instances"), ScanLocationKind.Minecraft);
        Add(result, "Technic Launcher modpacks", Path.Combine(appData, "technic", "modpacks"), ScanLocationKind.Minecraft);
        Add(result, "GDLauncher instances", Path.Combine(appData, "GDLauncher", "instances"), ScanLocationKind.Minecraft);

        Add(result, "Prism Launcher Flatpak instances", Path.Combine(home, ".var", "app", "org.prismlauncher.PrismLauncher", "data", "PrismLauncher", "instances"), ScanLocationKind.Minecraft);
        Add(result, "Modrinth Flatpak profiles", Path.Combine(home, ".var", "app", "com.modrinth.ModrinthApp", "data", "ModrinthApp", "profiles"), ScanLocationKind.Minecraft);
        Add(result, "MultiMC Flatpak instances", Path.Combine(home, ".var", "app", "org.multimc.MultiMC", "data", "MultiMC", "instances"), ScanLocationKind.Minecraft);
        Add(result, "ATLauncher Flatpak instances", Path.Combine(home, ".var", "app", "io.atlauncher.ATLauncher", "data", "ATLauncher", "instances"), ScanLocationKind.Minecraft);

        Add(result, "Sober Roblox data (Flatpak)", Path.Combine(home, ".var", "app", "org.vinegarhq.Sober", "data", "sober"), ScanLocationKind.Roblox);
        Add(result, "Vinegar Roblox prefix (Flatpak)", Path.Combine(home, ".var", "app", "org.vinegarhq.Vinegar", "data", "vinegar"), ScanLocationKind.Roblox);
        Add(result, "Sober Roblox data", Path.Combine(appData, "sober"), ScanLocationKind.Roblox);

        try
        {
            var wineRoot = Path.Combine(home, ".wine", "drive_c", "users");
            if (Directory.Exists(wineRoot))
            {
                foreach (var user in Directory.EnumerateDirectories(wineRoot).Take(5))
                    Add(result, "Roblox in Wine prefix", Path.Combine(user, "AppData", "Local", "Roblox"), ScanLocationKind.Roblox);
            }
        }
        catch { }

        return result.DistinctBy(l => l.Path).ToList();
    }

    public static List<ScanLocationOption> DetectCommonFolders()
    {
        var result = new List<ScanLocationOption>();
        Add(result, "Downloads", Path.Combine(LinuxPaths.Home, "Downloads"), ScanLocationKind.Common);
        Add(result, "Desktop", Path.Combine(LinuxPaths.Home, "Desktop"), ScanLocationKind.Common);
        return result;
    }

    public static List<LinuxMountOption> DetectMounts()
    {
        var result = new List<LinuxMountOption>();
        var pseudo = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "ramfs", "cgroup", "cgroup2",
            "securityfs", "pstore", "autofs", "mqueue", "debugfs", "tracefs", "configfs",
            "fusectl", "bpf", "hugetlbfs", "nsfs", "squashfs", "overlay", "fuse.portal"
        };
        try
        {
            foreach (var line in File.ReadLines("/proc/mounts"))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;
                var mountPoint = UnescapeMount(parts[1]);
                var fsType = parts[2];
                if (mountPoint is "/boot" or "/boot/efi" || mountPoint.StartsWith("/boot/", StringComparison.Ordinal)) continue;
                if (mountPoint.StartsWith("/snap", StringComparison.Ordinal)) continue;
                if (mountPoint.StartsWith("/run", StringComparison.Ordinal) && !mountPoint.StartsWith("/run/media", StringComparison.Ordinal)) continue;
                if (pseudo.Contains(fsType) && mountPoint != "/") continue;
                if (mountPoint is "/proc" or "/sys" or "/dev" or "/run" or "/tmp") continue;
                if (result.Any(m => m.MountPoint.Equals(mountPoint, StringComparison.Ordinal))) continue;
                result.Add(new LinuxMountOption { MountPoint = mountPoint, FileSystemType = fsType });
            }
        }
        catch { }
        if (result.All(m => m.MountPoint != "/"))
            result.Insert(0, new LinuxMountOption { MountPoint = "/", FileSystemType = "unknown" });
        return result;
    }

    private static void Add(List<ScanLocationOption> list, string label, string path, ScanLocationKind kind)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;
        if (list.Any(l => l.Path.Equals(path, StringComparison.OrdinalIgnoreCase))) return;
        list.Add(new ScanLocationOption { Label = label, Path = path, Kind = kind });
    }

    private static string UnescapeMount(string value)
        => value.Replace("\\040", " ", StringComparison.Ordinal).Replace("\\011", "\t", StringComparison.Ordinal);
}
