using System.IO;

namespace WtxPcCheck.Linux.Services;

public static class LinuxPaths
{
    public static string Home { get; } = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    public static string XdgConfigHome { get; } =
        Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } config ? config : Path.Combine(Home, ".config");
    public static string XdgCacheHome { get; } =
        Environment.GetEnvironmentVariable("XDG_CACHE_HOME") is { Length: > 0 } cache ? cache : Path.Combine(Home, ".cache");
    public static string ConfigDirectory { get; } = Path.Combine(XdgConfigHome, "wtx-pc-check");
    public static string SettingsFile { get; } = Path.Combine(ConfigDirectory, "settings.json");
    public static string CacheDirectory { get; } = Path.Combine(XdgCacheHome, "wtx-pc-check");
    public static string UpdateWorkDirectory { get; } = Path.Combine(CacheDirectory, "updates");
    public static string ExecutablePath => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "WTX-PC-CHECK");

    public static string? AppImagePath
    {
        get
        {
            var value = Environment.GetEnvironmentVariable("APPIMAGE");
            return !string.IsNullOrWhiteSpace(value) && File.Exists(value) ? value : null;
        }
    }

    public static bool IsAppImage => AppImagePath is not null;
    public static bool IsTarOrPackageInstall => !IsAppImage;
}
