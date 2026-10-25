using System.IO;

namespace WtxPcCheck.Services;

public static class AppPaths
{
    public static string LocalDataDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WTX PC CHECK");

    public static string SettingsFile { get; } = Path.Combine(LocalDataDirectory, "settings.json");
    public static string UpdateStateFile { get; } = Path.Combine(LocalDataDirectory, "update-state.json");
    public static string UpdateWorkDirectory { get; } = Path.Combine(Path.GetTempPath(), "WTX PC CHECK", "updates");

    public static string ExecutablePath =>
        Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "WTX-PC-CHECK.exe");
}
