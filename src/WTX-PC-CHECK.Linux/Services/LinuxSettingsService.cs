using System.IO;
using System.Text.Json;
using WtxPcCheck.Models;

namespace WtxPcCheck.Linux.Services;

public sealed class LinuxSettingsService
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };
    private static readonly int[] AllowedIntervals = [1, 6, 12, 24];

    public AppSettings Load()
    {
        try
        {
            if (!File.Exists(LinuxPaths.SettingsFile)) return new AppSettings();
            var loaded = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(LinuxPaths.SettingsFile), Options);
            if (loaded is null) return new AppSettings();
            if (!AllowedIntervals.Contains(loaded.UpdateIntervalHours)) loaded.UpdateIntervalHours = 6;
            return loaded;
        }
        catch
        {
            return new AppSettings();
        }
    }

    public bool Save(AppSettings settings)
    {
        try
        {
            Directory.CreateDirectory(LinuxPaths.ConfigDirectory);
            var temp = LinuxPaths.SettingsFile + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(settings, Options));
            File.Move(temp, LinuxPaths.SettingsFile, true);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
