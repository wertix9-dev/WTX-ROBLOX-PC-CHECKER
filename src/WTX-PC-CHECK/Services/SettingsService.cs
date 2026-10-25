using System.IO;
using System.Text.Json;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public sealed class SettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private static readonly int[] AllowedIntervals = [1, 6, 12, 24];

    public SettingsLoadResult Load()
    {
        try
        {
            if (!File.Exists(AppPaths.SettingsFile))
                return new SettingsLoadResult { Settings = new AppSettings() };

            var json = File.ReadAllText(AppPaths.SettingsFile);
            var loaded = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
            if (!AllowedIntervals.Contains(loaded.UpdateIntervalHours))
                loaded.UpdateIntervalHours = 6;

            return new SettingsLoadResult { Settings = loaded };
        }
        catch
        {
            return new SettingsLoadResult
            {
                Settings = new AppSettings(),
                Warning = "Your saved preferences could not be read, so default settings were loaded."
            };
        }
    }

    public bool TrySave(AppSettings settings)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.LocalDataDirectory);
            var temp = AppPaths.SettingsFile + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(settings, JsonOptions));
            File.Move(temp, AppPaths.SettingsFile, true);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
