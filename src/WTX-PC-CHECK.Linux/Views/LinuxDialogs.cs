using System.Diagnostics;
using System.IO;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using WtxPcCheck.Models;

namespace WtxPcCheck.Linux.Views;

public static class LinuxDialogs
{
    private static Window? Owner =>
        (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;

    public static async Task<bool> ShowPrivacyAsync(bool reduceMotion)
    {
        var owner = Owner;
        if (owner is null) return false;
        var dialog = new PrivacyDialog();
        return await dialog.ShowDialog<bool>(owner);
    }

    public static async Task<bool> ShowMessageAsync(string title, string message, string primaryLabel = "OK", string? secondaryLabel = null, bool warning = false)
        => await MessageDialog.ShowAsync(Owner, title, message, primaryLabel, secondaryLabel, warning);

    public static async Task<IReadOnlyList<string>> PickFoldersAsync()
    {
        var owner = Owner;
        if (owner?.StorageProvider is null) return [];
        var folders = await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select folders to scan",
            AllowMultiple = true
        });
        var paths = new List<string>();
        foreach (var folder in folders)
        {
            var path = folder.TryGetLocalPath();
            if (!string.IsNullOrWhiteSpace(path)) paths.Add(path);
        }
        return paths;
    }

    public static async Task<(bool Ok, string Error)> OpenLocationAsync(string path)
    {
        try
        {
            if (!File.Exists(path) && !Directory.Exists(path))
                return (false, "The file or folder no longer exists at this path.");
            var directory = File.Exists(path) ? Path.GetDirectoryName(path) : path;
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
                return (false, "The parent folder could not be opened.");
            var startInfo = new ProcessStartInfo("xdg-open")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add(directory);
            Process.Start(startInfo);
            return (true, string.Empty);
        }
        catch
        {
            return (false, "The file manager could not be opened. You can navigate to the path manually.");
        }
    }

    public static async Task ShowFindingDetailsAsync(ScanFinding finding, bool reduceMotion)
        => await FindingDetailsWindow.ShowAsync(Owner, finding, reduceMotion);

    public static async Task<bool> ShowUpdateRestartAsync(string version, string? notes, bool reduceMotion)
    {
        var owner = Owner;
        if (owner is null) return false;
        return await UpdateRestartDialog.ShowAsync(owner, version, notes, reduceMotion);
    }

    public static void ShutdownApplication()
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            desktop.Shutdown();
        else
            Environment.Exit(0);
    }
}
