using System.Diagnostics;
using System.IO;
using System.Windows;

namespace WtxPcCheck.Services;

public static class WindowsIntegration
{
    public static bool OpenFileLocation(string path, out string error)
    {
        error = string.Empty;
        try
        {
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                error = "The file or folder no longer exists at this path. It may have been moved or removed.";
                return false;
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = "explorer.exe",
                UseShellExecute = true
            };
            if (File.Exists(path))
            {
                startInfo.Arguments = $"/select,\"{path}\"";
            }
            else
            {
                startInfo.ArgumentList.Add(path);
            }
            Process.Start(startInfo);
            return true;
        }
        catch
        {
            error = "Windows could not open File Explorer for this location.";
            return false;
        }
    }

    public static bool OpenWindowsSecurity(out string error)
    {
        error = string.Empty;
        try
        {
            Process.Start(new ProcessStartInfo("windowsdefender://threat") { UseShellExecute = true });
            return true;
        }
        catch
        {
            try
            {
                Process.Start(new ProcessStartInfo("windowsdefender://") { UseShellExecute = true });
                return true;
            }
            catch
            {
                error = "Windows Security could not be opened on this PC.";
                return false;
            }
        }
    }

    public static bool OpenWindowsUpdate(out string error)
    {
        error = string.Empty;
        try
        {
            Process.Start(new ProcessStartInfo("ms-settings:windowsupdate") { UseShellExecute = true });
            return true;
        }
        catch
        {
            error = "Windows Update settings could not be opened on this PC.";
            return false;
        }
    }

    public static bool OpenLocalDataFolder(out string error)
    {
        error = string.Empty;
        try
        {
            Directory.CreateDirectory(AppPaths.LocalDataDirectory);
            var startInfo = new ProcessStartInfo("explorer.exe") { UseShellExecute = true };
            startInfo.ArgumentList.Add(AppPaths.LocalDataDirectory);
            Process.Start(startInfo);
            return true;
        }
        catch
        {
            error = "The local settings folder could not be opened.";
            return false;
        }
    }
}

