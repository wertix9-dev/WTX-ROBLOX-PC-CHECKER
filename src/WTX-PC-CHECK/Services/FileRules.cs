using System.IO;
using System.Text.RegularExpressions;

namespace WtxPcCheck.Services;

public static partial class FileRules
{
    private static readonly HashSet<string> PeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".cpl", ".sys", ".ocx"
    };

    private static readonly Dictionary<string, string> TypeLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        [".exe"] = "Windows application (.exe)",
        [".dll"] = "Dynamic-link library (.dll)",
        [".scr"] = "Screen saver (.scr)",
        [".com"] = "Command program (.com)",
        [".cpl"] = "Control panel item (.cpl)",
        [".sys"] = "System driver (.sys)",
        [".ocx"] = "ActiveX control (.ocx)",
        [".lua"] = "Lua script (.lua)",
        [".luau"] = "Luau script (.luau)"
    };

    public static bool IsPeFile(string path) => PeExtensions.Contains(Path.GetExtension(path));

    public static bool IsLuaFile(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".lua", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".luau", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsCandidateFile(string path) => IsPeFile(path) || IsLuaFile(path);

    public static string FileTypeLabel(string path)
    {
        var extension = Path.GetExtension(path);
        if (TypeLabels.TryGetValue(extension, out var label)) return label;
        return string.IsNullOrWhiteSpace(extension)
            ? "File"
            : $"{extension.TrimStart('.').ToUpperInvariant()} file";
    }

    public static string NormalizeName(string value)
        => NonAlphaNumeric().Replace(value.ToLowerInvariant(), string.Empty);

    public static bool IsCloudOnly(FileAttributes attributes)
        => attributes.HasFlag(FileAttributes.Offline)
           || ((int)attributes & 0x40000) != 0
           || ((int)attributes & 0x400000) != 0;

    public static bool IsInRobloxVersionsFolder(string path)
        => path.Contains(@"\Roblox\Versions\", StringComparison.OrdinalIgnoreCase);

    public static bool IsUserWritableLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var comparison = StringComparison.OrdinalIgnoreCase;
        var prefixes = new List<string?>
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        };
        foreach (var prefix in prefixes)
        {
            if (string.IsNullOrWhiteSpace(prefix)) continue;
            if (path.StartsWith(prefix, comparison)) return true;
        }
        return false;
    }

    public static bool LooksLikeDownloadsOrTemp(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var comparison = StringComparison.OrdinalIgnoreCase;
        var temp = Path.GetTempPath();
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        return path.StartsWith(temp, comparison) || path.StartsWith(downloads, comparison);
    }

    [GeneratedRegex("[^a-z0-9]+", RegexOptions.CultureInvariant)]
    private static partial Regex NonAlphaNumeric();
}

