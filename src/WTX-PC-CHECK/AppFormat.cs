using System.Globalization;

namespace WtxPcCheck;

public static class AppFormat
{
    private static readonly CultureInfo English = CultureInfo.GetCultureInfo("en-US");

    public static string Count(long value) => value.ToString("N0", English);

    public static string Bytes(long value)
    {
        if (value < 0) return "Unknown";
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double size = value;
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        return unit == 0
            ? $"{size.ToString("N0", English)} {units[unit]}"
            : $"{size.ToString("N1", English)} {units[unit]}";
    }

    public static string Date(DateTime value) => value.ToLocalTime().ToString("MMM d, yyyy, HH:mm", English);

    public static string Date(DateTimeOffset value) => value.ToLocalTime().ToString("MMM d, yyyy, HH:mm", English);

    public static string Duration(TimeSpan value)
    {
        if (value.TotalHours >= 1)
            return $"{(int)value.TotalHours}h {value.Minutes}m {value.Seconds}s";
        if (value.TotalMinutes >= 1)
            return $"{value.Minutes}m {value.Seconds}s";
        return $"{Math.Max(0, (int)value.TotalSeconds)}s";
    }

    public static string Relative(DateTimeOffset? when)
    {
        if (when is null) return "Never";
        var span = DateTimeOffset.UtcNow - when.Value;
        if (span.TotalSeconds < 60) return "Just now";
        if (span.TotalMinutes < 60) return $"{(int)span.TotalMinutes} min ago";
        if (span.TotalHours < 24) return $"{(int)span.TotalHours} h ago";
        return Date(when.Value);
    }
}
