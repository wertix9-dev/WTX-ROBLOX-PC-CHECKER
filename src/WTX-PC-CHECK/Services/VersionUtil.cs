namespace WtxPcCheck.Services;

public static class VersionUtil
{
    public static Version? TryParse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var value = text.Trim();
        if (value.StartsWith('v') || value.StartsWith('V')) value = value[1..];
        var cut = value.IndexOfAny(['-', '+', ' ']);
        if (cut >= 0) value = value[..cut];
        var pieces = value.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (pieces.Length is < 2 or > 4) return null;
        var numbers = new int[4];
        for (var i = 0; i < pieces.Length; i++)
        {
            if (!int.TryParse(pieces[i], out var number) || number < 0) return null;
            numbers[i] = number;
        }
        return new Version(numbers[0], numbers[1], numbers[2], numbers[3]);
    }

    public static bool IsNewer(string candidate, string current)
    {
        var left = TryParse(candidate);
        var right = TryParse(current);
        return left is not null && right is not null && left > right;
    }
}
