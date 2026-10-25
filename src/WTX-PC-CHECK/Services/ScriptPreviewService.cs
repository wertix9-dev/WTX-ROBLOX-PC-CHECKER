using System.IO;
using System.Text;

namespace WtxPcCheck.Services;

public static class ScriptPreviewService
{
    public const int MaxPreviewBytes = 64 * 1024;

    public sealed class PreviewResult
    {
        public bool Success { get; init; }
        public string Text { get; init; } = string.Empty;
        public bool Truncated { get; init; }
        public bool Binary { get; init; }
        public string Note { get; init; } = string.Empty;
    }

    public static PreviewResult TryRead(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
                return new PreviewResult { Note = "The script no longer exists at this path." };
            if (info.Length > 8L * 1024 * 1024)
                return new PreviewResult { Note = "Preview is limited to script files smaller than 8 MB." };

            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var count = (int)Math.Min(info.Length, MaxPreviewBytes);
            var buffer = new byte[count];
            var read = stream.Read(buffer, 0, count);
            var binary = buffer.AsSpan(0, read).Contains((byte)0);
            if (binary)
            {
                return new PreviewResult
                {
                    Binary = true,
                    Note = "This script file appears to contain binary data, so no text preview is shown."
                };
            }

            var text = Encoding.UTF8.GetString(buffer, 0, read).TrimStart('\uFEFF');
            var sanitized = Sanitize(text);
            return new PreviewResult
            {
                Success = true,
                Text = sanitized,
                Truncated = info.Length > read,
                Note = info.Length > read
                    ? $"Preview shows the first {MaxPreviewBytes / 1024} KB. The script is not executed."
                    : "The script is shown as static text. It is not executed."
            };
        }
        catch
        {
            return new PreviewResult { Note = "The script could not be read for preview." };
        }
    }

    private static string Sanitize(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var ch in text)
        {
            if (ch is '\r' or '\n' or '\t' || ch >= ' ')
                builder.Append(ch);
            else
                builder.Append('·');
        }
        return builder.ToString();
    }
}
