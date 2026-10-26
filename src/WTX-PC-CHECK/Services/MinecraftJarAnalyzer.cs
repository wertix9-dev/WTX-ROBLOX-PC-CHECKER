using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public sealed class JarAnalysisResult
{
    public bool Opened { get; init; }
    public string? FailureReason { get; init; }
    public int EntryCount { get; init; }
    public long UncompressedBytes { get; init; }
    public string? ModName { get; init; }
    public string? ModId { get; init; }
    public string? ModLoader { get; init; }
    public string? MainClass { get; init; }
    public bool HasJavaSignatureEntries { get; init; }
    public bool HasModMetadata { get; init; }
    public bool FilenameMatch { get; init; }
    public bool MetadataMatch { get; init; }
    public bool EntryNameMatch { get; init; }
    public string? MatchProduct { get; init; }
    public List<string> Evidence { get; init; } = [];

    public bool AnyKnownMatch => FilenameMatch || MetadataMatch || EntryNameMatch;
}

public static partial class MinecraftJarAnalyzer
{
    private static readonly string[] MetadataEntries =
    [
        "META-INF/MANIFEST.MF",
        "fabric.mod.json",
        "quilt.mod.json",
        "META-INF/mods.toml",
        "META-INF/neoforge.mods.toml",
        "mcmod.info"
    ];

    public static JarAnalysisResult Analyze(
        string path,
        IndicatorDatabase indicators,
        long maxBytes,
        int maxEntries,
        long maxMetadataBytes,
        CancellationToken cancellationToken)
    {
        var evidence = new List<string>();
        var nameMatch = indicators.TryMatchMinecraftToken(Path.GetFileNameWithoutExtension(path), out var nameIndicator);
        if (nameMatch)
            evidence.Add($"The JAR file name contains “{nameIndicator.Product}”, a known Minecraft cheat-client name. A file name alone is not proof.");

        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists)
                return new JarAnalysisResult { Opened = false, FailureReason = "The archive no longer exists.", FilenameMatch = nameMatch, MatchProduct = nameIndicator?.Product, Evidence = evidence };
            if (info.Length > maxBytes)
                return new JarAnalysisResult { Opened = false, FailureReason = "The archive is larger than the 100 MB inspection limit.", FilenameMatch = nameMatch, MatchProduct = nameIndicator?.Product, Evidence = evidence };
        }
        catch
        {
            return new JarAnalysisResult { Opened = false, FailureReason = "The archive metadata could not be read." };
        }

        try
        {
            using var archive = ZipFile.OpenRead(path);
            if (archive.Entries.Count > maxEntries)
                return new JarAnalysisResult
                {
                    Opened = false,
                    FailureReason = $"The archive contains more than {maxEntries:N0} entries and was not inspected.",
                    FilenameMatch = nameMatch,
                    MatchProduct = nameIndicator?.Product,
                    Evidence = evidence
                };

            long uncompressed = 0;
            var metadataFound = false;
            var hasJavaSignature = false;
            var metadataMatch = false;
            var entryNameMatch = false;
            TokenIndicator? matchedProduct = nameMatch ? nameIndicator : null;
            var foundMetadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var entryNames = new List<string>(Math.Min(archive.Entries.Count, 20000));

            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (entry.FullName.Length == 0) continue;
                uncompressed += entry.Length;
                if (uncompressed > 500L * 1024 * 1024)
                    return new JarAnalysisResult
                    {
                        Opened = false,
                        FailureReason = "The archive expands beyond the 500 MB inspection limit and was not inspected.",
                        FilenameMatch = nameMatch,
                        MatchProduct = nameIndicator?.Product,
                        Evidence = evidence
                    };

                entryNames.Add(entry.FullName);
                if (entry.FullName.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase) &&
                    (entry.FullName.EndsWith(".SF", StringComparison.OrdinalIgnoreCase) ||
                     entry.FullName.EndsWith(".RSA", StringComparison.OrdinalIgnoreCase) ||
                     entry.FullName.EndsWith(".DSA", StringComparison.OrdinalIgnoreCase)))
                {
                    hasJavaSignature = true;
                }

                if (indicators.TryMatchMinecraftToken(entry.FullName, out var entryIndicator))
                {
                    entryNameMatch = true;
                    matchedProduct ??= entryIndicator;
                    evidence.Add($"An archive entry name contains “{entryIndicator.Product}”, a known Minecraft cheat-client name.");
                }

                var metadataName = MetadataEntries.FirstOrDefault(m =>
                    entry.FullName.Equals(m, StringComparison.OrdinalIgnoreCase));
                if (metadataName is null) continue;

                var text = ReadEntryText(entry, maxMetadataBytes, cancellationToken);
                if (text is null) continue;
                metadataFound = metadataFound || metadataName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                                 metadataName.EndsWith(".toml", StringComparison.OrdinalIgnoreCase) ||
                                 metadataName.Equals("META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase);
                foundMetadata[metadataName] = text;

                if (indicators.TryMatchMinecraftToken(text, out var metadataIndicator))
                {
                    metadataMatch = true;
                    matchedProduct ??= metadataIndicator;
                    evidence.Add($"Archive metadata contains “{metadataIndicator.Product}”, a known Minecraft cheat-client name.");
                }
            }

            var modName = ExtractMetadataValue(foundMetadata, "name") ?? ExtractMetadataValue(foundMetadata, "displayName");
            var modId = ExtractMetadataValue(foundMetadata, "id") ?? ExtractMetadataValue(foundMetadata, "modId");
            var loader = ResolveLoader(foundMetadata);
            var mainClass = ExtractManifestValue(foundMetadata, "Main-Class");
            var hasModMetadata = foundMetadata.Keys.Any(k =>
                k.Equals("fabric.mod.json", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("quilt.mod.json", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("META-INF/mods.toml", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("META-INF/neoforge.mods.toml", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("mcmod.info", StringComparison.OrdinalIgnoreCase));

            if (hasModMetadata)
                evidence.Add($"The archive contains {(loader ?? "Minecraft mod")} metadata" +
                             (string.IsNullOrWhiteSpace(modName) ? "." : $" identifying it as “{modName}”."));
            else if (metadataFound)
                evidence.Add("The archive contains a manifest but no recognizable Minecraft mod metadata.");

            if (hasJavaSignature)
                evidence.Add("The archive contains Java signature entries (.SF/.RSA/.DSA). WTX PC CHECK does not cryptographically verify Java signatures.");

            return new JarAnalysisResult
            {
                Opened = true,
                EntryCount = archive.Entries.Count,
                UncompressedBytes = uncompressed,
                ModName = modName,
                ModId = modId,
                ModLoader = loader,
                MainClass = mainClass,
                HasJavaSignatureEntries = hasJavaSignature,
                HasModMetadata = hasModMetadata,
                FilenameMatch = nameMatch,
                MetadataMatch = metadataMatch,
                EntryNameMatch = entryNameMatch,
                MatchProduct = matchedProduct?.Product,
                Evidence = evidence.Distinct().ToList()
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (InvalidDataException)
        {
            return new JarAnalysisResult
            {
                Opened = false,
                FailureReason = "The file is not a readable ZIP/JAR archive.",
                FilenameMatch = nameMatch,
                MatchProduct = nameIndicator?.Product,
                Evidence = evidence
            };
        }
        catch
        {
            return new JarAnalysisResult
            {
                Opened = false,
                FailureReason = "The archive could not be opened or was locked.",
                FilenameMatch = nameMatch,
                MatchProduct = nameIndicator?.Product,
                Evidence = evidence
            };
        }
    }

    private static string? ReadEntryText(ZipArchiveEntry entry, long maxBytes, CancellationToken cancellationToken)
    {
        try
        {
            using var input = entry.Open();
            using var memory = new MemoryStream();
            var buffer = new byte[8192];
            long total = 0;
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                total += read;
                if (total > maxBytes) break;
                memory.Write(buffer, 0, read);
            }
            var bytes = memory.ToArray();
            if (bytes.AsSpan().Contains((byte)0)) return null;
            return Encoding.UTF8.GetString(bytes).TrimStart('\uFEFF');
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractManifestValue(Dictionary<string, string> metadata, string key)
    {
        if (!metadata.TryGetValue("META-INF/MANIFEST.MF", out var text)) return null;
        foreach (var line in text.Split('\n'))
        {
            var index = line.IndexOf(':');
            if (index <= 0) continue;
            if (line[..index].Trim().Equals(key, StringComparison.OrdinalIgnoreCase))
                return line[(index + 1)..].Trim();
        }
        return null;
    }

    private static string? ExtractMetadataValue(Dictionary<string, string> metadata, string property)
    {
        foreach (var text in metadata.Values)
        {
            try
            {
                using var document = JsonDocument.Parse(text);
                var value = FindJsonString(document.RootElement, property);
                if (!string.IsNullOrWhiteSpace(value)) return value;
            }
            catch { }

            var match = Regex.Match(text, $@"(?im)^\s*{Regex.Escape(property)}\s*=\s*[""']?([^""'\r\n]+)");
            if (match.Success) return match.Groups[1].Value.Trim();
        }
        return null;
    }

    private static string? FindJsonString(JsonElement element, string property)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var child in element.EnumerateObject())
            {
                if (child.Name.Equals(property, StringComparison.OrdinalIgnoreCase) &&
                    child.Value.ValueKind == JsonValueKind.String)
                    return child.Value.GetString();
                var nested = FindJsonString(child.Value, property);
                if (!string.IsNullOrWhiteSpace(nested)) return nested;
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in element.EnumerateArray())
            {
                var nested = FindJsonString(child, property);
                if (!string.IsNullOrWhiteSpace(nested)) return nested;
            }
        }
        return null;
    }

    private static string? ResolveLoader(Dictionary<string, string> metadata)
    {
        if (metadata.ContainsKey("fabric.mod.json")) return "Fabric";
        if (metadata.ContainsKey("quilt.mod.json")) return "Quilt";
        if (metadata.ContainsKey("META-INF/neoforge.mods.toml")) return "NeoForge";
        if (metadata.ContainsKey("META-INF/mods.toml")) return "Forge";
        if (metadata.ContainsKey("mcmod.info")) return "Forge (legacy)";
        return null;
    }
}
