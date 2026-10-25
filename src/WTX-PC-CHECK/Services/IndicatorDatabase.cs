using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public sealed class TokenIndicator
{
    public string Token { get; init; } = string.Empty;
    public string Product { get; init; } = string.Empty;
}

public sealed class HashIndicator
{
    public string Sha256 { get; init; } = string.Empty;
    public string Label { get; init; } = "Known indicator";
    public string Description { get; init; } = "The SHA-256 hash matches an entry in the local indicator database.";
    public RiskLevel Risk { get; init; } = RiskLevel.High;
}

public sealed class IndicatorFile
{
    public int SchemaVersion { get; init; }
    public string Notes { get; init; } = string.Empty;
    public List<HashIndicator> KnownHashes { get; init; } = [];
    public List<TokenIndicator> ExecutorNameTokens { get; init; } = [];
    public List<TokenIndicator> ExecutorFolderTokens { get; init; } = [];
    public List<string> RobloxProxyDllNames { get; init; } = [];
    public List<string> LuaExecutorApiTokens { get; init; } = [];
}

public sealed class IndicatorDatabase
{
    private readonly Dictionary<string, HashIndicator> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _proxyDlls = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _luaTokens = [];

    private IndicatorDatabase() { }

    public string Notes { get; private set; } = string.Empty;
    public List<TokenIndicator> ExecutorNameTokens { get; private set; } = [];
    public List<TokenIndicator> ExecutorFolderTokens { get; private set; } = [];
    public bool HasKnownHashes => _hashes.Count > 0;
    public int KnownHashCount => _hashes.Count;
    public string? LoadWarning { get; private set; }

    public static IndicatorDatabase LoadEmbedded()
    {
        var db = new IndicatorDatabase();
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            var name = assembly.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("KnownIndicators.json", StringComparison.OrdinalIgnoreCase));
            if (name is null)
            {
                db.LoadWarning = "The local indicator list could not be loaded. Name and script heuristics are unavailable.";
                return db;
            }

            using var stream = assembly.GetManifestResourceStream(name)!;
            var data = JsonSerializer.Deserialize<IndicatorFile>(stream, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                Converters = { new JsonStringEnumConverter() }
            });

            if (data is null)
            {
                db.LoadWarning = "The local indicator list could not be read. Name and script heuristics are unavailable.";
                return db;
            }

            db.Notes = data.Notes;
            db.ExecutorNameTokens = data.ExecutorNameTokens.Where(t => !string.IsNullOrWhiteSpace(t.Token)).ToList();
            db.ExecutorFolderTokens = data.ExecutorFolderTokens.Where(t => !string.IsNullOrWhiteSpace(t.Token)).ToList();
            db._luaTokens.AddRange(data.LuaExecutorApiTokens.Where(t => !string.IsNullOrWhiteSpace(t)));
            foreach (var proxy in data.RobloxProxyDllNames) db._proxyDlls.Add(proxy);
            foreach (var hash in data.KnownHashes)
            {
                if (hash.Sha256.Length == 64 && hash.Sha256.All(Uri.IsHexDigit))
                    db._hashes[hash.Sha256] = hash;
            }
        }
        catch
        {
            db.LoadWarning = "The local indicator list could not be read. Name and script heuristics are unavailable.";
        }
        return db;
    }

    public bool TryMatchExecutableName(string fileName, out TokenIndicator indicator)
        => TryMatchToken(fileName, ExecutorNameTokens, out indicator);

    public bool TryMatchFolder(string directoryPath, out TokenIndicator indicator)
    {
        indicator = default!;
        if (string.IsNullOrWhiteSpace(directoryPath)) return false;
        var segments = directoryPath.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in segments)
        {
            if (TryMatchToken(segment, ExecutorFolderTokens, out indicator))
                return true;
        }
        return false;
    }

    public bool TryMatchHash(string? sha256, out HashIndicator indicator)
    {
        indicator = default!;
        return sha256 is not null && _hashes.TryGetValue(sha256, out indicator!);
    }

    public IReadOnlyList<string> MatchLuaTokens(string text)
    {
        var matches = new List<string>();
        foreach (var token in _luaTokens)
        {
            if (text.Contains(token, StringComparison.OrdinalIgnoreCase))
                matches.Add(token);
        }
        return matches;
    }

    public bool IsRobloxProxyDll(string fileName) => _proxyDlls.Contains(fileName);

    private static bool TryMatchToken(string value, List<TokenIndicator> tokens, out TokenIndicator indicator)
    {
        var normalized = FileRules.NormalizeName(value);
        foreach (var token in tokens)
        {
            var normalizedToken = FileRules.NormalizeName(token.Token);
            if (normalizedToken.Length > 0 && normalized.Contains(normalizedToken, StringComparison.Ordinal))
            {
                indicator = token;
                return true;
            }
        }
        indicator = default!;
        return false;
    }
}
