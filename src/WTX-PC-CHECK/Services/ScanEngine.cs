using System.Diagnostics;
using System.IO;
using System.Text;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public sealed class ScanEngine
{
    private const int MaxInaccessibleDetails = 1500;
    private const int LuaReadLimit = 256 * 1024;
    private static readonly EnumerationOptions EnumOptions = new()
    {
        IgnoreInaccessible = false,
        AttributesToSkip = 0,
        RecurseSubdirectories = false,
        ReturnSpecialDirectories = false
    };

    private readonly IndicatorDatabase _indicators;

    public ScanEngine(IndicatorDatabase indicators)
    {
        _indicators = indicators;
    }

    public ScanOutcome Scan(
        ScanRequest request,
        IProgress<ScanProgress>? progress,
        IProgress<ScanFinding>? findingProgress,
        CancellationToken cancellationToken)
    {
        var outcome = new ScanOutcome
        {
            Roots = request.Roots.ToList(),
            StartedUtc = DateTimeOffset.UtcNow
        };

        var stopwatch = Stopwatch.StartNew();
        var lastProgress = -1000L;
        var stack = new Stack<string>();
        foreach (var root in request.Roots)
        {
            if (Directory.Exists(root)) stack.Push(root);
            else AddInaccessible(outcome, root, "The selected drive or folder is not available.", true);
        }

        void Report(string currentPath, bool force = false)
        {
            if (!force && stopwatch.ElapsedMilliseconds - lastProgress < 250) return;
            lastProgress = stopwatch.ElapsedMilliseconds;
            progress?.Report(new ScanProgress
            {
                FilesChecked = outcome.FilesChecked,
                DirectoriesChecked = outcome.DirectoriesChecked,
                CurrentPath = currentPath,
                FindingCount = outcome.Findings.Count,
                InaccessibleCount = outcome.InaccessibleTotal,
                Elapsed = stopwatch.Elapsed,
                LuaFilesChecked = outcome.LuaFilesChecked,
                ReparsePointsSkipped = outcome.ReparsePointsSkipped,
                CloudFilesSkipped = outcome.CloudFilesSkipped
            });
        }

        try
        {
            while (stack.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var directoryPath = stack.Pop();
                outcome.DirectoriesChecked++;
                Report(directoryPath);

                try
                {
                    var directory = new DirectoryInfo(directoryPath);
                    foreach (var entry in directory.EnumerateFileSystemInfos("*", EnumOptions))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        FileAttributes attributes;
                        try
                        {
                            attributes = entry.Attributes;
                        }
                        catch
                        {
                            AddInaccessible(outcome, entry.FullName, "File or folder information could not be read.", entry is DirectoryInfo);
                            continue;
                        }

                        if (entry is DirectoryInfo childDirectory)
                        {
                            if (attributes.HasFlag(FileAttributes.ReparsePoint))
                            {
                                outcome.ReparsePointsSkipped++;
                                continue;
                            }
                            stack.Push(childDirectory.FullName);
                            continue;
                        }

                        if (entry is not FileInfo file) continue;
                        outcome.FilesChecked++;
                        try
                        {
                            AnalyzeFile(file, attributes, directoryPath, request, outcome, findingProgress, cancellationToken);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch
                        {
                            AddInaccessible(outcome, file.FullName, "This file could not be inspected because it was locked or unreadable.", false);
                        }

                        if (outcome.FilesChecked % 32 == 0) Report(file.FullName);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException or PathTooLongException or NotSupportedException)
                {
                    AddInaccessible(
                        outcome,
                        directoryPath,
                        "Some or all entries in this folder could not be read because of permissions, locks, or a path limitation.",
                        true);
                }
            }

            outcome.CompletedUtc = DateTimeOffset.UtcNow;
            Report(string.Empty, true);
            return outcome;
        }
        catch (OperationCanceledException)
        {
            outcome.Cancelled = true;
            outcome.CompletedUtc = DateTimeOffset.UtcNow;
            Report(string.Empty, true);
            return outcome;
        }
    }

    private void AnalyzeFile(
        FileInfo file,
        FileAttributes attributes,
        string directoryPath,
        ScanRequest request,
        ScanOutcome outcome,
        IProgress<ScanFinding>? findingProgress,
        CancellationToken cancellationToken)
    {
        var path = file.FullName;
        var isPe = FileRules.IsPeFile(path);
        var isLua = FileRules.IsLuaFile(path);
        if (!isPe && !isLua) return;

        if (isPe) outcome.PeFilesChecked++;
        if (isLua) outcome.LuaFilesChecked++;

        var cloudOnly = FileRules.IsCloudOnly(attributes);
        var reparseFile = attributes.HasFlag(FileAttributes.ReparsePoint);
        if (cloudOnly) outcome.CloudFilesSkipped++;

        var evidence = new List<string>();
        var limitations = new List<string>();
        var risk = RiskLevel.Low;
        var category = isLua ? FindingCategory.ScriptReview : FindingCategory.ExecutorIndicator;
        string? matchedRule = null;

        var nameMatch = _indicators.TryMatchExecutableName(file.Name, out var nameIndicator);
        var folderMatch = _indicators.TryMatchFolder(directoryPath, out var folderIndicator);

        if (isPe && nameMatch)
        {
            evidence.Add($"The file name contains “{nameIndicator.Product}”, a name associated with a Roblox executor product.");
            risk = RiskLevel.Medium;
            matchedRule = $"Name: {nameIndicator.Product}";
        }

        if (isPe && folderMatch)
        {
            evidence.Add($"The file is inside a folder whose name contains “{folderIndicator.Product}”, which is associated with executor software.");
            if (!nameMatch) risk = RiskLevel.Low;
            else risk = RiskLevel.Medium;
            matchedRule ??= $"Folder: {folderIndicator.Product}";
        }

        if (isLua && (nameMatch || folderMatch))
        {
            var context = nameMatch ? nameIndicator.Product : folderIndicator.Product;
            evidence.Add($"The script name or folder is associated with “{context}”, which may relate to executor use.");
            matchedRule = $"Script context: {context}";
            risk = RiskLevel.Low;
        }

        var luaTokens = new List<string>();
        if (isLua && request.AnalyzeLuaContents && !cloudOnly && !reparseFile)
        {
            var text = TryReadLuaText(path, cancellationToken);
            if (text is not null)
            {
                luaTokens.AddRange(_indicators.MatchLuaTokens(text));
                if (luaTokens.Count > 0)
                {
                    evidence.Add($"The script text references {luaTokens.Count} executor-specific API name{(luaTokens.Count == 1 ? "" : "s")}: {string.Join(", ", luaTokens.Take(6))}.");
                    risk = luaTokens.Count >= 2 ? RiskLevel.Medium : RiskLevel.Low;
                    matchedRule = "Lua API names";
                    category = FindingCategory.ScriptReview;
                    limitations.Add("Static keyword matching can flag development or testing scripts. Obfuscated scripts may hide these names.");
                }
            }
            else
            {
                limitations.Add("The script text could not be read, so only its name and location were reviewed.");
            }
        }
        else if (isLua && cloudOnly)
        {
            limitations.Add("This is a cloud-only placeholder file. Its contents were not downloaded or analyzed.");
        }

        var proxyHit = false;
        if (isPe && FileRules.IsInRobloxVersionsFolder(path) && _indicators.IsRobloxProxyDll(file.Name))
        {
            proxyHit = true;
        }

        SignatureInfo? signature = null;
        var needsSignature = isPe && (nameMatch || folderMatch || proxyHit);
        if (needsSignature)
        {
            signature = SignatureService.Verify(path);
            outcome.SignatureChecksPerformed++;
        }

        if (proxyHit)
        {
            if (signature?.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid or SignatureStatus.Error)
            {
                evidence.Add("The DLL uses a name commonly used for DLL proxying and is located in a Roblox version folder. Its digital signature is not valid.");
                risk = RiskLevel.Medium;
                matchedRule ??= "Roblox proxy DLL name";
                limitations.Add("Some legitimate audio or accessibility tools also use proxy DLL names. The file was not loaded or executed.");
            }
            else
            {
                // A validly signed file with a proxy-like name is weak evidence; do not create a finding for it alone.
                proxyHit = false;
            }
        }

        var hash = (string?)null;
        string? hashNote = null;
        var shouldHash = _indicators.HasKnownHashes ? isPe || isLua : evidence.Count > 0;
        if (shouldHash && !reparseFile && !cloudOnly && file.Length <= HashService.MaxHashBytes)
        {
            var result = HashService.TryComputeSha256(path, file.Length, cancellationToken);
            outcome.HashChecksPerformed++;
            if (result.Success)
            {
                hash = result.Sha256;
                if (_indicators.TryMatchHash(hash, out var hashIndicator))
                {
                    evidence.Add($"The SHA-256 hash matches the local indicator “{hashIndicator.Label}”.");
                    risk = hashIndicator.Risk;
                    category = FindingCategory.MalwareIndicator;
                    matchedRule = $"SHA-256: {hashIndicator.Label}";
                    limitations.Add("A hash match means the file content matches an entry in the configured local indicator list. The list in this build may be empty or incomplete.");
                }
            }
            else
            {
                hashNote = result.Note;
            }
        }
        else if (shouldHash && (reparseFile || cloudOnly))
        {
            hashNote = "Hash not computed because this is a cloud placeholder or reparse point.";
        }
        else if (shouldHash)
        {
            hashNote = "Hash not computed because the file is larger than 256 MB.";
        }

        if (evidence.Count == 0) return;
        if (outcome.Findings.Count >= request.MaxFindings)
        {
            outcome.FindingLimitReached = true;
            return;
        }

        if (cloudOnly) limitations.Add("The file is a cloud-only placeholder; its content was not downloaded.");
        if (reparseFile) limitations.Add("The file is a reparse point (link). Linked content outside the selected scan scope was not read.");
        limitations.Add("Name, folder, and script-text matches are indicators, not proof. WTX PC CHECK did not execute or modify the file.");

        var typeLabel = FileRules.FileTypeLabel(path);
        var explanation = BuildExplanation(isPe, isLua, category, proxyHit);
        var detection = isLua
            ? "Local static inspection of file metadata" +
              (luaTokens.Count > 0 ? ", a limited text search of the script, and " : " and ") +
              "local indicator lists. The script was not executed."
            : "Local static inspection of file name, folder path, metadata, and digital signature" +
              (_indicators.HasKnownHashes ? ", plus SHA-256 hash comparison against the local indicator list." : ". No known-hash list is configured in this build.");

        var finding = new ScanFinding
        {
            FileName = file.Name,
            FullPath = path,
            FileType = typeLabel,
            Explanation = explanation,
            DetectionMethod = detection,
            Limitations = string.Join(" ", limitations.Distinct()),
            Category = category,
            Risk = risk,
            SizeBytes = file.Length,
            ModifiedUtc = file.LastWriteTimeUtc,
            Signature = signature ?? SignatureInfo.NotChecked(isLua
                ? "Digital signatures are not applicable to Lua script text."
                : "Signature verification is performed on flagged executable and library files."),
            Sha256 = hash,
            HashNote = hashNote,
            MatchedRule = matchedRule,
            IsScriptFile = isLua,
            IsCloudOnly = cloudOnly
        };

        outcome.Findings.Add(finding);
        findingProgress?.Report(finding);
    }

    private static string BuildExplanation(bool isPe, bool isLua, FindingCategory category, bool proxyHit)
    {
        if (category == FindingCategory.MalwareIndicator)
            return "This file matches a local malware indicator. Treat it as potentially dangerous and review it with Windows Security. A hash match is strong evidence but is limited by the completeness of the local indicator list.";

        if (isLua)
            return "This Lua script has characteristics that are often seen in executor-oriented scripts. It is not automatically malware, and legitimate Roblox development or testing files can look similar. Review the script text only if you understand it.";

        if (proxyHit)
            return "This DLL matches a proxy-DLL naming pattern inside a Roblox version folder and does not have a valid signature. This pattern can be used to load unsigned code into another process. It can also appear in legitimate software, so review the file before acting.";

        if (isPe)
            return "This program or library matches an executor-related name or location indicator. A name alone is not proof of malicious behavior, but the file deserves review because of its name, location, and signature status.";

        return "This item matched a local review indicator.";
    }

    private static string? TryReadLuaText(string path, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var length = (int)Math.Min(stream.Length, LuaReadLimit);
            if (length == 0) return string.Empty;
            var buffer = new byte[length];
            var read = stream.Read(buffer, 0, length);
            cancellationToken.ThrowIfCancellationRequested();
            if (buffer.AsSpan(0, read).Contains((byte)0)) return null;
            return Encoding.UTF8.GetString(buffer, 0, read);
        }
        catch
        {
            return null;
        }
    }

    private static void AddInaccessible(ScanOutcome outcome, string path, string reason, bool isDirectory)
    {
        outcome.InaccessibleTotal++;
        if (outcome.InaccessibleAreas.Count >= MaxInaccessibleDetails) return;
        outcome.InaccessibleAreas.Add(new InaccessibleArea
        {
            Path = path,
            Reason = reason,
            IsDirectory = isDirectory
        });
    }
}
