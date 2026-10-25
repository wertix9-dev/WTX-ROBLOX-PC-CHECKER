using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using WtxPcCheck.Models;
using WtxPcCheck.Services;

namespace WtxPcCheck;

public static class SelfTest
{
    private static readonly List<string> Lines = [];
    private static int _failures;

    public static int Run(string outputPath)
    {
        Check("Version comparison", () =>
        {
            Assert(VersionUtil.TryParse("1.2.3") == new Version(1, 2, 3, 0), "1.2.3 parse");
            Assert(VersionUtil.TryParse("v2.0.0-beta") == new Version(2, 0, 0, 0), "prerelease parse");
            Assert(VersionUtil.IsNewer("1.2.4", "1.2.3"), "newer comparison");
            Assert(!VersionUtil.IsNewer("1.2.3", "1.2.3"), "equal comparison");
            Assert(VersionUtil.TryParse("not-a-version") is null, "invalid version");
        });

        Check("Update configuration placeholders", () =>
        {
            var placeholder = new UpdateConfiguration();
            Assert(!placeholder.IsConfigured, "default configuration must be disabled");
            placeholder.Validate(out var reason);
            Assert(reason.Length > 10, "placeholder reason exists");

            var configured = new UpdateConfiguration
            {
                ManifestUrl = "https://updates.wertix.test/manifest.json",
                SignerThumbprint = new string('A', 64),
                PublisherName = "WERTIX"
            };
            Assert(configured.IsConfigured, "test configuration validates");

            var insecure = new UpdateConfiguration
            {
                ManifestUrl = "http://updates.wertix.test/manifest.json",
                SignerThumbprint = new string('A', 64),
                PublisherName = "WERTIX"
            };
            Assert(!insecure.IsConfigured, "HTTP update URL is rejected");
        });

        Check("SHA-256 hashing", () =>
        {
            var file = Path.Combine(Path.GetTempPath(), "wtx-selftest-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(file, "hello");
                var result = HashService.TryComputeSha256(file, 5, CancellationToken.None);
                Assert(result.Success, "hash success");
                Assert(result.Sha256 == "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824",
                    "known SHA-256 value");
            }
            finally
            {
                try { File.Delete(file); } catch { }
            }
        });

        Check("Authenticode verification of a signed Windows file", () =>
        {
            var path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
            Assert(File.Exists(path), "kernel32.dll exists");
            var signature = SignatureService.Verify(path);
            Assert(signature.Status == SignatureStatus.Valid, "kernel32.dll signature valid, got " + signature.StatusText);
        });

        Check("Local indicator database", () =>
        {
            var db = IndicatorDatabase.LoadEmbedded();
            Assert(db.LoadWarning is null, "indicator database loads");
            Assert(db.HasKnownHashes == false, "no invented hashes are bundled");
            Assert(db.TryMatchExecutableName("SynapseX.exe", out var name) && name.Product.Length > 0, "executor name match");
            Assert(!db.TryMatchExecutableName("notes.txt", out _), "benign name does not match");
            Assert(db.TryMatchFolder(@"C:\Users\Example\Krnl", out _), "executor folder match");
            Assert(db.IsRobloxProxyDll("version.dll"), "proxy DLL list");
            Assert(db.MatchLuaTokens("getgenv(); hookfunction(print, function() end)").Count >= 2, "Lua API matching");
        });

        Check("Scan engine on a harmless fixture", () =>
        {
            var root = Path.Combine(Path.GetTempPath(), "wtx-selftest-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(Path.Combine(root, "SynapseTest"));
                Directory.CreateDirectory(Path.Combine(root, "Docs"));
                File.WriteAllText(Path.Combine(root, "SynapseTest", "SynapseX.exe"), "harmless test placeholder, not executable");
                File.WriteAllText(Path.Combine(root, "SynapseTest", "loader.lua"), "getgenv(); hookfunction(print, function() end)");
                var hiddenLua = Path.Combine(root, "Docs", "safe.lua");
                File.WriteAllText(hiddenLua, "print('hello')");
                File.SetAttributes(hiddenLua, FileAttributes.Hidden | FileAttributes.System);
                File.WriteAllText(Path.Combine(root, "Docs", "benign.txt"), "hello");

                var engine = new ScanEngine(IndicatorDatabase.LoadEmbedded());
                var outcome = engine.Scan(
                    new ScanRequest { Roots = [root], AnalyzeLuaContents = true },
                    null, null, CancellationToken.None);

                Assert(outcome.FilesChecked == 4, "all fixture files counted, got " + outcome.FilesChecked);
                Assert(outcome.Findings.Count >= 2, "fixture indicators found, got " + outcome.Findings.Count);
                Assert(outcome.Findings.All(f => !f.FileName.Equals("benign.txt", StringComparison.OrdinalIgnoreCase)),
                    "benign text file is not flagged");
                Assert(outcome.Findings.Any(f => f.FileName.EndsWith(".lua", StringComparison.OrdinalIgnoreCase)),
                    "Lua script review finding exists");
                Assert(outcome.Findings.All(f => !string.IsNullOrWhiteSpace(f.Explanation)), "findings carry explanations");
                Assert(outcome.Findings.All(f => !string.IsNullOrWhiteSpace(f.Limitations)), "findings carry limitations");
                Assert(outcome.InaccessibleTotal == 0, "fixture has no inaccessible items");
            }
            finally
            {
                try { Directory.Delete(root, true); } catch { }
            }
        });

        Check("Missing scan root is reported", () =>
        {
            var missing = Path.Combine(Path.GetTempPath(), "wtx-selftest-missing-" + Guid.NewGuid().ToString("N"));
            var engine = new ScanEngine(IndicatorDatabase.LoadEmbedded());
            var outcome = engine.Scan(new ScanRequest { Roots = [missing] }, null, null, CancellationToken.None);
            Assert(outcome.InaccessibleTotal == 1, "missing root increments inaccessible count");
            Assert(outcome.InaccessibleAreas.Count == 1, "missing root detail exists");
            Assert(!string.IsNullOrWhiteSpace(outcome.InaccessibleAreas[0].Reason), "missing root has an English reason");
        });

        Check("Scan cancellation", () =>
        {
            var root = Path.Combine(Path.GetTempPath(), "wtx-selftest-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(root);
                File.WriteAllText(Path.Combine(root, "a.txt"), "a");
                var engine = new ScanEngine(IndicatorDatabase.LoadEmbedded());
                using var cts = new CancellationTokenSource();
                cts.Cancel();
                var outcome = engine.Scan(new ScanRequest { Roots = [root] }, null, null, cts.Token);
                Assert(outcome.Cancelled, "cancelled outcome is reported");
            }
            finally
            {
                try { Directory.Delete(root, true); } catch { }
            }
        });

        Check("Safe Lua preview", () =>
        {
            var file = Path.Combine(Path.GetTempPath(), "wtx-selftest-" + Guid.NewGuid().ToString("N") + ".lua");
            try
            {
                File.WriteAllText(file, "print('preview')", new UTF8Encoding(true));
                var preview = ScriptPreviewService.TryRead(file);
                Assert(preview.Success, "preview reads text");
                Assert(preview.Text.Contains("preview", StringComparison.Ordinal), "preview contains script text");
                Assert(!preview.Text.StartsWith('\uFEFF'), "preview strips BOM");
            }
            finally
            {
                try { File.Delete(file); } catch { }
            }
        });

        Check("No network use while update source is a placeholder", () =>
        {
            using var service = new UpdateService(new UpdateConfiguration());
            var result = service.CheckOnlyAsync(CancellationToken.None).GetAwaiter().GetResult();
            Assert(result.NotConfigured, "placeholder update check is rejected before any request");
        });

        Check("Updater rejects an unverified staged file", () =>
        {
            var directory = Path.Combine(AppPaths.UpdateWorkDirectory, Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(directory);
                var staged = Path.Combine(directory, "WTX-PC-CHECK-test.exe");
                File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), staged, true);
                var hash = HashService.TryComputeSha256(staged, new FileInfo(staged).Length, CancellationToken.None);
                Assert(hash.Success, "staged hash");
                var apply = new UpdateApplyService();
                var result = apply.StartApplyAsync(staged, hash.Sha256!, "9.9.9", CancellationToken.None)
                    .GetAwaiter().GetResult();
                Assert(!result.Started, "unverified staged update is rejected");
                Assert(result.ErrorEnglish.Length > 5, "rejection has an English reason");
            }
            finally
            {
                try { Directory.Delete(directory, true); } catch { }
            }
        });

        Check("Update helper script parses", () =>
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), "wtx-selftest-" + Guid.NewGuid().ToString("N") + ".ps1");
            var parserPath = Path.Combine(Path.GetTempPath(), "wtx-selftest-parse-" + Guid.NewGuid().ToString("N") + ".ps1");
            try
            {
                File.WriteAllText(scriptPath, UpdateApplyService.BuildApplyScript());
                File.WriteAllText(parserPath, """
                    param([string]$Path)
                    $errors = $null
                    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
                    if ($errors -and $errors.Count -gt 0) { Write-Output ('ERROR: ' + $errors[0].Message); exit 1 }
                    Write-Output 'OK'
                    exit 0
                    """);
                var result = ProcessRunner.RunAsync(
                    ProcessRunner.PowerShellPath,
                    ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", parserPath, "-Path", scriptPath],
                    TimeSpan.FromSeconds(30), CancellationToken.None).GetAwaiter().GetResult();
                Assert(result.Started && result.ExitCode == 0 && result.StandardOutput.Contains("OK"),
                    "PowerShell parser accepts apply script: " + result.StandardOutput + result.StandardError);
            }
            finally
            {
                try { File.Delete(scriptPath); } catch { }
                try { File.Delete(parserPath); } catch { }
            }
        });

        Lines.Add(string.Empty);
        Lines.Add(_failures == 0 ? "SELFTEST RESULT: PASS" : $"SELFTEST RESULT: FAIL ({_failures})");
        try
        {
            var directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            File.WriteAllLines(outputPath, Lines);
        }
        catch
        {
            return 2;
        }
        return _failures == 0 ? 0 : 1;
    }

    private static void Check(string name, Action action)
    {
        try
        {
            action();
            Lines.Add("PASS  " + name);
        }
        catch (Exception ex)
        {
            _failures++;
            Lines.Add("FAIL  " + name + " — " + ex.GetType().Name + ": " + ex.Message);
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}

