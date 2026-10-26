using System.IO.Compression;
using WtxPcCheck.Models;
using WtxPcCheck.Services;

namespace WtxPcCheck.Linux;

public static class LinuxSelfTest
{
    public static int Run(string outputPath)
    {
        var lines = new List<string>();
        var failures = 0;
        void Check(string name, Action test)
        {
            try { test(); lines.Add("PASS  " + name); }
            catch (Exception ex) { failures++; lines.Add("FAIL  " + name + " - " + ex.GetType().Name + ": " + ex.Message); }
        }
        void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }

        Check("Shared scan engine on Linux build", () =>
        {
            var root = Path.Combine(Path.GetTempPath(), "wtx-linux-selftest-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(Path.Combine(root, "mods"));
                File.WriteAllText(Path.Combine(root, "loader.lua"), "getgenv(); hookfunction(print, function() end)");
                using (var zip = ZipFile.Open(Path.Combine(root, "mods", "Wurst.jar"), ZipArchiveMode.Create))
                {
                    var entry = zip.CreateEntry("fabric.mod.json");
                    using var writer = new StreamWriter(entry.Open());
                    writer.Write("{\"schemaVersion\":1,\"id\":\"wurst\",\"name\":\"Wurst Client\"}");
                }
                var engine = new ScanEngine(IndicatorDatabase.LoadEmbedded());
                var outcome = engine.Scan(new ScanRequest
                {
                    Roots = [root],
                    ScanRobloxExecutables = false,
                    ScanLuaScripts = true,
                    ScanMinecraftJars = true,
                    DetectMinecraftCheatIndicators = true,
                    ReviewMinecraftJars = true
                }, null, null, CancellationToken.None);
                Assert(outcome.FilesChecked == 2, "file count is real");
                Assert(outcome.Findings.Any(f => f.Category == FindingCategory.ScriptReview), "Lua review finding exists");
                Assert(outcome.Findings.Any(f => f.Classification == FindingClassification.KnownCheatClient), "Minecraft known indicator exists");
            }
            finally
            {
                try { Directory.Delete(root, true); } catch { }
            }
        });

        Check("Linux signature policy is honest", () =>
        {
            var info = SignatureService.Verify(Path.Combine(Path.GetTempPath(), "does-not-exist.exe"));
            Assert(info.Status == SignatureStatus.Error, "missing file is not reported as signed");
        });

        lines.Add(failures == 0 ? "LINUX SELFTEST RESULT: PASS" : $"LINUX SELFTEST RESULT: FAIL ({failures})");
        try { File.WriteAllLines(outputPath, lines); } catch { return 2; }
        return failures == 0 ? 0 : 1;
    }
}
