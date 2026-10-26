using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using WtxPcCheck.Models;
using WtxPcCheck.Services;
using WtxPcCheck.Linux.Models;

namespace WtxPcCheck.Linux.Services;

public sealed partial class LinuxSecurityService
{
    private readonly IndicatorDatabase _indicators;

    public LinuxSecurityService(IndicatorDatabase indicators)
    {
        _indicators = indicators;
    }

    public async Task<LinuxSecurityOverview> GetOverviewAsync(CancellationToken cancellationToken)
    {
        var os = ReadOsRelease();
        var overview = new LinuxSecurityOverview
        {
            Distribution = os.DisplayName,
            DistributionId = os.Id,
            SupportNote = os.SupportNote
        };

        var firewallTask = GetFirewallAsync(cancellationToken);
        var updatesTask = GetUpdatesAsync(os.Id, cancellationToken);
        var startupTask = Task.Run(GetStartupEntries, cancellationToken);
        var processTask = Task.Run(GetProcesses, cancellationToken);
        var clamTask = GetClamAvStatusAsync(cancellationToken);

        await Task.WhenAll(firewallTask, updatesTask, startupTask, processTask, clamTask).ConfigureAwait(false);

        overview.Firewall = firewallTask.Result;
        overview.Updates = updatesTask.Result;
        var startup = startupTask.Result;
        overview.StartupEntries = startup.Items;
        overview.StartupEntryCount = startup.Total;
        var processes = processTask.Result;
        overview.Processes = processes.Items;
        overview.ProcessCount = processes.Total;
        overview.ProcessListTruncated = processes.Truncated;
        overview.ProcessNote = processes.Note;
        overview.ClamAv = clamTask.Result;
        overview.CheckedUtc = DateTimeOffset.UtcNow;
        overview.State = LinuxSecurityState.Available;
        return overview;
    }

    public async Task<ClamAvStatus> RefreshClamAvStatusAsync(CancellationToken cancellationToken)
        => await GetClamAvStatusAsync(cancellationToken).ConfigureAwait(false);

    public async Task<ClamAvScanResult> RunClamAvAsync(
        IReadOnlyList<string> roots,
        IProgress<TimeSpan>? progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var status = await GetClamAvStatusAsync(cancellationToken).ConfigureAwait(false);
        if (!status.Available || status.Executable is null)
        {
            return new ClamAvScanResult
            {
                State = ClamAvScanState.NotAvailable,
                Summary = "ClamAV is not installed or was not found in PATH. WTX PC CHECK does not install it and no malware scan was started.",
                StartedUtc = started,
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }
        if (roots.Count == 0)
        {
            return new ClamAvScanResult
            {
                State = ClamAvScanState.Failed,
                Summary = "No local location is selected, so ClamAV was not started.",
                StartedUtc = started,
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }

        var arguments = new List<string> { "-r", "--infected" };
        arguments.AddRange(roots);
        try
        {
            progress?.Report(TimeSpan.Zero);
            var result = await LinuxProcessRunner.RunAsync(
                status.Executable, arguments, null, cancellationToken).ConfigureAwait(false);
            var ended = DateTimeOffset.UtcNow;
            if (!result.Started)
            {
                return new ClamAvScanResult
                {
                    State = ClamAvScanState.Failed,
                    Summary = "ClamAV could not be started. Check that the executable and its virus database are readable by your user.",
                    StartedUtc = started,
                    CompletedUtc = ended
                };
            }

            var findings = ParseClamAvFindings(result.StandardOutput);
            var scannedFiles = ParseSummaryNumber(result.StandardOutput, "Scanned files");
            var infectedFiles = ParseSummaryNumber(result.StandardOutput, "Infected files")
                                ?? (findings.Count > 0 ? findings.Count : 0);

            if (result.ExitCode == 1 || findings.Count > 0)
            {
                return new ClamAvScanResult
                {
                    State = ClamAvScanState.ThreatsFound,
                    Summary = $"ClamAV reported {findings.Count} infected file{(findings.Count == 1 ? "" : "s")} in the selected locations. The paths and signatures are listed in the findings. WTX PC CHECK did not remove or quarantine anything.",
                    ExitCode = result.ExitCode,
                    ScannedFiles = scannedFiles,
                    InfectedFiles = infectedFiles,
                    Findings = findings,
                    StartedUtc = started,
                    CompletedUtc = ended
                };
            }

            if (result.ExitCode == 2)
            {
                return new ClamAvScanResult
                {
                    State = ClamAvScanState.Failed,
                    Summary = "ClamAV reported an error. Its virus database may be missing, outdated, or unreadable. No scan result is being claimed.",
                    ExitCode = result.ExitCode,
                    StartedUtc = started,
                    CompletedUtc = ended
                };
            }

            return new ClamAvScanResult
            {
                State = ClamAvScanState.NoThreats,
                Summary = $"ClamAV completed with no reported detections (exit code 0) after scanning {scannedFiles?.ToString("N0") ?? "an unknown number of"} files. This does not guarantee that the PC is clean.",
                ExitCode = result.ExitCode,
                ScannedFiles = scannedFiles,
                InfectedFiles = 0,
                StartedUtc = started,
                CompletedUtc = ended
            };
        }
        catch (OperationCanceledException)
        {
            return new ClamAvScanResult
            {
                State = ClamAvScanState.Cancelled,
                Summary = "The ClamAV scan was cancelled. Its result is incomplete.",
                StartedUtc = started,
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }
        catch
        {
            return new ClamAvScanResult
            {
                State = ClamAvScanState.Failed,
                Summary = "ClamAV could not be run. No malware scan result is available.",
                StartedUtc = started,
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }
    }

    private static List<ClamAvFinding> ParseClamAvFindings(string output)
    {
        var results = new List<ClamAvFinding>();
        foreach (var line in output.Split('\n'))
        {
            var match = ClamAvFindingRegex().Match(line.Trim());
            if (!match.Success) continue;
            var path = match.Groups[1].Value.Trim();
            var signature = match.Groups[2].Value.Trim();
            if (path.Length == 0 || signature.Length == 0) continue;
            if (results.Any(r => r.Path.Equals(path, StringComparison.Ordinal))) continue;
            results.Add(new ClamAvFinding { Path = path, Signature = signature });
        }
        return results;
    }

    private static int? ParseSummaryNumber(string output, string label)
    {
        var match = Regex.Match(output, $@"(?im)^\s*{Regex.Escape(label)}:\s*(\d+)");
        return match.Success && int.TryParse(match.Groups[1].Value, out var value) ? value : null;
    }

    private async Task<LinuxFirewallStatus> GetFirewallAsync(CancellationToken cancellationToken)
    {
        var ufw = LinuxProcessRunner.FindExecutable("ufw");
        if (ufw is not null)
        {
            var result = await LinuxProcessRunner.RunAsync(ufw, ["status"], TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
            if (result.Started && !result.TimedOut)
            {
                if (result.StandardOutput.Contains("Status: active", StringComparison.OrdinalIgnoreCase))
                    return new LinuxFirewallStatus { Available = true, Active = true, Summary = "Firewall active", Detail = "Reported by ufw. No firewall changes were made." };
                if (result.StandardOutput.Contains("Status: inactive", StringComparison.OrdinalIgnoreCase))
                    return new LinuxFirewallStatus { Available = true, Active = false, Summary = "Firewall inactive", Detail = "Reported by ufw. No firewall changes were made." };
                if (result.StandardError.Contains("permission", StringComparison.OrdinalIgnoreCase) || result.ExitCode != 0)
                    return new LinuxFirewallStatus { Available = false, Summary = "Firewall status restricted", Detail = "ufw is installed but did not expose its status to this user. WTX PC CHECK does not run firewall commands with elevated privileges." };
            }
        }

        var firewalld = LinuxProcessRunner.FindExecutable("firewall-cmd");
        if (firewalld is not null)
        {
            var result = await LinuxProcessRunner.RunAsync(firewalld, ["--state"], TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
            if (result.Started && !result.TimedOut)
            {
                var text = (result.StandardOutput + result.StandardError).Trim();
                if (text.Contains("running", StringComparison.OrdinalIgnoreCase))
                    return new LinuxFirewallStatus { Available = true, Active = true, Summary = "Firewall active", Detail = "Reported by firewalld. No firewall changes were made." };
                if (text.Contains("not running", StringComparison.OrdinalIgnoreCase))
                    return new LinuxFirewallStatus { Available = true, Active = false, Summary = "Firewall inactive", Detail = "Reported by firewalld. No firewall changes were made." };
            }
        }

        var systemctl = LinuxProcessRunner.FindExecutable("systemctl");
        if (systemctl is not null)
        {
            var result = await LinuxProcessRunner.RunAsync(systemctl, ["is-active", "firewalld"], TimeSpan.FromSeconds(4), cancellationToken).ConfigureAwait(false);
            var state = result.StandardOutput.Trim();
            if (result.Started && state is "active" or "inactive" or "failed" or "unknown")
                return new LinuxFirewallStatus
                {
                    Available = true,
                    Active = state == "active",
                    Summary = state == "active" ? "Firewall active" : "Firewall service not active",
                    Detail = "Read-only systemd service state. Other firewall tools may also be in use."
                };
        }

        return new LinuxFirewallStatus
        {
            Available = false,
            Summary = "Firewall status unavailable",
            Detail = "No supported read-only firewall status tool (ufw, firewalld) was accessible to this user. WTX PC CHECK did not request elevated privileges."
        };
    }

    private static async Task<LinuxUpdateStatus> GetUpdatesAsync(string distroId, CancellationToken cancellationToken)
    {
        var id = distroId.ToLowerInvariant();
        if (id is "debian" or "kali" or "ubuntu" or "linuxmint" or "pop")
        {
            var apt = LinuxProcessRunner.FindExecutable("apt-get");
            if (apt is null)
                return new LinuxUpdateStatus { Available = false, Kind = "apt", Summary = "APT status unavailable", Detail = "apt-get was not found in PATH." };
            var result = await LinuxProcessRunner.RunAsync(apt, ["-s", "upgrade"], TimeSpan.FromSeconds(30), cancellationToken,
                new Dictionary<string, string> { ["DEBIAN_FRONTEND"] = "noninteractive" }).ConfigureAwait(false);
            if (!result.Started)
                return new LinuxUpdateStatus { Available = false, Kind = "apt", Summary = "APT status unavailable", Detail = "APT could not be queried." };
            if (result.TimedOut)
                return new LinuxUpdateStatus { Available = true, Kind = "apt", Summary = "APT simulation timed out", Detail = "No package changes were made." };
            var match = Regex.Match(result.StandardOutput, @"(\d+)\s+upgraded");
            return new LinuxUpdateStatus
            {
                Available = true,
                Kind = "apt",
                PendingCount = match.Success ? int.Parse(match.Groups[1].Value) : null,
                Summary = match.Success
                    ? $"{match.Groups[1].Value} package upgrade{(match.Groups[1].Value == "1" ? "" : "s")} offered (simulation)"
                    : "APT simulation completed; no upgrade count was reported",
                Detail = "Read-only APT simulation. No package was installed, updated, or changed."
            };
        }

        if (id is "bazzite" or "fedora" or "silverblue" or "kinoite")
        {
            var rpmOstree = LinuxProcessRunner.FindExecutable("rpm-ostree");
            if (rpmOstree is null)
                return new LinuxUpdateStatus { Available = false, Kind = "rpm-ostree", Summary = "rpm-ostree not found", Detail = "No update information is available." };
            var result = await LinuxProcessRunner.RunAsync(rpmOstree, ["status"], TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
            return new LinuxUpdateStatus
            {
                Available = result.Started && !result.TimedOut,
                Kind = "rpm-ostree",
                Summary = result.Started && !result.TimedOut ? "Managed OS image" : "rpm-ostree status unavailable",
                Detail = "Bazzite uses a managed OS image. WTX PC CHECK did not query remote updates and did not run rpm-ostree or modify the system. Use your normal Bazzite update flow."
            };
        }

        return new LinuxUpdateStatus
        {
            Available = false,
            Kind = "unknown",
            Summary = "Update status is not available for this distribution",
            Detail = "WTX PC CHECK does not run package-manager update commands automatically. Use the distribution's normal update tool."
        };
    }

    private static StartupQueryResult GetStartupEntries()
    {
        var entries = new List<LinuxStartupEntry>();
        var total = 0;
        var autostartDirectories = new[]
        {
            Path.Combine(LinuxPaths.XdgConfigHome, "autostart"),
            "/etc/xdg/autostart"
        };
        foreach (var directory in autostartDirectories)
        {
            if (!Directory.Exists(directory)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(directory, "*.desktop").Take(100))
                {
                    total++;
                    var content = File.ReadAllText(file);
                    if (Regex.IsMatch(content, @"(?im)^\s*Hidden\s*=\s*true\s*$")) continue;
                    var name = ReadDesktopValue(content, "Name") ?? Path.GetFileNameWithoutExtension(file);
                    var command = ReadDesktopValue(content, "Exec") ?? file;
                    entries.Add(BuildStartupEntry(name, "XDG autostart", command));
                }
            }
            catch { }
        }

        var userUnits = Path.Combine(LinuxPaths.XdgConfigHome, "systemd", "user");
        if (Directory.Exists(userUnits))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(userUnits, "*.service").Take(100))
                {
                    total++;
                    var content = File.ReadAllText(file);
                    var command = Regex.Match(content, @"(?im)^\s*ExecStart\s*=\s*(.+)$").Groups[1].Value.Trim();
                    if (string.IsNullOrWhiteSpace(command)) continue;
                    entries.Add(BuildStartupEntry(Path.GetFileNameWithoutExtension(file), "systemd user unit", command));
                }
            }
            catch { }
        }

        return new StartupQueryResult
        {
            Items = entries.OrderByDescending(e => e.Risk).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase).Take(60).ToList(),
            Total = total
        };
    }

    private static string? ReadDesktopValue(string content, string key)
    {
        var match = Regex.Match(content, $@"(?im)^\s*{Regex.Escape(key)}\s*=\s*(.+)$");
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private static LinuxStartupEntry BuildStartupEntry(string name, string source, string command)
    {
        var expanded = Environment.ExpandEnvironmentVariables(command);
        var exe = ExtractExecutablePath(expanded);
        bool? exists = exe is null ? null : File.Exists(exe) || Directory.Exists(exe);
        var risk = RiskLevel.Info;
        var explanation = "This entry is configured to start with your Linux user session. It is shown for review and was not executed or changed.";
        if (exe is not null && exists == false)
        {
            risk = RiskLevel.Low;
            explanation = "The startup command points to a path that was not found. It may be stale or use a format that could not be resolved.";
        }
        else if (exe is not null && (exe.StartsWith("/tmp/", StringComparison.Ordinal) ||
                                     exe.Contains("/Downloads/", StringComparison.OrdinalIgnoreCase)))
        {
            risk = RiskLevel.Low;
            explanation = "The startup executable is in a temporary or download location. Review its source and publisher.";
        }
        var normalized = new string(name.ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
        if (new[] { "synapse", "krnl", "fluxus", "wurst", "meteorclient", "executor" }.Any(t => normalized.Contains(t, StringComparison.Ordinal)))
        {
            risk = RiskLevel.Medium;
            explanation = "The startup entry name contains a gaming or executor-related token. A name is not proof of malicious behavior; review the command and its source.";
        }
        return new LinuxStartupEntry
        {
            Name = name,
            Source = source,
            Command = command,
            ExecutablePath = exe,
            ExecutableExists = exists,
            Risk = risk,
            Explanation = explanation
        };
    }

    private static string? ExtractExecutablePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var value = command.Trim();
        if (value.StartsWith('"'))
        {
            var end = value.IndexOf('"', 1);
            return end > 1 ? value[1..end] : null;
        }
        var first = value.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)[0];
        return first.StartsWith('/') ? first : null;
    }

    private static ProcessQueryResult GetProcesses()
    {
        const int maxEntries = 120;
        var items = new List<LinuxProcessInfo>();
        var total = 0;
        try
        {
            foreach (var directory in Directory.EnumerateDirectories("/proc"))
            {
                var namePart = Path.GetFileName(directory);
                if (!int.TryParse(namePart, out var pid)) continue;
                total++;
                try
                {
                    var name = File.ReadAllText(Path.Combine(directory, "comm")).Trim();
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    string? path = null;
                    try
                    {
                        var link = new FileInfo(Path.Combine(directory, "exe"));
                        path = link.LinkTarget;
                    }
                    catch { }
                    var normalized = new string((name + " " + (path ?? string.Empty)).ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
                    var known = new[] { "synapse", "krnl", "fluxus", "wurst", "meteorclient", "impactclient", "jjsploit", "executor" }
                        .Any(token => normalized.Contains(token, StringComparison.Ordinal));
                    var risk = known ? RiskLevel.Medium : RiskLevel.Info;
                    var explanation = known
                        ? "The process name or path contains a gaming/executor-related token. A name is not proof of malicious behavior; review the executable path and source."
                        : "Read-only process snapshot. Process memory was not inspected.";
                    if (!known && path is not null && (path.StartsWith("/tmp/", StringComparison.Ordinal) || path.Contains("/Downloads/", StringComparison.OrdinalIgnoreCase)))
                    {
                        risk = RiskLevel.Low;
                        explanation = "The executable runs from a temporary or download location. This is a review signal, not proof of malware.";
                    }
                    items.Add(new LinuxProcessInfo { Name = name, ProcessId = pid, ExecutablePath = path, Risk = risk, Explanation = explanation });
                    if (items.Count >= maxEntries) break;
                }
                catch { }
            }
        }
        catch { }

        return new ProcessQueryResult
        {
            Items = items.OrderByDescending(p => p.Risk).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            Total = total,
            Truncated = total > items.Count,
            Note = "Read-only /proc snapshot. Process memory is never inspected. Publisher signatures are not checked on Linux."
        };
    }

    private async Task<ClamAvStatus> GetClamAvStatusAsync(CancellationToken cancellationToken)
    {
        var executable = LinuxProcessRunner.FindExecutable("clamscan") ?? LinuxProcessRunner.FindExecutable("clamdscan");
        if (executable is null)
        {
            return new ClamAvStatus
            {
                Available = false,
                Detail = "ClamAV is not installed or not in PATH. WTX PC CHECK does not install it; game-specific scans remain available without it."
            };
        }
        var result = await LinuxProcessRunner.RunAsync(executable, ["--version"], TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        var version = result.Started && !result.TimedOut ? result.StandardOutput.Split('\n')[0].Trim() : null;
        return new ClamAvStatus
        {
            Available = true,
            Executable = executable,
            Version = string.IsNullOrWhiteSpace(version) ? "Version unavailable" : version,
            Detail = "ClamAV is installed. WTX PC CHECK can run a read-only local scan when you request it."
        };
    }

    private static OsInfo ReadOsRelease()
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var line in File.ReadAllLines("/etc/os-release"))
            {
                var index = line.IndexOf('=');
                if (index <= 0) continue;
                values[line[..index]] = line[(index + 1)..].Trim('"');
            }
        }
        catch { }
        var id = values.GetValueOrDefault("ID", "linux");
        var name = values.GetValueOrDefault("PRETTY_NAME") ?? values.GetValueOrDefault("NAME") ?? "Linux";
        var targeted = id is "bazzite" or "kali";
        return new OsInfo
        {
            Id = id,
            DisplayName = name,
            SupportNote = targeted
                ? "Targeted Linux distribution. Only features available to the current user are shown."
                : "Linux support is best-effort on this distribution. Bazzite and Kali are the explicitly targeted distributions."
        };
    }

    private sealed class OsInfo
    {
        public string Id { get; init; } = "linux";
        public string DisplayName { get; init; } = "Linux";
        public string SupportNote { get; init; } = string.Empty;
    }

    private sealed class StartupQueryResult
    {
        public List<LinuxStartupEntry> Items { get; init; } = [];
        public int Total { get; init; }
    }

    private sealed class ProcessQueryResult
    {
        public List<LinuxProcessInfo> Items { get; init; } = [];
        public int Total { get; init; }
        public bool Truncated { get; init; }
        public string Note { get; init; } = string.Empty;
    }

    [GeneratedRegex(@"^(.+):\s+(.+)\s+FOUND$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ClamAvFindingRegex();
}


