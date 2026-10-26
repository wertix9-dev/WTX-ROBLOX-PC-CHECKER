using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Microsoft.Win32;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public sealed class SecurityStatusService
{
    private readonly IndicatorDatabase _indicators;

    public SecurityStatusService(IndicatorDatabase? indicators = null)
    {
        _indicators = indicators ?? IndicatorDatabase.LoadEmbedded();
    }

    private const string DefenderFirewallScript = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $out = [ordered]@{
          defenderAvailable = $false
          realtime = $null
          antivirus = $null
          amservice = $null
          tamper = $null
          signatureVersion = $null
          signatureUpdated = $null
          firewallAvailable = $false
          domain = $null
          private = $null
          public = $null
          avProducts = @()
        }
        try {
          $mp = Get-MpComputerStatus -ErrorAction Stop
          $out.defenderAvailable = $true
          $out.realtime = [bool]$mp.RealTimeProtectionEnabled
          $out.antivirus = [bool]$mp.AntivirusEnabled
          $out.amservice = [bool]$mp.AMServiceEnabled
          try { $out.tamper = [bool]$mp.IsTamperProtected } catch { }
          $out.signatureVersion = [string]$mp.AntivirusSignatureVersion
          try { $out.signatureUpdated = [string]$mp.AntivirusSignatureLastUpdated } catch { }
        } catch { }
        try {
          $profiles = Get-NetFirewallProfile -ErrorAction Stop
          $out.firewallAvailable = $true
          foreach ($p in $profiles) {
            if ($p.Name -eq 'Domain') { $out.domain = [bool]$p.Enabled }
            elseif ($p.Name -eq 'Private') { $out.private = [bool]$p.Enabled }
            elseif ($p.Name -eq 'Public') { $out.public = [bool]$p.Enabled }
          }
        } catch { }
        try {
          $av = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
          $out.avProducts = @($av | ForEach-Object { [string]$_.displayName } | Where-Object { $_ })
        } catch { }
        $out | ConvertTo-Json -Compress -Depth 4
        """;

    private const string WindowsUpdateScript = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $out = [ordered]@{ success = $false; count = 0; security = 0 }
        try {
          $session = New-Object -ComObject Microsoft.Update.Session
          $searcher = $session.CreateUpdateSearcher()
          $found = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
          $count = 0
          $security = 0
          foreach ($u in $found.Updates) {
            $count++
            $isSecurity = $false
            try { if ($u.MsrcSeverity) { $isSecurity = $true } } catch { }
            if (-not $isSecurity) {
              try {
                foreach ($c in $u.Categories) {
                  if ($c.Name -match 'Security|Critical') { $isSecurity = $true; break }
                }
              } catch { }
            }
            if ($isSecurity) { $security++ }
          }
          $out.success = $true
          $out.count = $count
          $out.security = $security
        } catch { }
        $out | ConvertTo-Json -Compress
        """;

    private static readonly string[] StartupRegistryKeys =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    ];

    public async Task<SecurityOverview> GetOverviewAsync(CancellationToken cancellationToken)
    {
        var overview = BuildOsInfo();

        var securityTask = GetDefenderAndFirewallAsync(cancellationToken);
        var updatesTask = GetWindowsUpdatesAsync(cancellationToken);
        var startupTask = Task.Run(GetStartupEntries, cancellationToken);
        var processTask = Task.Run(() => GetRunningProcesses(cancellationToken), cancellationToken);

        await Task.WhenAll(securityTask, updatesTask, startupTask, processTask).ConfigureAwait(false);

        var security = securityTask.Result;
        overview.Defender = security.Defender;
        overview.Firewall = security.Firewall;
        overview.RegisteredAntivirus = security.AntivirusProducts;
        overview.Updates = updatesTask.Result;

        var startup = startupTask.Result;
        overview.StartupEntries = startup.Entries;
        overview.StartupEntryCount = startup.Total;
        overview.StartupListTruncated = startup.Truncated;
        overview.StartupNote = startup.Note;

        var processes = processTask.Result;
        overview.Processes = processes.Items;
        overview.ProcessCount = processes.Total;
        overview.ProcessListTruncated = processes.Truncated;
        overview.ProcessNote = processes.Note;

        overview.CheckedUtc = DateTimeOffset.UtcNow;
        overview.State = SecurityQueryState.Available;
        return overview;
    }

    private sealed class SecuritySnapshot
    {
        public required DefenderStatus Defender { get; init; }
        public required FirewallStatus Firewall { get; init; }
        public List<string> AntivirusProducts { get; init; } = [];
    }


    private sealed class ProcessQueryResult
    {
        public List<RunningProcessInfo> Items { get; init; } = [];
        public int Total { get; init; }
        public bool Truncated { get; init; }
        public string Note { get; init; } = string.Empty;
    }

    private bool IsKnownProcessName(string name)
        => _indicators.TryMatchExecutableName(name + ".exe", out _) ||
           _indicators.TryMatchMinecraftToken(name, out _);

    private ProcessQueryResult GetRunningProcesses(CancellationToken cancellationToken)
    {
        const int maxEntries = 80;
        var entries = new List<RunningProcessInfo>();
        var total = 0;
        string note = "Read-only snapshot of running processes. Process memory is not inspected.";
        try
        {
            var processes = Process.GetProcesses()
                .OrderByDescending(p => IsKnownProcessName(p.ProcessName))
                .ThenBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            total = processes.Length;
            foreach (var process in processes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string name;
                try { name = process.ProcessName; }
                catch { continue; }
                if (string.IsNullOrWhiteSpace(name)) continue;

                string? path = null;
                try { path = process.MainModule?.FileName; }
                catch { }
                var signature = SignatureInfo.NotChecked("The executable path is unavailable, usually because the process is protected.");
                if (!string.IsNullOrWhiteSpace(path))
                {
                    try { signature = SignatureService.Verify(path); }
                    catch { signature = SignatureInfo.NotChecked("The publisher signature could not be checked."); }
                }

                var matched = _indicators.TryMatchExecutableName(name + ".exe", out var executorMatch) ||
                              _indicators.TryMatchMinecraftToken(name, out var minecraftMatch) ||
                              (path is not null && _indicators.TryMatchFolder(Path.GetDirectoryName(path) ?? string.Empty, out var folderMatch));
                var product = "";
                if (_indicators.TryMatchExecutableName(name + ".exe", out var em)) product = em.Product;
                else if (_indicators.TryMatchMinecraftToken(name, out var mm)) product = mm.Product;
                else if (path is not null && _indicators.TryMatchFolder(Path.GetDirectoryName(path) ?? string.Empty, out var fm)) product = fm.Product;

                var risk = RiskLevel.Info;
                var explanation = "Running process snapshot. Name, path, and publisher are shown without inspecting memory.";
                if (matched)
                {
                    risk = RiskLevel.Medium;
                    explanation = $"The process name or folder matches “{product}”, a known executor or Minecraft cheat-client indicator. A name is not proof; review the executable path and publisher.";
                }
                else if (signature.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid &&
                         (FileRules.LooksLikeDownloadsOrTemp(path) || FileRules.IsUserWritableLocation(path)))
                {
                    risk = RiskLevel.Low;
                    explanation = "The executable is unsigned or has an invalid signature and runs from a user-writable location. This is a review signal, not proof of malware.";
                }
                else if (signature.Status == SignatureStatus.Invalid)
                {
                    risk = RiskLevel.Low;
                    explanation = "The executable's signature is not valid. Review the publisher before trusting the process.";
                }

                entries.Add(new RunningProcessInfo
                {
                    Name = name,
                    ProcessId = process.Id,
                    ExecutablePath = path,
                    Signature = signature,
                    Risk = risk,
                    Explanation = explanation
                });

                if (entries.Count >= maxEntries)
                {
                    note = $"The process list is capped at {maxEntries} entries. {total:N0} processes were visible. Process memory was not inspected.";
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            note = "The running process snapshot could not be completed. Process memory was not inspected.";
        }

        return new ProcessQueryResult
        {
            Items = entries.OrderByDescending(p => p.Risk).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            Total = total,
            Truncated = total > entries.Count,
            Note = note
        };
    }
    private async Task<SecuritySnapshot> GetDefenderAndFirewallAsync(CancellationToken cancellationToken)
    {
        var result = await ProcessRunner.RunPowerShellAsync(
            DefenderFirewallScript, TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false);

        if (!result.Started || result.TimedOut || string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            return new SecuritySnapshot
            {
                Defender = new DefenderStatus
                {
                    Available = false,
                    Note = result.TimedOut
                        ? "Windows Defender did not respond in time."
                        : "Windows Defender status could not be read. A third-party antivirus may be managing protection, or the service may be disabled."
                },
                Firewall = new FirewallStatus
                {
                    Available = false,
                    Note = "Windows Firewall status could not be read."
                }
            };
        }

        try
        {
            using var document = JsonDocument.Parse(result.StandardOutput.Trim());
            var root = document.RootElement;
            var defenderAvailable = ReadBool(root, "defenderAvailable") ?? false;
            DateTimeOffset? updated = null;
            if (root.TryGetProperty("signatureUpdated", out var updatedElement) &&
                updatedElement.ValueKind == JsonValueKind.String &&
                DateTimeOffset.TryParse(updatedElement.GetString(), out var parsed))
            {
                updated = parsed;
            }

            var products = new List<string>();
            if (root.TryGetProperty("avProducts", out var productsElement) &&
                productsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in productsElement.EnumerateArray())
                {
                    var name = item.GetString();
                    if (!string.IsNullOrWhiteSpace(name)) products.Add(name);
                }
            }

            var firewallAvailable = ReadBool(root, "firewallAvailable") ?? false;
            return new SecuritySnapshot
            {
                Defender = new DefenderStatus
                {
                    Available = defenderAvailable,
                    RealTimeProtectionEnabled = ReadBool(root, "realtime"),
                    AntivirusEnabled = ReadBool(root, "antivirus"),
                    AmServiceEnabled = ReadBool(root, "amservice"),
                    TamperProtectionEnabled = ReadBool(root, "tamper"),
                    SignatureVersion = ReadString(root, "signatureVersion"),
                    SignatureUpdated = updated,
                    Note = defenderAvailable
                        ? "Status reported by Windows Security."
                        : "Windows Defender status is unavailable. Another antivirus may be managing protection."
                },
                Firewall = new FirewallStatus
                {
                    Available = firewallAvailable,
                    DomainEnabled = ReadBool(root, "domain"),
                    PrivateEnabled = ReadBool(root, "private"),
                    PublicEnabled = ReadBool(root, "public"),
                    Note = firewallAvailable
                        ? "Status reported by Windows Firewall."
                        : "Firewall status is unavailable."
                },
                AntivirusProducts = products
            };
        }
        catch
        {
            return new SecuritySnapshot
            {
                Defender = new DefenderStatus
                {
                    Available = false,
                    Note = "Windows Defender status could not be read."
                },
                Firewall = new FirewallStatus
                {
                    Available = false,
                    Note = "Windows Firewall status could not be read."
                }
            };
        }
    }

    private async Task<WindowsUpdatesStatus> GetWindowsUpdatesAsync(CancellationToken cancellationToken)
    {
        var result = await ProcessRunner.RunPowerShellAsync(
            WindowsUpdateScript, TimeSpan.FromSeconds(60), cancellationToken).ConfigureAwait(false);
        if (!result.Started)
        {
            return new WindowsUpdatesStatus
            {
                Available = false,
                Note = "Windows Update could not be queried on this PC."
            };
        }
        if (result.TimedOut)
        {
            return new WindowsUpdatesStatus
            {
                Available = true,
                TimedOut = true,
                Note = "Windows Update did not answer within 60 seconds. The PC may be offline, or Windows Update may be busy."
            };
        }

        try
        {
            using var document = JsonDocument.Parse(result.StandardOutput.Trim());
            var root = document.RootElement;
            var success = ReadBool(root, "success") ?? false;
            return new WindowsUpdatesStatus
            {
                Available = true,
                SearchSucceeded = success,
                PendingCount = ReadInt(root, "count") ?? 0,
                SecurityCount = ReadInt(root, "security") ?? 0,
                Note = success
                    ? "Counts come from a Windows Update search. Classification of security updates can be incomplete."
                    : "Windows Update could not be searched. The PC may be offline, or Windows Update may be disabled by policy."
            };
        }
        catch
        {
            return new WindowsUpdatesStatus
            {
                Available = true,
                SearchSucceeded = false,
                Note = "Windows Update returned a result that could not be read."
            };
        }
    }

    private sealed class StartupQueryResult
    {
        public List<StartupEntry> Entries { get; init; } = [];
        public int Total { get; init; }
        public bool Truncated { get; init; }
        public string Note { get; init; } = string.Empty;
    }

    private StartupQueryResult GetStartupEntries()
    {
        var entries = new List<StartupEntry>();
        var total = 0;
        var note = string.Empty;

        try
        {
            ReadRunKeys(entries, ref total, Registry.CurrentUser, "Current user");
            ReadRunKeys(entries, ref total, Registry.LocalMachine, "All users");
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
                ReadRunKeys(entries, ref total, baseKey, "All users (32-bit view)");
            }
            catch { }

            ReadStartupFolder(entries, ref total,
                Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Startup folder (current user)");
            ReadStartupFolder(entries, ref total,
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Startup folder (all users)");
        }
        catch
        {
            note = "Some startup locations could not be read because Windows denied access.";
        }

        var sorted = entries
            .OrderByDescending(e => e.Risk)
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .Take(50)
            .ToList();

        return new StartupQueryResult
        {
            Entries = sorted,
            Total = total,
            Truncated = total > sorted.Count,
            Note = note
        };
    }

    private static void ReadRunKeys(
        List<StartupEntry> entries,
        ref int total,
        RegistryKey hive,
        string label)
    {
        foreach (var subKey in StartupRegistryKeys)
        {
            try
            {
                using var key = hive.OpenSubKey(subKey);
                if (key is null) continue;
                foreach (var valueName in key.GetValueNames())
                {
                    if (string.IsNullOrWhiteSpace(valueName)) continue;
                    var command = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrWhiteSpace(command)) continue;
                    total++;
                    entries.Add(BuildStartupEntry(valueName, label, command));
                }
            }
            catch
            {
                // Protected keys are reported through the overall limitations text.
            }
        }
    }

    private static void ReadStartupFolder(List<StartupEntry> entries, ref int total, string folder, string label)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                total++;
                var target = ResolveShortcut(file);
                entries.Add(BuildStartupEntry(Path.GetFileName(file), label, target ?? file));
            }
        }
        catch
        {
            // Folder permissions vary by user.
        }
    }

    private static StartupEntry BuildStartupEntry(string name, string source, string command)
    {
        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        var exe = ExtractExecutablePath(expanded);
        bool? exists = exe is null ? null : File.Exists(exe);
        var signature = exe is not null && exists == true
            ? SignatureService.Verify(exe)
            : SignatureInfo.NotChecked("No executable path could be resolved from this startup command.");

        var risk = RiskLevel.Info;
        var explanation = "This entry is registered in a Windows startup location. Windows may currently have it disabled; WTX PC CHECK does not evaluate StartupApproved state. Review the command and publisher if you do not recognize it.";
        var normalized = FileRules.NormalizeName(name);
        var nameLooksExecutor = StartupNameTokens.Any(t => normalized.Contains(t, StringComparison.Ordinal));

        if (exe is not null && exists == false)
        {
            risk = RiskLevel.Low;
            explanation = "The startup command points to an executable that was not found. It may be stale, or the command format may hide the real target.";
        }
        else if (signature.Status == SignatureStatus.Invalid)
        {
            risk = RiskLevel.Medium;
            explanation = "The startup executable has an invalid digital signature. Windows did not accept the file signature at the time of this check.";
        }
        else if (signature.Status is SignatureStatus.Unsigned or SignatureStatus.Error &&
                 FileRules.IsUserWritableLocation(exe))
        {
            risk = RiskLevel.Medium;
            explanation = "The startup executable is unsigned and located in a user-writable folder. Unsigned software is not automatically malicious, but this combination deserves review.";
        }
        else if (nameLooksExecutor)
        {
            risk = RiskLevel.Medium;
            explanation = "The startup entry name contains a term associated with Roblox executor software. A name is not proof; verify the executable and publisher.";
        }
        else if (signature.Status == SignatureStatus.Unsigned)
        {
            risk = RiskLevel.Low;
            explanation = "The startup executable is unsigned. Many legitimate programs are unsigned, so review the publisher before deciding.";
        }

        return new StartupEntry
        {
            Name = name,
            Source = source,
            Command = command,
            ExecutablePath = exe,
            ExecutableExists = exists,
            Risk = risk,
            Explanation = explanation,
            Signature = signature
        };
    }

    private static readonly string[] StartupNameTokens =
    [
        "synapse", "krnl", "fluxus", "jjsploit", "scriptware",
        "sirhurt", "wearedevs", "executor", "robloxexecutor"
    ];

    private static string? ExtractExecutablePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var value = command.Trim();
        if (value.StartsWith('"'))
        {
            var end = value.IndexOf('"', 1);
            return end > 1 ? value[1..end] : null;
        }

        var exeIndex = value.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIndex >= 0) return value[..(exeIndex + 4)].Trim();
        var comma = value.IndexOf(',');
        if (comma > 0) return value[..comma].Trim();
        var space = value.IndexOf(' ');
        return space > 0 ? value[..space].Trim() : value;
    }

    private static string? ResolveShortcut(string path)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return null;
            dynamic? shell = Activator.CreateInstance(type);
            if (shell is null) return null;
            dynamic shortcut = shell.CreateShortcut(path);
            string target = shortcut.TargetPath;
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch
        {
            return null;
        }
    }

    private static SecurityOverview BuildOsInfo()
    {
        var version = Environment.OSVersion.Version;
        var isWindows11 = version.Build >= 22000;
        var supported = isWindows11 || version.Build >= 19045;
        var ubr = 0;
        try
        {
            ubr = (int)(Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", 0) ?? 0);
        }
        catch { }
        return new SecurityOverview
        {
            WindowsDisplay = isWindows11 ? "Windows 11" : "Windows 10",
            WindowsBuildDisplay = ubr > 0 ? $"Build {version.Build}.{ubr}" : $"Build {version.Build}.{version.Revision}",
            WindowsSupported = supported
        };
    }

    private static bool? ReadBool(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element)) return null;
        return element.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String when bool.TryParse(element.GetString(), out var parsed) => parsed,
            _ => null
        };
    }

    private static int? ReadInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element)) return null;
        if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var number)) return number;
        if (element.ValueKind == JsonValueKind.String && int.TryParse(element.GetString(), out var parsed)) return parsed;
        return null;
    }

    private static string? ReadString(JsonElement root, string name)
        => root.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
            ? element.GetString()
            : null;
}








