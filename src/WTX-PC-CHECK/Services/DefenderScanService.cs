using System.Diagnostics;
using System.Text.Json;
using System.IO;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public sealed class DefenderProgress
{
    public int CurrentRootIndex { get; init; }
    public int TotalRoots { get; init; }
    public string CurrentRoot { get; init; } = string.Empty;
    public TimeSpan Elapsed { get; init; }
}

public sealed class DefenderScanService
{
    public string? MpCmdRunPath { get; } = FindMpCmdRun();

    public bool IsAvailable => MpCmdRunPath is not null && File.Exists(MpCmdRunPath);

    public async Task<DefenderScanResult> RunSelectedDrivesAsync(
        IReadOnlyList<string> roots,
        IProgress<DefenderProgress>? progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        if (!IsAvailable)
        {
            return new DefenderScanResult
            {
                State = DefenderScanState.NotAvailable,
                Summary = "Windows Defender is not available on this PC. No Defender scan was started.",
                StartedUtc = started,
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }

        if (roots.Count == 0)
        {
            return new DefenderScanResult
            {
                State = DefenderScanState.Failed,
                Summary = "No drives were selected, so no Defender scan was started.",
                StartedUtc = started,
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }

        var stopwatch = Stopwatch.StartNew();
        var nonZero = 0;
        var errors = 0;
        var completed = 0;
        var cancelled = false;

        for (var index = 0; index < roots.Count; index++)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                cancelled = true;
                break;
            }

            var root = roots[index];
            progress?.Report(new DefenderProgress
            {
                CurrentRootIndex = index + 1,
                TotalRoots = roots.Count,
                CurrentRoot = root,
                Elapsed = stopwatch.Elapsed
            });

            var args = new[]
            {
                "-Scan",
                "-ScanType", "3",
                "-File", root,
                "-DisableRemediation"
            };

            ProcessResult result;
            try
            {
                result = await ProcessRunner.RunAsync(MpCmdRunPath!, args, null, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
                break;
            }

            if (!result.Started)
            {
                errors++;
                continue;
            }

            completed++;
            if (result.ExitCode == 0)
            {
                // This drive completed without a reported detection.
            }
            else if (result.ExitCode == 2)
            {
                nonZero++;
            }
            else
            {
                errors++;
            }
        }

        var ended = DateTimeOffset.UtcNow;
        var detections = new List<DefenderDetection>();
        var detectionDetailsAvailable = false;
        if (!cancelled && nonZero > 0)
        {
            var query = await TryGetRecentDetectionsAsync(started, cancellationToken).ConfigureAwait(false);
            detections = query.Detections;
            detectionDetailsAvailable = query.Available;
        }
        if (cancelled)
        {
            return new DefenderScanResult
            {
                State = DefenderScanState.Cancelled,
                Summary = $"The Windows Defender scan was cancelled after {AppFormat.Duration(stopwatch.Elapsed)}. Its result is incomplete. Files scanned before cancellation are not listed in WTX PC CHECK.",
                StartedUtc = started,
                CompletedUtc = ended
            };
        }

        if (errors > 0 && completed == 0)
        {
            return new DefenderScanResult
            {
                State = DefenderScanState.Failed,
                Summary = "Windows Defender could not complete the scan. Windows may have denied access, the Defender service may be unavailable, or the scan was blocked by policy. You can open Windows Security to run a scan from there.",
                StartedUtc = started,
                CompletedUtc = ended,
                ExitCode = null
            };
        }

        if (nonZero > 0)
        {
            return new DefenderScanResult
            {
                State = DefenderScanState.ThreatsFound,
                Summary = $"Windows Defender returned a non-zero result for {nonZero} of {roots.Count} selected drive{(roots.Count == 1 ? "" : "s")}. " +
                          (detections.Count > 0
                              ? $"Windows Security recorded {detections.Count} detection resource{(detections.Count == 1 ? "" : "s")}; they are listed as separate findings."
                              : "Defender detection details could not be read. Open Windows Security to review the result.") +
                          " WTX PC CHECK did not change, remove, or quarantine any file.",
                StartedUtc = started,
                CompletedUtc = ended,
                ExitCode = 2,
                Detections = detections,
                DetectionDetailsAvailable = detectionDetailsAvailable
            };
        }

        if (errors > 0)
        {
            return new DefenderScanResult
            {
                State = DefenderScanState.Failed,
                Summary = $"Windows Defender completed part of the scan but reported an error for {errors} selected drive{(errors == 1 ? "" : "s")}. Open Windows Security for the full result.",
                StartedUtc = started,
                CompletedUtc = ended
            };
        }

        return new DefenderScanResult
        {
            State = DefenderScanState.NoThreats,
            Summary = $"Windows Defender completed a custom scan with remediation disabled on {roots.Count} selected drive{(roots.Count == 1 ? "" : "s")} and reported no detection (exit code 0). This does not guarantee that the PC is clean.",
            StartedUtc = started,
            CompletedUtc = ended,
            ExitCode = 0
        };
    }

    private sealed class DetectionQuery
    {
        public List<DefenderDetection> Detections { get; init; } = [];
        public bool Available { get; init; }
    }

    private static async Task<DetectionQuery> TryGetRecentDetectionsAsync(DateTimeOffset since, CancellationToken cancellationToken)
    {
        try
        {
            var timestamp = since.UtcDateTime.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
            var script = $$"""
                $ErrorActionPreference = 'Stop'
                $ProgressPreference = 'SilentlyContinue'
                [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
                $start = [datetime]'{{timestamp}}'
                $items = @(Get-MpThreatDetection -ErrorAction Stop |
                    Where-Object { $_.InitialDetectionTime -ge $start } |
                    ForEach-Object {
                        [pscustomobject]@{
                            threatId = [string]$_.ThreatID
                            detectedUtc = [string]($_.InitialDetectionTime.ToUniversalTime().ToString('o'))
                            resources = @($_.Resources | ForEach-Object { ([string]$_) -replace '^file:_','' -replace '^file:','' -replace '^containerfile:_','' -replace '^containerfile:','' })
                        }
                    })
                $items | ConvertTo-Json -Depth 5 -Compress
                """;
            var result = await ProcessRunner.RunPowerShellAsync(script, TimeSpan.FromSeconds(20), cancellationToken).ConfigureAwait(false);
            if (!result.Started || result.TimedOut || string.IsNullOrWhiteSpace(result.StandardOutput))
                return new DetectionQuery { Available = false };
            var output = result.StandardOutput.Trim();
            if (output == "[]") return new DetectionQuery { Available = true };

            using var document = JsonDocument.Parse(output);
            var root = document.RootElement;
            var items = root.ValueKind == JsonValueKind.Array
                ? root.EnumerateArray().ToList()
                : new List<JsonElement> { root };
            var list = new List<DefenderDetection>();
            foreach (var item in items)
            {
                if (item.ValueKind != JsonValueKind.Object) continue;
                var threatId = item.TryGetProperty("threatId", out var id) ? id.GetString() ?? "Unknown" : "Unknown";
                DateTimeOffset? detected = null;
                if (item.TryGetProperty("detectedUtc", out var detectedElement) &&
                    DateTimeOffset.TryParse(detectedElement.GetString(), out var parsed))
                    detected = parsed;
                var resources = new List<string>();
                if (item.TryGetProperty("resources", out var resourceElement))
                {
                    if (resourceElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var resource in resourceElement.EnumerateArray())
                        {
                            if (resource.ValueKind == JsonValueKind.String)
                            {
                                var value = resource.GetString();
                                if (!string.IsNullOrWhiteSpace(value)) resources.Add(value);
                            }
                        }
                    }
                    else if (resourceElement.ValueKind == JsonValueKind.String)
                    {
                        var value = resourceElement.GetString();
                        if (!string.IsNullOrWhiteSpace(value)) resources.Add(value);
                    }
                }
                if (resources.Count > 0)
                    list.Add(new DefenderDetection { ThreatId = threatId, DetectedUtc = detected, Resources = resources });
            }
            return new DetectionQuery { Available = true, Detections = list };
        }
        catch (OperationCanceledException)
        {
            return new DetectionQuery { Available = false };
        }
        catch
        {
            return new DetectionQuery { Available = false };
        }
    }
    private static string? FindMpCmdRun()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender", "MpCmdRun.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Windows Defender", "MpCmdRun.exe")
        };
        return candidates.FirstOrDefault(File.Exists);
    }
}



