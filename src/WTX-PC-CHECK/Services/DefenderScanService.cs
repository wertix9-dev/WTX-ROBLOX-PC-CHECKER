using System.Diagnostics;
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
                Summary = $"Windows Defender returned a non-zero result for {nonZero} of {roots.Count} selected drive{(roots.Count == 1 ? "" : "s")}. This can mean malware was detected or that the scan reported an error. WTX PC CHECK did not change, remove, or quarantine any file. Open Windows Security to review Defender's own result.",
                StartedUtc = started,
                CompletedUtc = ended,
                ExitCode = 2
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
