using System.Diagnostics;
using System.IO;
using System.Text.Json;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public sealed class UpdateStateFile
{
    public string Status { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public DateTimeOffset TimestampUtc { get; init; }
}

public sealed class UpdateApplyService
{
    public async Task<(bool Started, string ErrorEnglish)> StartApplyAsync(
        string stagedPath,
        string expectedSha256,
        string version,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(stagedPath))
                return (false, "The staged update file is no longer available. Run the update check again.");

            var hash = HashService.TryComputeSha256(
                stagedPath, new FileInfo(stagedPath).Length, cancellationToken, 500L * 1024 * 1024);
            if (!hash.Success || !string.Equals(hash.Sha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
                return (false, "The staged update failed its final hash verification. Nothing was installed.");

            var configuration = new UpdateConfiguration();
            var signature = SignatureService.Verify(stagedPath, checkRevocation: true);
            var thumbprint = UpdateConfiguration.NormalizeThumbprint(signature.ThumbprintSha256);
            if (signature.Status != SignatureStatus.Valid ||
                thumbprint != configuration.ExpectedThumbprint ||
                configuration.ExpectedThumbprint.Length != 64)
            {
                return (false, "The staged update failed its final publisher-signature verification. Nothing was installed.");
            }

            var target = AppPaths.ExecutablePath;
            if (Path.GetFileName(target).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
                return (false, "The app is running through the .NET host rather than WTX-PC-CHECK.exe. A self-update was not attempted.");
            if (!Path.GetFullPath(stagedPath).StartsWith(
                    Path.GetFullPath(AppPaths.UpdateWorkDirectory), StringComparison.OrdinalIgnoreCase))
                return (false, "The staged update is not in the expected temporary location. Nothing was installed.");

            Directory.CreateDirectory(AppPaths.LocalDataDirectory);
            UpdateWorkFiles files = new(
                target,
                stagedPath,
                target + ".previous.exe",
                AppPaths.UpdateStateFile,
                Path.Combine(AppPaths.UpdateWorkDirectory, $"apply-{Guid.NewGuid():N}.ps1"));

            WriteState(new UpdateStateFile
            {
                Status = "applying",
                Version = version,
                Message = "The verified update is being installed.",
                TimestampUtc = DateTimeOffset.UtcNow
            });

            var script = BuildApplyScript();
            Directory.CreateDirectory(Path.GetDirectoryName(files.Script)!);
            await File.WriteAllTextAsync(files.Script, script, cancellationToken).ConfigureAwait(false);

            var startInfo = new ProcessStartInfo
            {
                FileName = ProcessRunner.PowerShellPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            startInfo.ArgumentList.Add("-NoLogo");
            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-NonInteractive");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-File");
            startInfo.ArgumentList.Add(files.Script);
            startInfo.ArgumentList.Add("-WaitForProcessId");
            startInfo.ArgumentList.Add(Environment.ProcessId.ToString());
            startInfo.ArgumentList.Add("-TargetExe");
            startInfo.ArgumentList.Add(files.Target);
            startInfo.ArgumentList.Add("-StagedExe");
            startInfo.ArgumentList.Add(files.Staged);
            startInfo.ArgumentList.Add("-BackupExe");
            startInfo.ArgumentList.Add(files.Backup);
            startInfo.ArgumentList.Add("-StateFile");
            startInfo.ArgumentList.Add(files.State);
            startInfo.ArgumentList.Add("-Version");
            startInfo.ArgumentList.Add(version);
            startInfo.ArgumentList.Add("-StagedSha256");
            startInfo.ArgumentList.Add(expectedSha256);

            using var process = Process.Start(startInfo);
            if (process is null)
                return (false, "The update helper could not be started. The previous version remains in use.");

            return (true, string.Empty);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return (false, "The update could not be prepared for installation. The previous version remains in use.");
        }
    }

    public static UpdateStateFile? ReadAndConsumeState()
    {
        try
        {
            if (!File.Exists(AppPaths.UpdateStateFile)) return null;
            var json = File.ReadAllText(AppPaths.UpdateStateFile);
            var state = JsonSerializer.Deserialize<UpdateStateFile>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            File.Delete(AppPaths.UpdateStateFile);
            return state;
        }
        catch
        {
            return null;
        }
    }

    public static string? DescribeStartupState(UpdateStateFile? state)
    {
        if (state is null) return null;
        return state.Status switch
        {
            "success" => $"WTX PC CHECK {state.Version} was installed successfully.",
            "rolled-back" => $"An update to version {state.Version} could not be installed. The previous version was restored and remains usable.",
            "applying" => "A previous update attempt did not finish. The current version is still available. Run the update check again if needed.",
            _ => null
        };
    }

    private static void WriteState(UpdateStateFile state)
    {
        Directory.CreateDirectory(AppPaths.LocalDataDirectory);
        var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
        var temp = AppPaths.UpdateStateFile + ".tmp";
        File.WriteAllText(temp, json);
        File.Move(temp, AppPaths.UpdateStateFile, true);
    }

    private sealed record UpdateWorkFiles(
        string Target,
        string Staged,
        string Backup,
        string State,
        string Script);

    internal static string BuildApplyScript() => """
        param(
            [Parameter(Mandatory=$true)][int]$WaitForProcessId,
            [Parameter(Mandatory=$true)][string]$TargetExe,
            [Parameter(Mandatory=$true)][string]$StagedExe,
            [Parameter(Mandatory=$true)][string]$BackupExe,
            [Parameter(Mandatory=$true)][string]$StateFile,
            [Parameter(Mandatory=$true)][string]$Version,
            [Parameter(Mandatory=$true)][string]$StagedSha256
        )
        $ErrorActionPreference = 'Stop'
        function Set-UpdateState([string]$status, [string]$message) {
            $payload = [ordered]@{
                status = $status
                version = $Version
                message = $message
                timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
            } | ConvertTo-Json -Compress
            $dir = [System.IO.Path]::GetDirectoryName($StateFile)
            if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            [System.IO.File]::WriteAllText($StateFile, $payload, [System.Text.UTF8Encoding]::new($false))
        }
        try { Wait-Process -Id $WaitForProcessId -Timeout 180 -ErrorAction SilentlyContinue } catch { }
        Start-Sleep -Milliseconds 900
        try {
            $actualHash = (Get-FileHash -LiteralPath $StagedExe -Algorithm SHA256).Hash
            if ($actualHash -ne $StagedSha256.ToUpperInvariant()) { throw 'Hash mismatch.' }
            if (Test-Path -LiteralPath $TargetExe) {
                Copy-Item -LiteralPath $TargetExe -Destination $BackupExe -Force
            }
            Set-UpdateState 'applying' 'Installing the verified update.'
            $copied = $false
            for ($i = 0; $i -lt 8 -and -not $copied; $i++) {
                try {
                    Copy-Item -LiteralPath $StagedExe -Destination $TargetExe -Force
                    $copied = $true
                } catch {
                    Start-Sleep -Milliseconds 700
                }
            }
            if (-not $copied) { throw 'The app file could not be replaced.' }
            $newProcess = Start-Process -FilePath $TargetExe -PassThru
            Start-Sleep -Seconds 7
            if ($newProcess.HasExited) { throw 'The updated app did not stay running.' }
            Set-UpdateState 'success' 'Update installed successfully.'
            Remove-Item -LiteralPath $StagedExe -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $BackupExe -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
            exit 0
        } catch {
            Set-UpdateState 'rolled-back' 'The update could not be installed. The previous version was restored.'
            if (Test-Path -LiteralPath $BackupExe) {
                Copy-Item -LiteralPath $BackupExe -Destination $TargetExe -Force -ErrorAction SilentlyContinue
                Start-Process -FilePath $TargetExe
            }
            Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
            exit 1
        }
        """;
}


