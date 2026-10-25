using System.IO;
using System.Diagnostics;
using System.Text;

namespace WtxPcCheck.Services;

public sealed class ProcessResult
{
    public bool Started { get; init; }
    public bool TimedOut { get; init; }
    public int ExitCode { get; init; } = -1;
    public string StandardOutput { get; init; } = string.Empty;
    public string StandardError { get; init; } = string.Empty;
}

public static class ProcessRunner
{
    public static string PowerShellPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");

    public static async Task<ProcessResult> RunAsync(
        string fileName,
        IEnumerable<string> arguments,
        TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false)
        };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
                return new ProcessResult { Started = false };
        }
        catch
        {
            return new ProcessResult { Started = false };
        }

        using var timeoutSource = timeout is null ? null : new CancellationTokenSource(timeout.Value);
        using var linked = timeoutSource is null
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
            : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);

        var stdoutTask = process.StandardOutput.ReadToEndAsync(linked.Token);
        var stderrTask = process.StandardError.ReadToEndAsync(linked.Token);
        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested) throw;
            timedOut = true;
            try { process.Kill(true); } catch { }
        }

        string stdout = string.Empty;
        string stderr = string.Empty;
        try { stdout = await stdoutTask.ConfigureAwait(false); } catch { }
        try { stderr = await stderrTask.ConfigureAwait(false); } catch { }

        return new ProcessResult
        {
            Started = true,
            TimedOut = timedOut,
            ExitCode = timedOut ? -1 : SafeExitCode(process),
            StandardOutput = stdout,
            StandardError = stderr
        };
    }

    public static async Task<ProcessResult> RunPowerShellAsync(
        string script,
        TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        var args = new[]
        {
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script
        };
        return await RunAsync(PowerShellPath, args, timeout, cancellationToken).ConfigureAwait(false);
    }

    private static int SafeExitCode(Process process)
    {
        try { return process.ExitCode; } catch { return -1; }
    }
}

