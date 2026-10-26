using System.Diagnostics;
using System.Text;

namespace WtxPcCheck.Linux.Services;

public sealed class LinuxProcessResult
{
    public bool Started { get; init; }
    public bool TimedOut { get; init; }
    public int ExitCode { get; init; } = -1;
    public string StandardOutput { get; init; } = string.Empty;
    public string StandardError { get; init; } = string.Empty;
}

public static class LinuxProcessRunner
{
    public static async Task<LinuxProcessResult> RunAsync(
        string fileName,
        IEnumerable<string> arguments,
        TimeSpan? timeout,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? environment = null)
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
        startInfo.Environment["LANG"] = "C";
        startInfo.Environment["LC_ALL"] = "C";
        if (environment is not null)
        {
            foreach (var pair in environment) startInfo.Environment[pair.Key] = pair.Value;
        }
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start()) return new LinuxProcessResult { Started = false };
        }
        catch
        {
            return new LinuxProcessResult { Started = false };
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
        int exitCode = -1;
        if (!timedOut)
        {
            try { exitCode = process.ExitCode; } catch { }
        }
        return new LinuxProcessResult
        {
            Started = true,
            TimedOut = timedOut,
            ExitCode = exitCode,
            StandardOutput = stdout,
            StandardError = stderr
        };
    }

    public static string? FindExecutable(string name)
    {
        if (Path.IsPathRooted(name) && File.Exists(name)) return name;
        var path = Environment.GetEnvironmentVariable("PATH") ?? "/usr/local/bin:/usr/bin:/bin";
        var directories = path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).ToList();
        directories.AddRange(["/usr/local/sbin", "/usr/sbin", "/sbin"]);
        foreach (var directory in directories.Distinct())
        {
            var candidate = Path.Combine(directory, name);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}

