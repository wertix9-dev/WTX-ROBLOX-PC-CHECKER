using System.Text.RegularExpressions;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using WtxPcCheck.Models;
using WtxPcCheck.Services;

namespace WtxPcCheck.Linux.Services;

public sealed class LinuxUpdateProgress
{
    public string Status { get; init; } = string.Empty;
    public long BytesReceived { get; init; }
    public long? TotalBytes { get; init; }
    public double? Percent { get; init; }
}

public sealed class LinuxUpdateResult
{
    public bool Succeeded { get; init; }
    public bool UpdateAvailable { get; init; }
    public bool NotConfigured { get; init; }
    public string Message { get; init; } = string.Empty;
    public LinuxUpdateManifest? Manifest { get; init; }
    public string? StagedPath { get; init; }
    public string? Sha256 { get; init; }
    public bool Installable { get; init; }
}

public sealed class LinuxUpdateService : IDisposable
{
    private readonly LinuxUpdateConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public LinuxUpdateService(LinuxUpdateConfiguration configuration)
    {
        _configuration = configuration;
        _httpClient = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"WTX-PC-CHECK/{AppInfo.Version}");
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public LinuxUpdateConfiguration Configuration => _configuration;

    public async Task<LinuxUpdateResult> CheckAndStageAsync(IProgress<LinuxUpdateProgress>? progress, CancellationToken cancellationToken)
    {
        if (!_configuration.IsConfigured)
        {
            _configuration.Validate(out var reason);
            return new LinuxUpdateResult
            {
                NotConfigured = true,
                Message = $"Automatic updates are not configured for this Linux build. {reason} The app can still be used offline."
            };
        }

        LinuxUpdateManifest? manifest;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(25));
        try
        {
            manifest = await ReadManifestAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new LinuxUpdateResult { Message = "The Linux update check timed out. The app can continue offline." };
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return new LinuxUpdateResult { Message = "The Linux update server could not be reached. The app can continue offline." };
        }

        if (manifest is null || VersionUtil.TryParse(manifest.Version) is null)
            return new LinuxUpdateResult { Message = "The Linux update manifest was not valid." };

        if (!Uri.TryCreate(manifest.Url, UriKind.Absolute, out var downloadUri) || downloadUri.Scheme != Uri.UriSchemeHttps ||
            !Uri.TryCreate(manifest.SignatureUrl, UriKind.Absolute, out var signatureUri) || signatureUri.Scheme != Uri.UriSchemeHttps)
            return new LinuxUpdateResult { Message = "The Linux update manifest does not contain valid HTTPS download and signature URLs." };

        if (manifest.Sha256.Length != 64 || !manifest.Sha256.All(Uri.IsHexDigit))
            return new LinuxUpdateResult { Message = "The Linux update manifest does not contain a valid SHA-256 hash." };

        if (LinuxUpdateConfiguration.NormalizeFingerprint(manifest.GpgFingerprint) != _configuration.ExpectedFingerprintNormalized)
            return new LinuxUpdateResult { Message = "The Linux update manifest does not match the configured GPG signing fingerprint. The update was rejected." };

        if (!VersionUtil.IsNewer(manifest.Version, AppInfo.Version))
        {
            return new LinuxUpdateResult
            {
                Succeeded = true,
                UpdateAvailable = false,
                Manifest = manifest,
                Message = $"WTX PC CHECK {AppInfo.Version} is up to date. The update server lists version {manifest.Version}."
            };
        }

        if (!LinuxPaths.IsAppImage)
        {
            return new LinuxUpdateResult
            {
                Succeeded = true,
                UpdateAvailable = true,
                Manifest = manifest,
                Installable = false,
                Message = $"Update {manifest.Version} is available. This installation is not an AppImage, so WTX PC CHECK will not replace package-manager or archive files. Update through your normal package manager or replace the archive manually."
            };
        }

        Directory.CreateDirectory(LinuxPaths.UpdateWorkDirectory);
        var stagingDirectory = Path.Combine(LinuxPaths.UpdateWorkDirectory, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stagingDirectory);
        var safeVersion = new string(manifest.Version.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_').ToArray());
        var stagedPath = Path.Combine(stagingDirectory, $"WTX-PC-CHECK-{safeVersion}.AppImage");
        var signaturePath = stagedPath + ".sig";

        try
        {
            progress?.Report(new LinuxUpdateProgress { Status = "Downloading the verified Linux update..." });
            var download = await DownloadAsync(downloadUri, stagedPath, progress, cancellationToken).ConfigureAwait(false);
            if (!download.Success)
            {
                Cleanup(stagingDirectory);
                return new LinuxUpdateResult { Message = download.Message };
            }
            if (!string.Equals(download.Sha256, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                Cleanup(stagingDirectory);
                return new LinuxUpdateResult { Message = "The Linux update did not match the manifest SHA-256 hash and was discarded." };
            }

            var signatureDownload = await DownloadSmallAsync(signatureUri, signaturePath, cancellationToken).ConfigureAwait(false);
            if (!signatureDownload)
            {
                Cleanup(stagingDirectory);
                return new LinuxUpdateResult { Message = "The Linux update signature could not be downloaded. The update was rejected." };
            }

            progress?.Report(new LinuxUpdateProgress { Status = "Verifying the OpenPGP signature..." });
            if (!await VerifyDetachedSignatureAsync(stagedPath, signaturePath, cancellationToken).ConfigureAwait(false))
            {
                Cleanup(stagingDirectory);
                return new LinuxUpdateResult { Message = "The Linux update does not have a valid OpenPGP signature from the configured publisher. It was rejected." };
            }

            return new LinuxUpdateResult
            {
                Succeeded = true,
                UpdateAvailable = true,
                Installable = true,
                Manifest = manifest,
                StagedPath = stagedPath,
                Sha256 = download.Sha256,
                Message = $"Update {manifest.Version} was downloaded and its OpenPGP signature was verified."
            };
        }
        catch (OperationCanceledException)
        {
            Cleanup(stagingDirectory);
            throw;
        }
        catch
        {
            Cleanup(stagingDirectory);
            return new LinuxUpdateResult { Message = "The Linux update could not be downloaded or verified. No update was installed." };
        }
    }

    public async Task<(bool Started, string ErrorEnglish)> StartApplyAsync(string stagedPath, string sha256, string version, CancellationToken cancellationToken)
    {
        try
        {
            if (LinuxPaths.AppImagePath is null)
                return (false, "This installation is not running from an AppImage. Update through your package manager or replace the archive manually.");
            if (!File.Exists(stagedPath))
                return (false, "The staged Linux update is no longer available.");
            var hash = HashService.TryComputeSha256(stagedPath, new FileInfo(stagedPath).Length, cancellationToken, 500L * 1024 * 1024);
            if (!hash.Success || !string.Equals(hash.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
                return (false, "The staged Linux update failed its final hash verification. Nothing was installed.");
            var signaturePath = stagedPath + ".sig";
            if (!File.Exists(signaturePath) || !await VerifyDetachedSignatureAsync(stagedPath, signaturePath, cancellationToken).ConfigureAwait(false))
                return (false, "The staged Linux update failed its final OpenPGP verification. Nothing was installed.");

            var target = LinuxPaths.AppImagePath;
            var backup = target + ".previous";
            var scriptPath = Path.Combine(Path.GetDirectoryName(stagedPath)!, "apply-update.sh");
            var script = """
                #!/bin/sh
                set -u
                PID="$1"; TARGET="$2"; STAGED="$3"; BACKUP="$4"
                while kill -0 "$PID" 2>/dev/null; do sleep 1; done
                cp "$TARGET" "$BACKUP" || exit 10
                cp "$STAGED" "$TARGET" || { cp "$BACKUP" "$TARGET"; exit 11; }
                chmod +x "$TARGET"
                "$TARGET" >/dev/null 2>&1 &
                NEWPID=$!
                sleep 6
                if kill -0 "$NEWPID" 2>/dev/null; then
                  rm -f "$BACKUP" "$STAGED" "$3.sig" "$0"
                  exit 0
                fi
                cp "$BACKUP" "$TARGET"
                "$TARGET" >/dev/null 2>&1 &
                exit 12
                """;
            await File.WriteAllTextAsync(scriptPath, script, cancellationToken).ConfigureAwait(false);
            var startInfo = new ProcessStartInfo
            {
                FileName = "/bin/sh",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add(scriptPath);
            startInfo.ArgumentList.Add(Environment.ProcessId.ToString());
            startInfo.ArgumentList.Add(target);
            startInfo.ArgumentList.Add(stagedPath);
            startInfo.ArgumentList.Add(backup);
            using var process = Process.Start(startInfo);
            return process is null
                ? (false, "The Linux update helper could not be started. Nothing was installed.")
                : (true, string.Empty);
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return (false, "The Linux update could not be prepared for installation. Nothing was installed.");
        }
    }

    private async Task<LinuxUpdateManifest?> ReadManifestAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(_configuration.ManifestUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps) return null;
        if (response.Content.Headers.ContentLength > 128 * 1024) return null;
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var memory = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (memory.Length + read > 128 * 1024) return null;
            memory.Write(buffer, 0, read);
        }
        memory.Position = 0;
        return await JsonSerializer.DeserializeAsync<LinuxUpdateManifest>(memory, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }, cancellationToken).ConfigureAwait(false);
    }

    private sealed class DownloadResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public string Sha256 { get; init; } = string.Empty;
    }

    private async Task<DownloadResult> DownloadAsync(Uri uri, string destination, IProgress<LinuxUpdateProgress>? progress, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps)
            return new DownloadResult { Message = "The Linux update download was redirected away from HTTPS and was rejected." };
        var total = response.Content.Headers.ContentLength;
        if (total > 500L * 1024 * 1024) return new DownloadResult { Message = "The Linux update is larger than the allowed limit." };
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, true);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long received = 0;
        var lastReport = 0L;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            received += read;
            if (received > 500L * 1024 * 1024) return new DownloadResult { Message = "The Linux update exceeded the allowed size." };
            await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            hash.AppendData(buffer, 0, read);
            if (received - lastReport > 512 * 1024)
            {
                lastReport = received;
                progress?.Report(new LinuxUpdateProgress
                {
                    Status = "Downloading the verified Linux update...",
                    BytesReceived = received,
                    TotalBytes = total,
                    Percent = total is > 0 ? Math.Min(100, received * 100.0 / total.Value) : null
                });
            }
        }
        await target.FlushAsync(cancellationToken).ConfigureAwait(false);
        return new DownloadResult { Success = true, Sha256 = Convert.ToHexString(hash.GetHashAndReset()) };
    }

    private async Task<bool> DownloadSmallAsync(Uri uri, string destination, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) return false;
        if (response.Content.Headers.ContentLength > 128 * 1024) return false;
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (bytes.Length > 128 * 1024) return false;
        await File.WriteAllBytesAsync(destination, bytes, cancellationToken).ConfigureAwait(false);
        return true;
    }

    private async Task<bool> VerifyDetachedSignatureAsync(string file, string signature, CancellationToken cancellationToken)
    {
        var gpg = LinuxProcessRunner.FindExecutable("gpg");
        if (gpg is null) return false;
        var home = Path.Combine(Path.GetTempPath(), "wtx-pc-check-gpg-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(home);
            var import = await LinuxProcessRunner.RunAsync(gpg,
                ["--batch", "--homedir", home, "--import", _configuration.GpgKeyPath],
                TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
            if (!import.Started || import.ExitCode != 0) return false;
            var verify = await LinuxProcessRunner.RunAsync(gpg,
                ["--batch", "--homedir", home, "--status-fd", "1", "--verify", signature, file],
                TimeSpan.FromSeconds(20), cancellationToken).ConfigureAwait(false);
            if (!verify.Started || verify.ExitCode != 0) return false;
            var match = Regex.Match(verify.StandardOutput, @"\[GNUPG:\]\s+VALIDSIG\s+([0-9A-F]+)");
            return match.Success &&
                   match.Groups[1].Value.Equals(_configuration.ExpectedFingerprintNormalized, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
        finally
        {
            try { Directory.Delete(home, true); } catch { }
        }
    }

    private static void Cleanup(string directory)
    {
        try { Directory.Delete(directory, true); } catch { }
    }

    public void Dispose() => _httpClient.Dispose();
}

