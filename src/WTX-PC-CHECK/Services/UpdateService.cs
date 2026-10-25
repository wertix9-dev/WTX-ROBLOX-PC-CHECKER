using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public sealed class UpdateProgress
{
    public string Status { get; init; } = string.Empty;
    public long BytesReceived { get; init; }
    public long? TotalBytes { get; init; }
    public double? Percent { get; init; }
}

public sealed class UpdateService : IDisposable
{
    private const long MaxManifestBytes = 128 * 1024;
    private const long MaxUpdateBytes = 500L * 1024 * 1024;
    private readonly UpdateConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public UpdateService(UpdateConfiguration configuration)
    {
        _configuration = configuration;
        _httpClient = new HttpClient
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"WTX-PC-CHECK/{AppInfo.Version}");
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public UpdateConfiguration Configuration => _configuration;

    public async Task<UpdateCheckOutcome> CheckOnlyAsync(CancellationToken cancellationToken)
    {
        if (!_configuration.IsConfigured)
        {
            _configuration.Validate(out var reason);
            return new UpdateCheckOutcome
            {
                NotConfigured = true,
                Message = $"Automatic updates are not configured in this build. {reason} The app can still be used offline."
            };
        }

        UpdateManifest? manifest;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(25));
        try
        {
            manifest = await ReadManifestAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new UpdateCheckOutcome { Message = "The update check timed out. The app can continue offline." };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new UpdateCheckOutcome
            {
                Message = "The update server could not be reached or its response could not be read. The app can continue offline."
            };
        }

        if (manifest is null)
            return new UpdateCheckOutcome { Message = "The update manifest was not valid. No update was downloaded." };

        var invalid = ValidateManifest(manifest);
        if (invalid is not null) return new UpdateCheckOutcome { Message = invalid };

        if (!VersionUtil.IsNewer(manifest.Version, AppInfo.Version))
        {
            return new UpdateCheckOutcome
            {
                Succeeded = true,
                UpdateAvailable = false,
                Manifest = manifest,
                Message = $"WTX PC CHECK {AppInfo.Version} is up to date. The update server lists version {manifest.Version}."
            };
        }

        return new UpdateCheckOutcome
        {
            Succeeded = true,
            UpdateAvailable = true,
            Manifest = manifest,
            Message = $"Update {manifest.Version} is available."
        };
    }

    public async Task<UpdateCheckOutcome> CheckAndStageAsync(
        IProgress<UpdateProgress>? progress,
        CancellationToken cancellationToken)
    {
        var check = await CheckOnlyAsync(cancellationToken).ConfigureAwait(false);
        if (!check.Succeeded || !check.UpdateAvailable || check.Manifest is null) return check;
        return await DownloadAndStageAsync(check.Manifest, progress, cancellationToken).ConfigureAwait(false);
    }

    public async Task<UpdateCheckOutcome> DownloadAndStageAsync(
        UpdateManifest manifest,
        IProgress<UpdateProgress>? progress,
        CancellationToken cancellationToken)
    {
        var invalid = ValidateManifest(manifest);
        if (invalid is not null) return new UpdateCheckOutcome { Message = invalid };
        if (!Uri.TryCreate(manifest.Url, UriKind.Absolute, out var downloadUri)) return new UpdateCheckOutcome { Message = "The update download URL was not valid." };

        var stagingDirectory = Path.Combine(AppPaths.UpdateWorkDirectory, Guid.NewGuid().ToString("N"));
        var safeVersion = new string(manifest.Version.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_').ToArray());
        if (string.IsNullOrWhiteSpace(safeVersion)) safeVersion = "update";
        var stagedPath = Path.Combine(stagingDirectory, $"WTX-PC-CHECK-{safeVersion}.exe");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(20));
        try
        {
            Directory.CreateDirectory(stagingDirectory);
            progress?.Report(new UpdateProgress { Status = "Downloading the verified update…" });
            var download = await DownloadAsync(downloadUri, stagedPath, progress, timeout.Token).ConfigureAwait(false);
            if (!download.Success)
            {
                CleanupStaging(stagingDirectory);
                return new UpdateCheckOutcome { Message = download.Message };
            }

            var expectedHash = new string(manifest.Sha256.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
            if (expectedHash.Length != 64 || !string.Equals(download.Sha256, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                CleanupStaging(stagingDirectory);
                return new UpdateCheckOutcome { Message = "The downloaded update did not match the SHA-256 hash in the manifest. It was discarded." };
            }

            progress?.Report(new UpdateProgress { Status = "Verifying the publisher signature…" });
            var signature = SignatureService.Verify(stagedPath, checkRevocation: true);
            var actualThumbprint = UpdateConfiguration.NormalizeThumbprint(signature.ThumbprintSha256);
            if (signature.Status != SignatureStatus.Valid ||
                actualThumbprint.Length != 64 ||
                actualThumbprint != _configuration.ExpectedThumbprint)
            {
                CleanupStaging(stagingDirectory);
                return new UpdateCheckOutcome
                {
                    Message = "The downloaded update is not validly signed by the configured publisher. It was rejected and will not be installed."
                };
            }

            var fileVersion = ReadFileVersion(stagedPath);
            if (fileVersion is not null && fileVersion != VersionUtil.TryParse(manifest.Version))
            {
                CleanupStaging(stagingDirectory);
                return new UpdateCheckOutcome
                {
                    Message = "The downloaded update's file version does not match the update manifest. It was rejected."
                };
            }

            return new UpdateCheckOutcome
            {
                Succeeded = true,
                UpdateAvailable = true,
                Message = $"Update {manifest.Version} was downloaded and its publisher signature was verified.",
                Manifest = manifest,
                StagedExePath = stagedPath,
                StagedSha256 = download.Sha256,
                StagedBytes = download.Bytes
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            CleanupStaging(stagingDirectory);
            return new UpdateCheckOutcome { Message = "The update download timed out. The app can continue offline." };
        }
        catch (OperationCanceledException)
        {
            CleanupStaging(stagingDirectory);
            throw;
        }
        catch
        {
            CleanupStaging(stagingDirectory);
            return new UpdateCheckOutcome
            {
                Message = "The update could not be downloaded or verified. No update was installed."
            };
        }
    }

    private string? ValidateManifest(UpdateManifest manifest)
    {
        if (VersionUtil.TryParse(manifest.Version) is null)
            return "The update manifest contains an invalid version number.";

        if (!Uri.TryCreate(manifest.Url, UriKind.Absolute, out var downloadUri) ||
            downloadUri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(downloadUri.UserInfo))
            return "The update download URL is not a valid HTTPS address. The update was rejected.";

        if (UpdateConfiguration.NormalizeThumbprint(manifest.SignerThumbprint) != _configuration.ExpectedThumbprint)
            return "The update manifest does not match the configured signing certificate thumbprint. The update was rejected.";

        if (!string.IsNullOrWhiteSpace(manifest.Publisher) &&
            !manifest.Publisher.Equals(_configuration.PublisherName, StringComparison.OrdinalIgnoreCase))
            return "The update manifest does not match the configured publisher. The update was rejected.";

        if (manifest.Sha256.Length != 64 || !manifest.Sha256.All(Uri.IsHexDigit))
            return "The update manifest does not contain a valid SHA-256 hash.";

        return null;
    }

    public static void CleanupOldStaging()
    {
        try
        {
            if (!Directory.Exists(AppPaths.UpdateWorkDirectory)) return;
            foreach (var directory in Directory.GetDirectories(AppPaths.UpdateWorkDirectory))
            {
                try
                {
                    if (Directory.GetLastWriteTimeUtc(directory) < DateTime.UtcNow.AddDays(-1))
                        Directory.Delete(directory, true);
                }
                catch { }
            }
        }
        catch { }
    }

    public static void CleanupStaging(string? stagedPath)
    {
        if (string.IsNullOrWhiteSpace(stagedPath)) return;
        try
        {
            var directory = Path.GetDirectoryName(stagedPath);
            if (directory is not null &&
                directory.StartsWith(AppPaths.UpdateWorkDirectory, StringComparison.OrdinalIgnoreCase) &&
                Directory.Exists(directory))
            {
                Directory.Delete(directory, true);
            }
        }
        catch { }
    }

    private async Task<UpdateManifest?> ReadManifestAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(
            _configuration.ManifestUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps)
            throw new InvalidDataException("Update redirect was not HTTPS.");
        if (response.Content.Headers.ContentLength > MaxManifestBytes)
            throw new InvalidDataException("Update manifest was too large.");

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var memory = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (memory.Length + read > MaxManifestBytes)
                throw new InvalidDataException("Update manifest was too large.");
            memory.Write(buffer, 0, read);
        }
        memory.Position = 0;
        return await JsonSerializer.DeserializeAsync<UpdateManifest>(memory, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }, cancellationToken).ConfigureAwait(false);
    }

    private sealed class DownloadOutcome
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public string Sha256 { get; init; } = string.Empty;
        public long Bytes { get; init; }
    }

    private async Task<DownloadOutcome> DownloadAsync(
        Uri uri,
        string destination,
        IProgress<UpdateProgress>? progress,
        CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps)
            return new DownloadOutcome { Message = "The update download was redirected away from HTTPS. It was rejected." };

        var total = response.Content.Headers.ContentLength;
        if (total > MaxUpdateBytes)
            return new DownloadOutcome { Message = "The update file is larger than the allowed limit. It was rejected." };

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
            if (received > MaxUpdateBytes)
                return new DownloadOutcome { Message = "The update file exceeded the allowed size. It was rejected." };
            await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            hash.AppendData(buffer, 0, read);

            if (received - lastReport > 512 * 1024)
            {
                lastReport = received;
                progress?.Report(new UpdateProgress
                {
                    Status = "Downloading the verified update…",
                    BytesReceived = received,
                    TotalBytes = total,
                    Percent = total is > 0 ? Math.Min(100, received * 100.0 / total.Value) : null
                });
            }
        }
        await target.FlushAsync(cancellationToken).ConfigureAwait(false);
        return new DownloadOutcome
        {
            Success = true,
            Sha256 = Convert.ToHexString(hash.GetHashAndReset()),
            Bytes = received
        };
    }

    private static Version? ReadFileVersion(string path)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            return VersionUtil.TryParse(info.FileVersion) ?? VersionUtil.TryParse(info.ProductVersion);
        }
        catch
        {
            return null;
        }
    }

    public void Dispose() => _httpClient.Dispose();
}





