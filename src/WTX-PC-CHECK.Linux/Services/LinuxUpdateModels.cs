using System.IO;

namespace WtxPcCheck.Linux.Services;

public sealed class LinuxUpdateConfiguration
{
    public string ManifestUrl { get; init; } = AppInfo.UpdateManifestUrl;
    public string GpgKeyPath { get; init; } = "REPLACE_WITH_ABSOLUTE_PATH_TO_GPG_PUBLIC_KEY";
    public string ExpectedFingerprint { get; init; } = "REPLACE_WITH_40_HEX_GPG_FINGERPRINT";
    public string PublisherName { get; init; } = "WERTIX";

    public bool IsConfigured => Validate(out _);

    public bool Validate(out string reason)
    {
        if (!Uri.TryCreate(ManifestUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            uri.Host.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase) ||
            ManifestUrl.Contains("REPLACE_", StringComparison.OrdinalIgnoreCase))
        {
            reason = "The Linux update source is not configured. The maintainer must provide a real HTTPS update manifest URL.";
            return false;
        }
        if (GpgKeyPath.Contains("REPLACE_", StringComparison.OrdinalIgnoreCase) || !File.Exists(GpgKeyPath))
        {
            reason = "The Linux update signing public key is not configured or cannot be read.";
            return false;
        }
        var fingerprint = NormalizeFingerprint(ExpectedFingerprint);
        if (fingerprint.Length != 40 || !fingerprint.All(Uri.IsHexDigit) ||
            ExpectedFingerprint.Contains("REPLACE_", StringComparison.OrdinalIgnoreCase))
        {
            reason = "The expected Linux update signing fingerprint is still a placeholder or is not a 40-hex OpenPGP fingerprint.";
            return false;
        }
        if (LinuxProcessRunner.FindExecutable("gpg") is null)
        {
            reason = "GnuPG (gpg) is required to verify Linux update signatures but was not found. No update will be installed.";
            return false;
        }
        reason = string.Empty;
        return true;
    }

    public string ExpectedFingerprintNormalized => NormalizeFingerprint(ExpectedFingerprint);

    public static string NormalizeFingerprint(string? value)
        => new string((value ?? string.Empty).Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
}

public sealed class LinuxUpdateManifest
{
    public string Version { get; init; } = string.Empty;
    public string Url { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public string SignatureUrl { get; init; } = string.Empty;
    public string GpgFingerprint { get; init; } = string.Empty;
    public string Publisher { get; init; } = string.Empty;
    public string ReleaseNotes { get; init; } = string.Empty;
}

public enum LinuxUpdateState
{
    Idle,
    Disabled,
    NotConfigured,
    Checking,
    UpToDate,
    UpdateAvailable,
    Downloading,
    ReadyToInstall,
    Failed
}

public sealed class LinuxUpdateSnapshot
{
    public LinuxUpdateState State { get; init; } = LinuxUpdateState.Idle;
    public string Message { get; init; } = "Not checked yet.";
    public string? Version { get; init; }
    public double? ProgressPercent { get; init; }
    public long BytesReceived { get; init; }
    public long? TotalBytes { get; init; }
    public string? StagedPath { get; init; }
    public string? Sha256 { get; init; }
    public string? ReleaseNotes { get; init; }
    public DateTimeOffset? CheckedUtc { get; init; }
}
