using System.IO;

namespace WtxPcCheck.Services;

public sealed class UpdateConfiguration
{
    public string ManifestUrl { get; init; } = AppInfo.UpdateManifestUrl;
    public string SignerThumbprint { get; init; } = AppInfo.UpdateSignerThumbprint;
    public string PublisherName { get; init; } = AppInfo.UpdatePublisherName;

    public bool IsConfigured => Validate(out _);

    public bool Validate(out string reason)
    {
        if (!Uri.TryCreate(ManifestUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            reason = "The update manifest URL is not a valid HTTPS URL without embedded credentials.";
            return false;
        }

        if (uri.Host.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.Equals("example.com", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.Contains("example.", StringComparison.OrdinalIgnoreCase) ||
            ManifestUrl.Contains("REPLACE_", StringComparison.OrdinalIgnoreCase))
        {
            reason = "The update source is still a placeholder. The maintainer must provide the real HTTPS update URL.";
            return false;
        }

        var thumbprint = NormalizeThumbprint(SignerThumbprint);
        if (thumbprint.Length != 64 || !thumbprint.All(Uri.IsHexDigit) ||
            SignerThumbprint.Contains("REPLACE_", StringComparison.OrdinalIgnoreCase))
        {
            reason = "The update signing certificate thumbprint is still a placeholder or is not a SHA-256 thumbprint (64 hex characters).";
            return false;
        }

        if (string.IsNullOrWhiteSpace(PublisherName) || PublisherName.Contains("REPLACE_", StringComparison.OrdinalIgnoreCase))
        {
            reason = "The expected update publisher name is not configured.";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    public string ExpectedThumbprint => NormalizeThumbprint(SignerThumbprint);

    public static string NormalizeThumbprint(string? value)
        => new string((value ?? string.Empty).Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
}

