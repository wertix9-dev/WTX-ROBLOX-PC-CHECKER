using System.Reflection;

namespace WtxPcCheck;

public static class AppInfo
{
    public const string ProductName = "WTX PC CHECK";
    public const string Publisher = "WERTIX";
    public const string Tagline = "Defensive PC check";
    public const string UpdateManifestUrl = "https://updates.example.invalid/wtx-pc-check/update-manifest.json";
    public const string UpdateSignerThumbprint = "REPLACE_WITH_64_HEX_CHARACTER_SHA256_CERTIFICATE_THUMBPRINT";
    public const string UpdatePublisherName = "WERTIX";

    public static string Version
    {
        get
        {
            var value = Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            if (!string.IsNullOrWhiteSpace(value))
            {
                var plus = value.IndexOf('+');
                return plus > 0 ? value[..plus] : value;
            }
            return Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";
        }
    }

    public static string VersionLabel => $"Version {Version}";
}
