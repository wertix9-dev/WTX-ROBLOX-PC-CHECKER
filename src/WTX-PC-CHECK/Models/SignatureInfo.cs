namespace WtxPcCheck.Models;

public enum SignatureStatus
{
    NotChecked,
    Valid,
    Unsigned,
    Invalid,
    Error
}

public sealed class SignatureInfo
{
    public SignatureStatus Status { get; init; } = SignatureStatus.NotChecked;
    public string StatusText { get; init; } = "Not checked";
    public string? Subject { get; init; }
    public string? Issuer { get; init; }
    public string? ThumbprintSha256 { get; init; }
    public DateTime? NotBefore { get; init; }
    public DateTime? NotAfter { get; init; }
    public string? Detail { get; init; }
    public bool IsValid => Status == SignatureStatus.Valid;

    public static SignatureInfo NotChecked(string reason) => new()
    {
        Status = SignatureStatus.NotChecked,
        StatusText = "Not checked",
        Detail = reason
    };

    public string PublisherDisplay => Subject ?? "No publisher certificate available";

    public string ValidityDisplay => NotBefore is null || NotAfter is null
        ? "Not available"
        : $"{AppFormat.Date(NotBefore.Value)} to {AppFormat.Date(NotAfter.Value)}";
}
