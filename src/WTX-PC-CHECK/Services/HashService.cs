using System.IO;
using System.Security.Cryptography;

namespace WtxPcCheck.Services;

public sealed class HashResult
{
    public bool Success { get; init; }
    public string? Sha256 { get; init; }
    public string Note { get; init; } = string.Empty;
}

public static class HashService
{
    public const long MaxHashBytes = 256L * 1024 * 1024;

    public static HashResult TryComputeSha256(string path, long knownLength, CancellationToken cancellationToken, long maxBytes = MaxHashBytes)
    {
        if (knownLength > maxBytes)
            return new HashResult { Note = "Hash not computed because the file is larger than the allowed limit." };

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                1024 * 1024,
                FileOptions.SequentialScan);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1024 * 1024];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                hash.AppendData(buffer, 0, read);
            }
            return new HashResult
            {
                Success = true,
                Sha256 = Convert.ToHexString(hash.GetHashAndReset())
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new HashResult { Note = "Hash not computed because the file could not be read." };
        }
    }
}

