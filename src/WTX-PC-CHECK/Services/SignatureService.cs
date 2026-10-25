using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public static class SignatureService
{
    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const int WtdUiNone = 2;
    private const int WtdRevokeNone = 0;
    private const int WtdRevokeWholeChain = 1;
    private const int WtdChoiceFile = 1;
    private const int WtdStateActionVerify = 1;
    private const int WtdStateActionClose = 2;
    private const int WtdCacheOnlyUrlRetrieval = 0x1000;
    private const int WtdDisableMd2Md4 = 0x2000;
    private const int WtdRevocationCheckChain = 0x40;

    public static SignatureInfo Verify(string path, bool checkRevocation = false)
    {
        if (!File.Exists(path))
            return new SignatureInfo
            {
                Status = SignatureStatus.Error,
                StatusText = "File missing",
                Detail = "The file no longer exists at this path."
            };

        X509Certificate2? certificate = null;
        try
        {
#pragma warning disable SYSLIB0057
            var raw = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            certificate = new X509Certificate2(raw);
        }
        catch
        {
            certificate = null;
        }

        try
        {
            var result = VerifyWithWinTrust(path, checkRevocation);
            if (result == 0)
            {
                var detail = certificate is null
                    ? "A valid signature was verified through a Windows catalog. The embedded publisher certificate was not available."
                    : "The Authenticode signature was verified by Windows.";
                return new SignatureInfo
                {
                    Status = SignatureStatus.Valid,
                    StatusText = certificate is null ? "Valid (catalog-signed)" : "Valid signature",
                    Subject = certificate?.Subject,
                    Issuer = certificate?.Issuer,
                    ThumbprintSha256 = certificate?.GetCertHashString(HashAlgorithmName.SHA256),
                    NotBefore = certificate?.NotBefore,
                    NotAfter = certificate?.NotAfter,
                    Detail = detail
                };
            }

            if (unchecked((uint)result) == 0x800B0100)
            {
                return new SignatureInfo
                {
                    Status = SignatureStatus.Unsigned,
                    StatusText = "Not digitally signed",
                    Detail = "Windows found no Authenticode signature for this file."
                };
            }

            return new SignatureInfo
            {
                Status = SignatureStatus.Invalid,
                StatusText = "Signature not valid",
                Subject = certificate?.Subject,
                Issuer = certificate?.Issuer,
                ThumbprintSha256 = certificate?.GetCertHashString(HashAlgorithmName.SHA256),
                NotBefore = certificate?.NotBefore,
                NotAfter = certificate?.NotAfter,
                Detail = DescribeError(result)
            };
        }
        catch
        {
            return new SignatureInfo
            {
                Status = SignatureStatus.Error,
                StatusText = "Signature check failed",
                Detail = "Windows could not complete the signature check for this file."
            };
        }
        finally
        {
            certificate?.Dispose();
        }
    }

    private static int VerifyWithWinTrust(string path, bool checkRevocation)
    {
        var filePathPtr = IntPtr.Zero;
        var fileInfoPtr = IntPtr.Zero;
        try
        {
            filePathPtr = Marshal.StringToHGlobalUni(path);
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = filePathPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var trustData = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = checkRevocation ? WtdRevokeWholeChain : WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = fileInfoPtr,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdDisableMd2Md4 |
                              (checkRevocation ? WtdRevocationCheckChain : WtdCacheOnlyUrlRetrieval)
            };

            var action = WinTrustActionGenericVerifyV2;
            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            trustData.dwStateAction = WtdStateActionClose;
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            return result;
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPtr);
            if (filePathPtr != IntPtr.Zero) Marshal.FreeHGlobal(filePathPtr);
        }
    }

    private static string DescribeError(int result) => unchecked((uint)result) switch
    {
        0x800B0109 => "The signing certificate is not trusted on this PC.",
        0x800B0101 => "The signing certificate has expired.",
        0x800B010C => "The signing certificate has been revoked.",
        0x80096010 => "The file contents do not match the signature.",
        0x800B0111 => "The signature is explicitly distrusted by Windows.",
        0x80092026 => "Windows security settings blocked signature verification.",
        0x800B0004 => "The subject is not trusted for the requested action.",
        0x800B010A => "The signing certificate chain could not be validated.",
        0x800B0110 => "The signing certificate is not valid for code signing.",
        0x800B0003 => "The signature format is not recognized.",
        _ => "Windows reports that the signature is not valid."
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public int dwUIChoice;
        public int fdwRevocationChecks;
        public int dwUnionChoice;
        public IntPtr pFile;
        public int dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public int dwProvFlags;
        public int dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        ref Guid pgActionID,
        ref WinTrustData pWVTData);
}


