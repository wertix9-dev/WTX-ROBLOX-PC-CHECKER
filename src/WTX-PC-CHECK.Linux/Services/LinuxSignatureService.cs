using WtxPcCheck.Models;

namespace WtxPcCheck.Services;

public static class SignatureService
{
    public static SignatureInfo Verify(string path, bool checkRevocation = false)
    {
        if (!File.Exists(path))
            return new SignatureInfo
            {
                Status = SignatureStatus.Error,
                StatusText = "File missing",
                Detail = "The file no longer exists at this path."
            };

        return new SignatureInfo
        {
            Status = SignatureStatus.NotChecked,
            StatusText = "Signature not checked on Linux",
            Detail = "Windows Authenticode verification is not available in this Linux build. The file was not executed. Use a trusted publisher source or Windows for Authenticode review."
        };
    }
}

