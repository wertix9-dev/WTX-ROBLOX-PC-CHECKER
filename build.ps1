param(
    [string]$Dotnet = "dotnet",
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    Write-Host "WTX PC CHECK build" -ForegroundColor Cyan
    Write-Host "Using .NET host: $Dotnet"
    try {
        $versionText = (& $Dotnet --version 2>&1 | Out-String).Trim()
    }
    catch {
        throw "The .NET SDK was not found. Install the .NET 10 SDK from https://dot.net and run this script again."
    }

    Write-Host ".NET SDK: $versionText"
    if ($versionText -notmatch '^10\.') {
        throw "This project targets .NET 10. Install the .NET 10 SDK (the global.json file pins this requirement), then run the build again."
    }

    $publishDirectory = Join-Path $root "publish"
    New-Item -ItemType Directory -Force -Path $publishDirectory | Out-Null
    $target = Join-Path $publishDirectory "WTX-PC-CHECK.exe"
    if (Test-Path $target) { Remove-Item -LiteralPath $target -Force }

    & $Dotnet publish (Join-Path $root "src\WTX-PC-CHECK\WTX-PC-CHECK.csproj") `
        -c Release `
        -r win-x64 `
        --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true `
        -p:DebugType=none `
        -p:DebugSymbols=false `
        -o $publishDirectory

    if (-not (Test-Path $target)) {
        throw "The publish completed without producing $target."
    }

    $file = Get-Item -LiteralPath $target
    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Write-Host ""
    Write-Host "Build complete." -ForegroundColor Green
    Write-Host "EXE:  $target"
    Write-Host "Size: $([math]::Round($file.Length / 1MB, 1)) MB"
    Write-Host "SHA-256: $hash"

    if ($SelfTest) {
        $testOutput = Join-Path $root "selftest.txt"
        $process = Start-Process -FilePath $target -ArgumentList @("--self-test", $testOutput) -Wait -PassThru
        if (Test-Path $testOutput) { Get-Content -LiteralPath $testOutput }
        if ($process.ExitCode -ne 0) { throw "Self-test failed with exit code $($process.ExitCode)." }
        Write-Host "Self-test: PASS" -ForegroundColor Green
    }
}
finally {
    Pop-Location
}
