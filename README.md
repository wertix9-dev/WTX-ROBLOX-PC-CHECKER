# WTX ROBLOX PC CHECKER

**WTX PC CHECK - Made by WERTIX**

GitHub repository name: **WTX ROBLOX PC CHECKER**. The application and its executable keep the product name **WTX PC CHECK** (`WTX-PC-CHECK.exe`).

WTX PC CHECK is a defensive, local PC-check application for Windows 10 version 22H2 and Windows 11 on x64. It reviews selected drives for Roblox executor indicators, Lua script risk signals, and basic Windows security gaps, and explains the limits of every result.

The application is built with C#, WPF, and .NET 10. It never runs, modifies, deletes, moves, or quarantines a discovered file and never guarantees that a PC is clean.

## Run the published application

The self-contained single-file executable is at:

`publish\WTX-PC-CHECK.exe`

Double-click it, or run from PowerShell:

```powershell
.\publish\WTX-PC-CHECK.exe
```

It is self-contained for Windows x64; the user does not need to install .NET or WPF. No administrator elevation is requested.

Delivered binary for this build:

- Size: 61,583,683 bytes (58.7 MB)
- SHA-256: `4C625785DBA1053E44AC5ED15D00619649A80892EC8D1F05821DA9211AAAA0D3`

The delivered EXE is not Authenticode-signed because no code-signing certificate or key was provided for this build. Windows SmartScreen may therefore warn about an unknown publisher. Update packages themselves are still rejected unless they have a valid signature from the configured pinned publisher certificate.

## Build from source

Requirements:

- Windows 10 version 22H2 or Windows 11, x64
- .NET 10 SDK (the repository includes a `global.json` that requires 10.0.100 or a later 10.x feature band)
- No Visual Studio requirement; the .NET SDK is enough.

From the repository root:

```powershell
.\build.ps1
```

or directly:

```powershell
dotnet publish .\src\WTX-PC-CHECK\WTX-PC-CHECK.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -p:DebugSymbols=false -o .\publish
```

Output:

`publish\WTX-PC-CHECK.exe`

The build uses a single-file, self-contained publish. `IncludeNativeLibrariesForSelfExtract` is required by WPF's native components; those native files are extracted to a temporary directory by .NET at start-up.

## What is implemented

### Branding and start-up

- Animated start-up screen with **WTX PC CHECK**, **Made by WERTIX**, a lightweight scan-ring animation, and real start-up status messages.
- No invented percentage and no artificial start-up delay. The splash closes as soon as settings and the optional update check are finished.
- If update checking fails or the update source is not configured, the app continues offline and displays an English status message.

### Privacy confirmation

A blocking **Privacy & Purpose** dialog appears before every file scan and every Windows Defender scan. It contains the required purpose, data-handling, updater, and detection-limit text. **Start Scan** is disabled until **I understand and want to scan this PC** is checked.

### Scan

- Selects all fixed local drives by default. Removable and network drives can be selected explicitly.
- Recursively scans subfolders, including hidden and system files where Windows permits access.
- Reports the actual number of files and folders checked, elapsed time, current path, finding count, and inaccessible count.
- Records inaccessible files and folders with English reasons for permission denial, locks, long paths, disconnected drives, and similar limitations.
- Handles reparse-point folders safely (skips them and reports the count) and does not download cloud-only placeholder contents.
- Keeps all findings in memory only. There is no scan history page, no persisted finding list, no telemetry, no analytics, and no crash reporting.
- Reading a `.lua`/`.luau` file is limited to a static 256 KB text search. Scripts are never executed.

### Detection and review

- Explainable local indicators: executable names, folder locations, digital signatures, Roblox proxy-DLL names, optional SHA-256 matches, and Lua API-name patterns.
- `.lua` and `.luau` files are classified separately as **Script review**, not automatically as executors or malware.
- Each finding includes file name, full path, type, size, modified date, risk, explanation, detection method, limitations, signature status, and SHA-256 when available.
- **View Details** and **Open File Location** are provided. File Explorer is opened only after a warning; the app never runs the file.
- Script details include an optional read-only text preview. A confirmation is required, and the preview is never executed.

### Windows security overview

- Windows version and build.
- Defender status, real-time protection state, signature version, and optional tamper-protection state.
- Windows Firewall state for Domain, Private, and Public profiles.
- Pending updates offered by Windows Update, with security-update counts where Windows exposes them.
- Startup entries from common Run keys and Startup folders, with resolved executable path, signature status, and risk rationale. The app does not evaluate Windows StartupApproved state, scheduled tasks, or services, so an entry may be present but disabled. Startup command lines are shown as recorded and are not executed; only the executable path is resolved.
- These checks are shown separately from file findings and are not presented as confirmed malware.

### Windows Defender scans

- An explicit **Run Defender scan** action starts a real Windows Defender custom scan of the selected local drives using `MpCmdRun.exe -ScanType 3 -DisableRemediation`.
- A custom scan can be very long; progress text shows the current drive, drive count, and elapsed time. Cancellation is available.
- WTX PC CHECK reports Defender's exit result rather than inventing detection names. It tells the user to open Windows Security for Defender's own details. If the scan cannot start, the English explanation and **Open Windows Security** action are provided.
- Real-time protection may still act according to Windows settings; WTX PC CHECK does not change Defender policy and does not request administrator rights.

### Updater

- Configurable automatic update checks on start-up and every 1, 6, 12, or 24 hours.
- Automatic updates can be turned off in Settings. Manual checking remains available.
- Updates are downloaded only over HTTPS, with a maximum size, into a temporary staging directory.
- The updater verifies all of the following before staging:
  - the manifest version is newer;
  - the download URL is HTTPS without embedded credentials;
  - the SHA-256 hash matches;
  - the Authenticode signature is valid;
  - the signer certificate SHA-256 thumbprint matches the configured pin;
  - the file version matches the manifest.
- It asks before restarting. On approval, a helper waits for WTX PC CHECK to exit, backs up the current EXE, replaces it, starts the new version, and verifies that it remains running. On failure it restores and reopens the previous version.
- No update is installed covertly. No administrator prompt is raised.
- No scan data is sent to the update server. Requests contain only a user agent and the manifest/download request.

## Update source and signing configuration

**The update source is intentionally not configured in this delivery.** The following placeholders are present in `src/WTX-PC-CHECK/AppInfo.cs`:

```csharp
public const string UpdateManifestUrl = "https://updates.example.invalid/wtx-pc-check/update-manifest.json";
public const string UpdateSignerThumbprint = "REPLACE_WITH_64_HEX_CHARACTER_SHA256_CERTIFICATE_THUMBPRINT";
public const string UpdatePublisherName = "WERTIX";
```

No real URL, certificate, or signing key is bundled or invented. Update checking remains disabled while these placeholders are present; the UI reports **Not configured** and the app continues offline.

To enable signed updates, the maintainer must:

1. Obtain an Authenticode code-signing certificate whose subject corresponds to the intended publisher.
2. Sign the `WTX-PC-CHECK.exe` release with that certificate.
3. Set `UpdateManifestUrl` to a real HTTPS endpoint and `UpdateSignerThumbprint` to the certificate's SHA-256 thumbprint (64 hex characters).
4. Serve a JSON manifest over HTTPS with this shape:

```json
{
  "version": "1.1.0",
  "url": "https://your-https-host.example/updates/WTX-PC-CHECK-1.1.0.exe",
  "sha256": "64_HEX_SHA256_OF_THE_EXE",
  "signerThumbprint": "64_HEX_SHA256_OF_THE_SIGNING_CERTIFICATE",
  "publisher": "WERTIX",
  "releaseNotes": "Text shown in the restart prompt.",
  "publishedUtc": "2026-10-25T12:00:00Z"
}
```

5. Rebuild with the real values. Keep the update EXE and manifest on HTTPS.

The manifest itself is not signed; the EXE's Authenticode signature and the pinned certificate thumbprint are the authenticity boundary. A hash match alone is never accepted. Do not add a certificate pin that you have not verified independently.

Windows code signing credentials are not part of this repository and must not be committed.

## Known-hash list / indicator database

The scan engine supports SHA-256 matching, but **this build bundles no third-party malware hashes** and does not fetch a cloud hash list. `src/WTX-PC-CHECK/Data/KnownIndicators.json` currently has an empty `knownHashes` array. The UI clearly reports that hash matching is inactive.

Maintainers can add only independently verified entries and rebuild:

```json
{
  "sha256": "64_HEX_SHA256",
  "label": "Short explanation",
  "description": "Why this hash is an indicator.",
  "risk": "High"
}
```

Name, folder, proxy-DLL, and Lua API-name rules are heuristics. They are not proof that a file is an executor or malware. Keep the explanations and limitations intact when maintaining the list.

## Detection limits

- WTX PC CHECK is not an antivirus replacement and does not claim that a PC is clean.
- Name and folder matches can flag legitimate software. A file name alone is never treated as proof.
- Executor binaries can be renamed, packed, signed by another publisher, or missed entirely.
- Hash matching is inactive without a verified local list. No reputation or cloud analysis is used.
- Signature verification is performed on flagged executable/library candidates, not every file on the drive.
- Script analysis is static and shallow. Obfuscation can hide behavior; scripts are never executed.
- Files that are locked, encrypted, access-denied, cloud-only, inside reparse-point folders, or on disconnected drives may not be inspected. Archives are not unpacked, and running processes are not memory-scanned.
- Windows Update classification and Defender result details depend on what Windows exposes to a non-elevated process. The app reports counts and exit results, not fabricated detection names.
- The app does not modify, move, delete, or quarantine files. Defender's real-time protection can still act according to Windows settings.

## Privacy and local data

- Files, file names, paths, hashes, contents, findings, and scan reports are never uploaded or persisted by WTX PC CHECK.
- Results exist in memory until **Close results** is used or the app exits.
- The only persisted preferences are:
  - automatic updates on/off;
  - update interval;
  - reduced-motion choice;
  - timestamp of the last update check.
- Settings file: `%LOCALAPPDATA%\WTX PC CHECK\settings.json`.
- Update staging uses `%TEMP%\WTX PC CHECK\updates`.
- Windows Update and Defender may contact Microsoft according to Windows settings; the app sends no scan data in those operations.
- The updater may contact the configured HTTPS update source. Standard connection information may be visible to that server, but no scan data is sent.

## Project layout

```
src/WTX-PC-CHECK/                 WPF application source
  Assets/AppIcon.ico
  Data/KnownIndicators.json      local indicator database (no hashes bundled)
  Models/                        settings, drives, findings, security, updates
  Services/                      scanner, signatures, hashing, security, updater
  Themes/Theme.xaml              dark security dashboard theme
  ViewModels/MainViewModel.cs
  Views/                         splash, privacy, detail, and message dialogs
  MainWindow.xaml(.cs)
  Program.cs                     entry point and developer self-test modes
  SelfTest.cs
publish/WTX-PC-CHECK.exe          self-contained single-file build
build.ps1                        publish script
```

## Verification

The included self-test exercises version comparison, update configuration rejection, SHA-256 hashing, Authenticode verification, indicator loading, the scan engine on a harmless fixture, inaccessible-root reporting, cancellation, safe Lua preview, the disabled update source, rejection of unverified staged updates, and PowerShell parsing of the update helper script.

```powershell
$p = Start-Process .\publish\WTX-PC-CHECK.exe -ArgumentList '--self-test', '.\selftest.txt' -Wait -PassThru
Get-Content .\selftest.txt
if ($p.ExitCode -ne 0) { throw 'Self-test failed.' }
```

Manual checks performed during development: start-up, navigation, screen-reader-visible controls, privacy gating, a real scan of a harmless test drive, a permission-denied folder, secure script preview, finding details, a real Windows Defender custom scan on a harmless folder, updater rollback helper, and settings persistence. A real signed network update was not exercised because no real update URL, certificate, or signing key was provided.

## License and attribution

Made by WERTIX. © 2026 WERTIX. No third-party packages are used beyond the .NET/WPF runtime.




