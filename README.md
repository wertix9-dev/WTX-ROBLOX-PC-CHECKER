# WTX PC CHECK

**Made by WERTIX**

WTX PC CHECK is a defensive, local PC-check application for Windows 10 version 22H2 and Windows 11 on x64. It helps users review selected locations for Roblox executor indicators, Minecraft cheat-client indicators and mods, and signs of malware, including trojans. It is built to support a safer, fairer gaming community.

The application is built with C#, WPF, and .NET 10. It does not execute, modify, delete, move, or quarantine discovered files, and it never guarantees that a PC is clean.

GitHub repository name from the project setup: **WTX ROBLOX PC CHECKER**.

## Run the published application

The self-contained single-file executable is at:

`publish\WTX-PC-CHECK.exe`

Double-click it, or run from PowerShell:

```powershell
.\publish\WTX-PC-CHECK.exe
```

It is self-contained for Windows x64; the user does not need to install .NET or WPF. No administrator elevation is requested.

Delivered binary for this build:

- **Size:** 61,609,057 bytes (58.8 MB)
- **SHA-256:** `B5A12ECAEC2411BA6E3EB24DDA5E3ED6499F9E0603C139618802FC22422EB3D6`

The delivered EXE is not Authenticode-signed because no code-signing certificate or key was provided. Windows SmartScreen may warn about an unknown publisher. Update packages themselves are still rejected unless they have a valid signature from the configured pinned publisher certificate.

## Build from source

Requirements:

- Windows 10 version 22H2 or Windows 11, x64
- .NET 10 SDK (the repository includes a `global.json` that requires 10.0.100 or a later 10.x feature band)
- No Visual Studio requirement; the .NET SDK is enough.

From the repository root:

```powershell
.\build.ps1
```

Or directly:

```powershell
dotnet publish .\src\WTX-PC-CHECK\WTX-PC-CHECK.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -p:DebugSymbols=false -o .\publish
```

Output:

`publish\WTX-PC-CHECK.exe`

The build is a single-file, self-contained publish. `IncludeNativeLibrariesForSelfExtract` is required by WPF's native components; .NET extracts those native files to a temporary directory at start-up.

## Navigation and start-up

- Animated start-up screen with **WTX PC CHECK**, **Made by WERTIX**, a lightweight scan ring, and real English status messages such as **Loading settings...** and **Checking for updates...**.
- No fake percentages and no artificial delay. The splash closes as soon as settings and the optional update check are ready. Failures are explained and the app continues offline.
- Left navigation rail: **Dashboard**, **Roblox PC Check**, **Minecraft PC Check**, **Full PC Check**, **Settings**, **About**.
- The About page repeats the branding, version, privacy, purpose, detection limits, and update configuration placeholders.

## Scan profiles, categories, and locations

Available profiles:

- **Roblox Scan** - Roblox indicators and Lua review in detected Roblox/common folders.
- **Minecraft Scan** - Minecraft JAR/mod review and known cheat-client indicators in detected Minecraft/launcher/common folders.
- **Quick Scan** - all file categories in common and detected game folders, without scanning full drives.
- **Full PC Scan** - all categories on all selected fixed drives by default, with removable/network drives opt-in.
- **Custom Folder Scan** - only the folders the user adds, with selectable categories.

Users can select individual categories:

- Roblox executor programs and related components
- Lua and Luau script review
- Minecraft JAR files and mod folders
- Known Minecraft cheat-client indicators
- Windows security, startup entries, and running processes

Users can select locations before starting:

- Fixed, removable, and network drives. Full PC Scan selects all fixed drives by default; any drive can be deselected.
- Common user folders: Downloads, Desktop, and temporary files.
- Detected game/launcher folders. These are displayed with labels and paths and included only when checked.
- Custom folders added through the Windows folder picker.

The profile card explains exactly which categories and locations will be checked. A privacy confirmation is shown before every scan.

## Roblox checks

- Treats executors as standalone programs and possible associated components such as executable files and libraries.
- Uses explainable local indicators: file name, folder location, Roblox proxy-DLL patterns, Authenticode signature status, optional local SHA-256 indicators, and limited static Lua text.
- A file name or folder match is never presented as proof. Findings are classified as potentially suspicious unless a stronger local indicator is available.
- `.lua`/`.luau` scripts are reviewed separately as static text (up to 256 KB per file). Scripts are never executed and are not automatically classified as malware or an executor.
- Roblox folders are detected under the user profile and shown for confirmation; users can add any other folder.

## Minecraft checks

- Detects `.minecraft`, Prism Launcher, Modrinth launcher, MultiMC, ATLauncher, CurseForge, Technic, and GDLauncher folders when present, and shows them for confirmation.
- Inspects `.jar` archives statically as ZIP containers: manifest, Fabric/Quilt/Forge/NeoForge metadata, mod names, selected entry names, Java signature-entry presence, and known cheat-client tokens.
- Archives are never extracted to disk or executed.
- Limits: 100 MB archive size, 20,000 entries, 512 KB per metadata entry, 500 MB total uncompressed size. Unreadable, locked, cloud-only, oversized, or over-limit archives are listed separately as archives that could not be checked.
- Classifications include **Known Cheat Client**, **Potentially Suspicious**, **Malware Detected by Windows Security**, **Unknown File**, and **Likely Legitimate Mod**.
- An unfamiliar mod is not labelled malicious merely because it is unknown. A JAR with recognizable mod metadata and no known indicator is reported as a likely legitimate mod with a clear limitation; metadata is not a safety guarantee.

## Findings

Every finding includes:

- File name, full path, type, size, and modified date
- Risk level, classification, and confidence
- Evidence and a plain-English explanation
- Detection method and limitations
- Digital signature status when applicable
- SHA-256 when available

Actions:

- **View Details** opens a full review window.
- **Open File Location** opens File Explorer only after a warning and never runs the selected file.
- Lua/Luau findings can show a confirmation-gated, read-only script preview. Scripts are never executed.
- The app does not offer an action that runs, modifies, deletes, moves, or quarantines files.

## Windows security and processes

The app shows Windows version/build, Defender state, real-time protection, signature information, firewall profiles, Windows Update counts, startup entries, and a read-only running-process snapshot.

Running-process checks show:

- Process name and PID
- Executable path when Windows exposes it
- Publisher certificate subject and signature status
- Review rationale for known names, unsigned user-writable executables, or invalid signatures

Process checks use only process metadata, the executable path, and Authenticode verification. WTX PC CHECK does **not** inspect process memory, inject code, stop processes, or modify files. Protected processes may not expose a path, and the displayed list is capped with a visible note.

Startup entries are limited to common Run keys and Startup folders. Windows StartupApproved state, scheduled tasks, and services are not evaluated, so an existing entry may be disabled. Command lines are displayed as recorded and are not executed.

These checks are separate from file findings and never presented as confirmed malware.

## Windows Defender

- **Run Defender scan** starts a real Windows Defender custom scan of the selected local drives using `MpCmdRun.exe -ScanType 3 -DisableRemediation`.
- A custom Defender scan can take a long time; the app shows the current drive and elapsed time, and allows cancellation. Windows Defender scans can be cancelled but not paused.
- WTX PC CHECK reports Defender's exit status rather than inventing detection names.
- When Defender records detection resources after the scan, the app queries those records read-only and adds them as findings classified **Malware Detected by Windows Security**, with the actual resource path and Defender threat ID.
- If Defender details cannot be read, the app says so and offers **Open Windows Security**.
- WTX PC CHECK never changes Defender policy. Real-time protection may act according to Windows settings. No administrator prompt is raised.

## Pause and cancellation

- Local file scans can be paused and resumed at file boundaries; the scan line stops while paused and resumes only when scanning continues.
- Cancellation stops the current local scan and keeps any partial results with a clear incomplete label.
- The actual file count, folders checked, current path, finding count, and inaccessible count are shown. No percentage is invented.
- Inaccessible folders and files are reported with English reasons for permissions, locks, long paths, disconnected drives, and similar limitations.

## Privacy

- Files, names, paths, contents, hashes, findings, and scan reports are never uploaded or persisted by WTX PC CHECK.
- Results exist in memory until **Close results** is used or the app exits.
- The only persisted preferences are automatic-update choices, update interval, reduced-motion choice, and the last update-check time.
- Settings: `%LOCALAPPDATA%\WTX PC CHECK\settings.json`.
- Staging: `%TEMP%\WTX PC CHECK\updates`.
- No telemetry, analytics, crash reports, cloud hash lookup, or scan history.
- The only network requests made by the app itself are update checks/downloads against the configured HTTPS source. Windows Update and Defender may contact Microsoft according to Windows settings; no scan data is sent by WTX PC CHECK in those operations.

## Detection limits

- WTX PC CHECK is not an antivirus replacement and never guarantees that a PC is clean.
- Name, folder, and metadata matches can flag legitimate software. They are indicators, not proof.
- Executors and cheat clients can be renamed, packed, signed by another publisher, or missed entirely.
- Hash matching is implemented but inactive in this build until verified local hashes are added to `src/WTX-PC-CHECK/Data/KnownIndicators.json`.
- Signature verification is performed on flagged executable/library candidates, not every file on a drive.
- Lua analysis is a shallow static text search; obfuscation can hide behavior.
- JAR analysis inspects metadata and entry names only, not decompiled or executed bytecode. Encrypted or over-limit archives may not be checked.
- Files that are locked, encrypted, cloud-only, inside reparse-point folders, or blocked by permissions may not be inspected. Archives are not unpacked. Running processes are not memory-scanned.
- Windows Update classification and Defender-detail visibility depend on what Windows exposes to a non-elevated process.
- A clean result never proves that a PC is clean.

## Updater configuration placeholders

No real update URL, publisher certificate, or signing key is bundled. The following placeholders are in `src/WTX-PC-CHECK/AppInfo.cs`:

```csharp
public const string UpdateManifestUrl = "https://updates.example.invalid/wtx-pc-check/update-manifest.json";
public const string UpdateSignerThumbprint = "REPLACE_WITH_64_HEX_CHARACTER_SHA256_CERTIFICATE_THUMBPRINT";
public const string UpdatePublisherName = "WERTIX";
```

Update checking stays disabled while these placeholders remain. The UI reports **Not configured** and the app continues offline.

To enable updates, the maintainer must:

1. Obtain an Authenticode code-signing certificate for the intended publisher.
2. Sign the `WTX-PC-CHECK.exe` release with that certificate.
3. Set `UpdateManifestUrl` to a real HTTPS endpoint.
4. Set `UpdateSignerThumbprint` to the certificate's SHA-256 thumbprint (64 hex characters).
5. Serve a JSON manifest over HTTPS with this shape:

```json
{
  "version": "1.2.0",
  "url": "https://your-https-host.example/updates/WTX-PC-CHECK-1.2.0.exe",
  "sha256": "64_HEX_SHA256_OF_THE_EXE",
  "signerThumbprint": "64_HEX_SHA256_OF_THE_SIGNING_CERTIFICATE",
  "publisher": "WERTIX",
  "releaseNotes": "Text shown in the restart prompt.",
  "publishedUtc": "2026-10-25T12:00:00Z"
}
```

6. Rebuild with the real values.

The updater validates all of the following: newer manifest version, HTTPS download without embedded credentials, SHA-256, valid Authenticode signature, pinned signer certificate thumbprint, and matching file version. It stages the update in a temporary folder, asks before restarting, waits for the app to exit, backs up the EXE, replaces it, verifies the new app remains running, and restores the previous version if installation fails. A hash alone is never accepted as authenticity.

Windows code-signing credentials are not part of this repository and must not be committed.

## Indicator database

`src/WTX-PC-CHECK/Data/KnownIndicators.json` contains the local Roblox, Minecraft, proxy-DLL, and Lua heuristic lists. No verified malware hashes are bundled. Add only independently verified SHA-256 entries and rebuild. Name and metadata rules are heuristics, so keep their explanations and limitations intact.

## Project layout

```
src/WTX-PC-CHECK/                 WPF source
  Assets/AppIcon.ico
  Data/KnownIndicators.json
  Models/                        settings, findings, security, updates
  Services/                      scan engine, JAR analyzer, signatures, updater
  Themes/Theme.xaml
  ViewModels/MainViewModel.cs
  Views/                         splash, privacy, details, message dialogs
  MainWindow.xaml(.cs)
  Program.cs                     entry point and self-test mode
  SelfTest.cs
publish/WTX-PC-CHECK.exe          self-contained single-file build
build.ps1                         publish script
```

## Verification

The self-test covers version comparison, update configuration rejection, SHA-256 hashing, Authenticode verification, indicator loading, Roblox/Lua scan behavior, static Minecraft JAR analysis and classifications, inaccessible-root reporting, cancellation, safe Lua preview, disabled update source, rejection of unverified staged updates, and update-helper script parsing.

Manual checks during development included:

- Start-up and navigation, scan profiles, category and location presets
- Privacy gating before scans
- A real scan of a controlled drive containing Roblox/Lua and Minecraft JAR fixtures
- Permission-denied folders and archive-limit reporting
- Pause, resume, and cancel
- Finding details, read-only Lua preview, and File Explorer warning
- Read-only process snapshot and publisher signatures
- A real Windows Defender custom scan on a harmless folder
- Updater rollback with dummy binaries and settings persistence

A complete all-drive scan was not run during validation because it is long-running. A real signed network update was not exercised because no real update URL, publisher certificate, or signing key was provided. Defender detection-record parsing is implemented but was not triggered against live malware during validation.

## Attribution

Made by WERTIX. (c) 2026 WERTIX. No third-party packages beyond the .NET/WPF runtime.
