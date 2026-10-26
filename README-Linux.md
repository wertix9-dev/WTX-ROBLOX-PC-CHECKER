# WTX PC CHECK for Linux

**Made by WERTIX**

WTX PC CHECK is a local, defensive PC checker for Linux x64. It keeps the existing Roblox and Minecraft scan categories and adds Linux-native, read-only security checks. The Windows build remains available as `WTX-PC-CHECK.exe`.

## Download and run

Actual Linux packages built for this release:

| Package | Path | SHA-256 |
|---|---|---|
| AppImage (recommended for Bazzite) | `publish/linux/packages/WTX-PC-CHECK-1.2.0-x86_64.AppImage` | `E2C90CA7FA9E4AE46696C1EDB8B2DB028A20F77CA427731679092F68910AA381` |
| Portable archive (any x64 distro) | `publish/linux/packages/WTX-PC-CHECK-1.2.0-linux-x64.tar.gz` | `81EAEDA3E37F661519D11708B20A99F82D665B35C7CFBA7ADF72D8C2378FD880` |
| Debian package (Kali and compatible) | `publish/linux/packages/wtx-pc-check_1.2.0_amd64.deb` | `2E758F0E7DFD465B21A2C42AB72FC57FBF91C2FF56A829BC8B91C3B2582504BB` |

AppImage:

```bash
chmod +x WTX-PC-CHECK-1.2.0-x86_64.AppImage
./WTX-PC-CHECK-1.2.0-x86_64.AppImage
```

If FUSE 2 is unavailable, use the portable archive or:

```bash
APPIMAGE_EXTRACT_AND_RUN=1 ./WTX-PC-CHECK-1.2.0-x86_64.AppImage
```

Portable archive:

```bash
tar -xzf WTX-PC-CHECK-1.2.0-linux-x64.tar.gz
cd WTX-PC-CHECK-1.2.0-linux-x64
./WTX-PC-CHECK
```

Debian/Kali:

```bash
sudo apt install ./wtx-pc-check_1.2.0_amd64.deb
wtx-pc-check
```

Do not use `rpm-ostree` layering on Bazzite. Use the AppImage or archive.

## Verified targets and status

- Explicit target distributions: **Bazzite** and **Kali Linux**, x64.
- Other mainstream Linux x64 distributions are best-effort only. They are not claimed as verified.
- The packages were built on Ubuntu 24.04 in GitHub Actions. The Linux self-test passed, and both the AppImage and the installed `.deb` passed an Xvfb GUI startup smoke test.
- Bazzite and Kali were not available as live test machines in this environment. Their package advice is therefore target guidance, not a claim of runtime verification.
- No Flatpak package is provided. The `.deb` and AppImage do not use a sandbox. If you run the app from a sandboxed environment, only the files and processes visible to that sandbox can be checked.

## Desktop and graphics

- X11 is supported directly.
- On Wayland desktops, the app uses Avalonia's Linux X11 path through XWayland where the desktop provides it. Native Wayland is not claimed.
- Typical runtime libraries: X11, XCB, XKB, XRandR, XInput, fontconfig, FreeType, HarfBuzz, and OpenGL/EGL. The `.deb` declares its package dependencies. The AppImage and archive are self-contained for .NET but still use the desktop's graphics and font libraries.

## Linux scanning

- Roblox and Minecraft categories remain separate, with Lua/Luau and JAR/mod checks separate from each other.
- Roblox paths are discovered only when present: Sober and Vinegar Flatpak data, native Sober data, Wine prefixes with Roblox, and common user folders. Paths are shown for confirmation and can be deselected. Add custom folders through the visible folder picker.
- Minecraft paths include `~/.minecraft`, Prism Launcher, Modrinth, MultiMC, ATLauncher, Technic, GDLauncher, their Flatpak equivalents, and custom folders. No launcher layout is assumed.
- JAR inspection is read-only ZIP metadata/entry inspection. Archives are never extracted to disk or executed. Limits: 100 MB archive, 20,000 entries, 512 KB per metadata entry, 500 MB total uncompressed.
- `.lua`/`.luau` files are read as static text only for up to 256 KB per file. They are never executed.
- Linux ELF publisher signatures are not verified in this build. Signature results clearly state that limitation instead of pretending Windows Authenticode was checked.
- The process snapshot reads `/proc` names and executable links only. It never reads process memory. The list is capped at 120 entries.
- Startup entries come from XDG autostart and user systemd units. System services, scheduled tasks, and protected locations are not claimed.
- Firewall status uses read-only `ufw`/`firewalld`/systemd checks when accessible. Update status uses a read-only APT simulation on Debian-family systems and `rpm-ostree status` on Bazzite-like systems; WTX PC CHECK never installs, updates, or changes packages.
- No root access is requested. Anything unavailable to the current user is reported as restricted or unavailable.

## ClamAV

- If `clamscan` or `clamdscan` is already installed, the Linux app offers a read-only ClamAV scan of the selected locations.
- WTX PC CHECK does not install ClamAV, update its database, or make ClamAV a requirement for game-specific scans.
- ClamAV detections are reported with the actual path and signature, classified as **Malware Detected by Local Scanner**. They are not invented or treated as proof beyond ClamAV's own result.
- If ClamAV is not installed, the app explains the limitation. It does not substitute Windows Defender results.

## Privacy and updater

- Scan data, file names, paths, hashes, contents, and results are never uploaded.
- Results are in memory only. Closing results or exiting discards them. No scan history, telemetry, or crash reports are stored.
- Linux preferences are stored at `${XDG_CONFIG_HOME:-~/.config}/wtx-pc-check/settings.json`.
- The Linux updater is platform-aware:
  - It verifies HTTPS, SHA-256, and a detached OpenPGP signature against a configured fingerprint before staging an update.
  - Only a user-owned AppImage can be replaced automatically after the user approves a restart.
  - `.deb` and archive installations are never silently replaced; the app tells the user to use the normal package manager or replace the archive.
  - No update is applied without a valid signature and an explicit restart confirmation.
- No real Linux update URL, OpenPGP public key, or signing key is bundled. `src/WTX-PC-CHECK.Linux/Services/LinuxUpdateModels.cs` contains clearly marked placeholders. The Linux updater remains disabled until the maintainer configures them.
- Windows keeps its existing Authenticode-based updater placeholders in `src/WTX-PC-CHECK/AppInfo.cs`.

## Linux limitations

- Linux is not a verified runtime target for every distribution. Bazzite and Kali are the explicit targets; other distributions are best-effort.
- Wayland native support is not claimed; XWayland is used where available.
- Files hidden by sandboxing, permissions, mounts, or kernel restrictions may not be readable.
- Linux process publisher signatures and ELF signatures are not checked. Windows Authenticode is unavailable on Linux.
- ClamAV is optional, and its signature database is owned by ClamAV.
- Bazzite is image-based; WTX PC CHECK does not provide or query rpm-ostree updates and does not layer packages.
- AppImage requires FUSE 2 for direct execution unless extract-and-run mode is used.
- The Linux app currently uses Avalonia for the Linux presentation layer. The Windows WPF interface is preserved to keep the tested Windows behavior and `WTX-PC-CHECK.exe` unchanged. The scanner core, models, JAR analysis, indicator database, and privacy behavior are shared.

## Build Linux packages

The reproducible packager is `.github/workflows/linux-build.yml`. It publishes the self-contained `linux-x64` app, runs the Linux self-test, builds the AppImage, tar.gz, and `.deb`, runs Xvfb GUI smoke tests for the AppImage and installed `.deb`, and uploads the artifacts.

Manual Linux build outline:

```bash
dotnet publish src/WTX-PC-CHECK.Linux/WTX-PC-CHECK.Linux.csproj \
  -c Release -r linux-x64 --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true \
  -o publish/linux/app
```

Then use the AppDir/package steps in the workflow with `appimagetool` and `dpkg-deb`.

Self-test:

```bash
./publish/linux/app/WTX-PC-CHECK --self-test ./linux-selftest.txt
```
