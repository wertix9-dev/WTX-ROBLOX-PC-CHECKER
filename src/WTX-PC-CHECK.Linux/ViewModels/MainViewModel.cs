using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using WtxPcCheck.Models;
using WtxPcCheck.Services;
using WtxPcCheck.ViewModels;
using WtxPcCheck.Linux.Models;
using WtxPcCheck.Linux.Services;
using WtxPcCheck.Linux.Views;

namespace WtxPcCheck.Linux.ViewModels;

public sealed record LinuxNavItem(string Key, string Label, string Glyph);
public sealed record LinuxFindingFilter(string Key, string Label);

public enum LinuxScanState { Idle, Running, Completed, Cancelled, Failed }

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly LinuxSettingsService _settingsService = new();
    private readonly IndicatorDatabase _indicators = IndicatorDatabase.LoadEmbedded();
    private readonly ScanEngine _scanEngine;
    private readonly LinuxSecurityService _securityService;
    private readonly LinuxUpdateConfiguration _updateConfiguration = new();
    private readonly LinuxUpdateService _updateService;
    private readonly DispatcherTimer _scanTimer;
    private readonly DispatcherTimer _clamTimer;
    private readonly DispatcherTimer _updateTimer;

    private CancellationTokenSource? _scanCts;
    private CancellationTokenSource? _securityCts;
    private CancellationTokenSource? _clamCts;
    private CancellationTokenSource? _updateCts;
    private ScanPauseController? _pause;
    private Stopwatch? _scanStopwatch;
    private Stopwatch? _clamStopwatch;
    private bool _disposed;
    private bool _applyingProfile;
    private bool _suppressNavigationProfile;
    private int _scanSequence;

    private LinuxScanState _scanState;
    private bool _isPaused;
    private bool _isClamScanning;
    private bool _isSecurityChecking;
    private bool _hasScanOutcome;
    private bool _findingLimitReached;
    private long _filesChecked;
    private long _directoriesChecked;
    private int _inaccessibleCount;
    private string _currentPath = string.Empty;
    private string _scanElapsedText = "0s";
    private string _lastScanText = string.Empty;
    private string _scanSummaryText = string.Empty;
    private string _scanScopeDisplay = string.Empty;
    private string _scannedAreasDisplay = string.Empty;
    private string _scanConfigurationSummary = string.Empty;
    private string _archiveTruncationNote = string.Empty;
    private long _luaFilesChecked;
    private long _jarFilesChecked;
    private long _minecraftArchivesInspected;
    private long _minecraftModsReviewed;
    private long _hashChecksPerformed;
    private long _signatureChecksPerformed;
    private long _reparsePointsSkipped;
    private string _clamProgressText = string.Empty;
    private string _noticeText = string.Empty;
    private bool _hasNotice;
    private string _currentPageKey = "dashboard";
    private LinuxNavItem _selectedNav;
    private ScanProfileOption? _selectedProfile;
    private ScanProfileKind _activeProfile = ScanProfileKind.Full;
    private bool _scanRobloxExecutables = true;
    private bool _scanLuaScripts = true;
    private bool _scanMinecraftJars = true;
    private bool _detectMinecraftCheatIndicators = true;
    private bool _includeLinuxSecurity = true;
    private string _selectedFilterKey = "all";
    private LinuxSecurityOverview _security = new();
    private ClamAvStatus _clamAv = new();
    private ClamAvScanResult _clamResult = new();
    private LinuxUpdateSnapshot _update = new();
    private bool _updateBusy;
    private string? _stagedUpdatePath;
    private string? _stagedUpdateHash;
    private string? _stagedUpdateVersion;
    private string? _stagedUpdateNotes;
    private bool _deferredUpdatePrompt;

    public MainViewModel(AppSettings settings)
    {
        Settings = settings;
        _scanEngine = new ScanEngine(_indicators);
        _securityService = new LinuxSecurityService(_indicators);
        _updateService = new LinuxUpdateService(_updateConfiguration);

        NavigationItems =
        [
            new LinuxNavItem("dashboard", "Dashboard", "▦"),
            new LinuxNavItem("roblox", "Roblox PC Check", "R"),
            new LinuxNavItem("minecraft", "Minecraft PC Check", "M"),
            new LinuxNavItem("full", "Full PC Check", "◆"),
            new LinuxNavItem("settings", "Settings", "⚙"),
            new LinuxNavItem("about", "About", "i")
        ];
        _selectedNav = NavigationItems[0];
        ProfileOptions =
        [
            new ScanProfileOption(ScanProfileKind.Roblox, "Roblox Scan", "Roblox executor indicators and Lua review in selected Linux, Wine/Flatpak, and common folders."),
            new ScanProfileOption(ScanProfileKind.Minecraft, "Minecraft Scan", "Minecraft JAR/mod review and known cheat-client indicators in selected game and launcher folders."),
            new ScanProfileOption(ScanProfileKind.Quick, "Quick Scan", "All file categories in common and detected game folders, without scanning full mounts."),
            new ScanProfileOption(ScanProfileKind.Full, "Full PC Scan", "All categories across selected mounted filesystems by default."),
            new ScanProfileOption(ScanProfileKind.Custom, "Custom Folder Scan", "Only the folders you choose, with the categories you select.")
        ];
        _selectedProfile = ProfileOptions.First(p => p.Kind == ScanProfileKind.Full);
        FindingFilters =
        [
            new LinuxFindingFilter("all", "All"),
            new LinuxFindingFilter("roblox", "Roblox"),
            new LinuxFindingFilter("minecraft", "Minecraft"),
            new LinuxFindingFilter("known", "Known cheat"),
            new LinuxFindingFilter("suspicious", "Suspicious"),
            new LinuxFindingFilter("unknown", "Unknown / mods"),
            new LinuxFindingFilter("malware", "Malware")
        ];

        foreach (var folder in LinuxLocationService.DetectGameFolders())
        {
            folder.PropertyChanged += LocationOnPropertyChanged;
            GameFolders.Add(folder);
        }
        foreach (var folder in LinuxLocationService.DetectCommonFolders())
        {
            folder.PropertyChanged += LocationOnPropertyChanged;
            CommonFolders.Add(folder);
        }
        foreach (var mount in LinuxLocationService.DetectMounts())
        {
            mount.PropertyChanged += MountOnPropertyChanged;
            Mounts.Add(mount);
        }

        _scanTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _scanTimer.Tick += (_, _) => { if (_scanStopwatch is not null) ScanElapsedText = AppFormat.Duration(_scanStopwatch.Elapsed); };
        _clamTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clamTimer.Tick += (_, _) => { if (_clamStopwatch is not null && IsClamScanning) ClamProgressText = $"ClamAV is scanning the selected locations · {AppFormat.Duration(_clamStopwatch.Elapsed)}"; };
        _updateTimer = new DispatcherTimer();
        _updateTimer.Tick += async (_, _) => { if (AutomaticUpdates && !_updateBusy) await CheckForUpdatesAsync(true); };
        ConfigureUpdateTimer();

        StartScanCommand = new AsyncRelayCommand(StartScanAsync, () => !IsBusy);
        CancelScanCommand = new RelayCommand(CancelScan, () => IsScanning);
        PauseScanCommand = new RelayCommand(PauseScan, () => IsScanning && !IsPaused);
        ResumeScanCommand = new RelayCommand(ResumeScan, () => IsScanning && IsPaused);
        AddCustomFolderCommand = new AsyncRelayCommand(AddCustomFolderAsync, () => !IsBusy);
        RemoveCustomFolderCommand = new RelayCommand<ScanLocationOption>(RemoveCustomFolder, _ => !IsBusy);
        ClearLocationsCommand = new RelayCommand(ClearLocations, () => !IsBusy);
        SelectMountsCommand = new RelayCommand(SelectAllMounts, () => !IsBusy);
        RefreshSecurityCommand = new AsyncRelayCommand(RefreshSecurityAsync, () => !IsSecurityChecking);
        RunClamAvCommand = new AsyncRelayCommand(RunClamAvAsync, () => !IsBusy && ClamAv.Available);
        CancelClamAvCommand = new RelayCommand(CancelClamAv, () => IsClamScanning);
        ViewDetailsCommand = new RelayCommand<ScanFinding>(ViewDetails);
        OpenLocationCommand = new RelayCommand<ScanFinding>(OpenFindingLocation);
        OpenProcessLocationCommand = new RelayCommand<LinuxProcessInfo>(OpenProcessLocation);
        CloseResultsCommand = new RelayCommand(CloseResults, () => HasScanOutcome && !IsScanning);
        DismissNoticeCommand = new RelayCommand(() => HasNotice = false);
        CheckUpdatesCommand = new AsyncRelayCommand(() => CheckForUpdatesAsync(false), () => !_updateBusy);
        InstallUpdateCommand = new AsyncRelayCommand(InstallUpdateAsync, () => _stagedUpdatePath is not null && !IsBusy);
        NavigateScanCommand = new RelayCommand(OpenScanWorkspace);
        NavigateSettingsCommand = new RelayCommand(() => Navigate("settings"));
        StartFullScanSetupCommand = new RelayCommand(() => { ApplyProfilePreset(ScanProfileKind.Full, true, true); Navigate("full"); });
        OpenAppImageFolderCommand = new RelayCommand(OpenInstallLocation);

        ApplyProfilePreset(ScanProfileKind.Full, false, true);
        RefreshUpdateState();
    }

    public AppSettings Settings { get; }
    public IReadOnlyList<LinuxNavItem> NavigationItems { get; }
    public IReadOnlyList<ScanProfileOption> ProfileOptions { get; }
    public IReadOnlyList<LinuxFindingFilter> FindingFilters { get; }
    public ObservableCollection<ScanLocationOption> GameFolders { get; } = [];
    public ObservableCollection<ScanLocationOption> CommonFolders { get; } = [];
    public ObservableCollection<ScanLocationOption> CustomFolders { get; } = [];
    public ObservableCollection<LinuxMountOption> Mounts { get; } = [];
    public ObservableCollection<ScanFinding> Findings { get; } = [];
    public ObservableCollection<ScanFinding> FilteredFindings { get; } = [];
    public ObservableCollection<InaccessibleArea> InaccessibleAreas { get; } = [];
    public ObservableCollection<ArchiveIssue> ArchiveIssues { get; } = [];

    public AsyncRelayCommand StartScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand PauseScanCommand { get; }
    public RelayCommand ResumeScanCommand { get; }
    public AsyncRelayCommand AddCustomFolderCommand { get; }
    public RelayCommand<ScanLocationOption> RemoveCustomFolderCommand { get; }
    public RelayCommand ClearLocationsCommand { get; }
    public RelayCommand SelectMountsCommand { get; }
    public AsyncRelayCommand RefreshSecurityCommand { get; }
    public AsyncRelayCommand RunClamAvCommand { get; }
    public RelayCommand CancelClamAvCommand { get; }
    public RelayCommand<ScanFinding> ViewDetailsCommand { get; }
    public RelayCommand<ScanFinding> OpenLocationCommand { get; }
    public RelayCommand<LinuxProcessInfo> OpenProcessLocationCommand { get; }
    public RelayCommand CloseResultsCommand { get; }
    public RelayCommand DismissNoticeCommand { get; }
    public AsyncRelayCommand CheckUpdatesCommand { get; }
    public AsyncRelayCommand InstallUpdateCommand { get; }
    public RelayCommand NavigateScanCommand { get; }
    public RelayCommand NavigateSettingsCommand { get; }
    public RelayCommand StartFullScanSetupCommand { get; }
    public RelayCommand OpenAppImageFolderCommand { get; }

    public LinuxNavItem SelectedNav
    {
        get => _selectedNav;
        set
        {
            if (value is null || !SetProperty(ref _selectedNav, value)) return;
            CurrentPageKey = value.Key;
        }
    }

    public string CurrentPageKey
    {
        get => _currentPageKey;
        set
        {
            if (!SetProperty(ref _currentPageKey, value)) return;
            _selectedNav = NavigationItems.FirstOrDefault(n => n.Key == value) ?? _selectedNav;
            OnPropertyChanged(nameof(SelectedNav));
            OnPropertyChanged(nameof(IsDashboardPage));
            OnPropertyChanged(nameof(IsScanPage));
            OnPropertyChanged(nameof(IsSettingsPage));
            OnPropertyChanged(nameof(IsAboutPage));
            OnPropertyChanged(nameof(CurrentPageTitle));
            OnPropertyChanged(nameof(CurrentPageSubtitle));
            if (!_suppressNavigationProfile && value is "roblox" or "minecraft" or "full")
                ApplyProfilePreset(ProfileForPage(value), false, true);
        }
    }

    public bool IsDashboardPage => CurrentPageKey == "dashboard";
    public bool IsScanPage => CurrentPageKey is "roblox" or "minecraft" or "full";
    public bool IsSettingsPage => CurrentPageKey == "settings";
    public bool IsAboutPage => CurrentPageKey == "about";
    public string CurrentPageTitle => IsScanPage ? ActiveProfileTitle : CurrentPageKey switch
    {
        "settings" => "Settings",
        "about" => "About",
        _ => "Dashboard"
    };
    public string CurrentPageSubtitle => IsScanPage ? ActiveProfileDescription : CurrentPageKey switch
    {
        "settings" => "Updates, motion, and local preferences.",
        "about" => "Purpose, privacy, Linux limits, and update configuration.",
        _ => "A local, honest check of this PC."
    };

    public void Navigate(string key)
    {
        if (key is "dashboard" or "roblox" or "minecraft" or "full" or "settings" or "about")
            CurrentPageKey = key;
    }

    public void OpenScanWorkspace()
    {
        _suppressNavigationProfile = true;
        Navigate(PageForProfile(_activeProfile));
        _suppressNavigationProfile = false;
    }

    private static ScanProfileKind ProfileForPage(string key) => key switch
    {
        "roblox" => ScanProfileKind.Roblox,
        "minecraft" => ScanProfileKind.Minecraft,
        _ => ScanProfileKind.Full
    };

    private static string PageForProfile(ScanProfileKind kind) => kind switch
    {
        ScanProfileKind.Roblox => "roblox",
        ScanProfileKind.Minecraft => "minecraft",
        _ => "full"
    };

    public ScanProfileOption? SelectedProfile
    {
        get => _selectedProfile;
        set
        {
            if (value is null || ReferenceEquals(value, _selectedProfile)) return;
            _selectedProfile = value;
            OnPropertyChanged();
            ApplyProfilePreset(value.Kind, value.Kind is ScanProfileKind.Roblox or ScanProfileKind.Minecraft or ScanProfileKind.Full, true);
        }
    }

    public string ActiveProfileTitle => _selectedProfile?.Label ?? "Full PC Scan";
    public string ActiveProfileDescription => _selectedProfile?.Description ?? "Review this PC locally.";
    public ScanProfileKind ActiveProfileKind => _activeProfile;

    public void ApplyProfilePreset(ScanProfileKind kind, bool updatePage, bool resetSelections)
    {
        if (_applyingProfile) return;
        _applyingProfile = true;
        try
        {
            _activeProfile = kind;
            _selectedProfile = ProfileOptions.FirstOrDefault(p => p.Kind == kind) ?? _selectedProfile;
            OnPropertyChanged(nameof(SelectedProfile));
            OnPropertyChanged(nameof(ActiveProfileKind));
            OnPropertyChanged(nameof(ActiveProfileTitle));
            OnPropertyChanged(nameof(ActiveProfileDescription));
            OnPropertyChanged(nameof(CurrentPageTitle));
            OnPropertyChanged(nameof(CurrentPageSubtitle));
            if (updatePage)
            {
                _suppressNavigationProfile = true;
                Navigate(PageForProfile(kind));
                _suppressNavigationProfile = false;
            }
            if (!resetSelections) return;
            ScanRobloxExecutables = kind is ScanProfileKind.Roblox or ScanProfileKind.Quick or ScanProfileKind.Full or ScanProfileKind.Custom;
            ScanLuaScripts = ScanRobloxExecutables;
            ScanMinecraftJars = kind is ScanProfileKind.Minecraft or ScanProfileKind.Quick or ScanProfileKind.Full or ScanProfileKind.Custom;
            DetectMinecraftCheatIndicators = ScanMinecraftJars;
            IncludeLinuxSecurity = true;
            foreach (var mount in Mounts) mount.IsSelected = kind == ScanProfileKind.Full;
            foreach (var folder in CommonFolders) folder.IsSelected = kind != ScanProfileKind.Custom;
            foreach (var folder in GameFolders)
                folder.IsSelected = kind switch
                {
                    ScanProfileKind.Roblox => folder.Kind == ScanLocationKind.Roblox,
                    ScanProfileKind.Minecraft => folder.Kind == ScanLocationKind.Minecraft,
                    ScanProfileKind.Quick or ScanProfileKind.Full => true,
                    _ => false
                };
            RaiseScopeProperties();
        }
        finally
        {
            _applyingProfile = false;
        }
    }

    public bool ScanRobloxExecutables { get => _scanRobloxExecutables; set { if (SetProperty(ref _scanRobloxExecutables, value)) RaiseScopeProperties(); } }
    public bool ScanLuaScripts { get => _scanLuaScripts; set { if (SetProperty(ref _scanLuaScripts, value)) RaiseScopeProperties(); } }
    public bool ScanMinecraftJars { get => _scanMinecraftJars; set { if (SetProperty(ref _scanMinecraftJars, value)) RaiseScopeProperties(); } }
    public bool DetectMinecraftCheatIndicators { get => _detectMinecraftCheatIndicators; set { if (SetProperty(ref _detectMinecraftCheatIndicators, value)) RaiseScopeProperties(); } }
    public bool IncludeLinuxSecurity { get => _includeLinuxSecurity; set { if (SetProperty(ref _includeLinuxSecurity, value)) RaiseScopeProperties(); } }
    public bool HasSelectedFileCategories => ScanRobloxExecutables || ScanLuaScripts || ScanMinecraftJars || DetectMinecraftCheatIndicators;

    public string SelectedCategorySummary
    {
        get
        {
            var labels = new List<string>();
            if (ScanRobloxExecutables) labels.Add("Roblox executors/components");
            if (ScanLuaScripts) labels.Add("Lua script review");
            if (ScanMinecraftJars) labels.Add("Minecraft JAR/mod review");
            if (DetectMinecraftCheatIndicators) labels.Add("Known Minecraft cheat indicators");
            if (IncludeLinuxSecurity) labels.Add("Linux security/startup/processes");
            return labels.Count == 0 ? "No categories selected" : string.Join(" | ", labels);
        }
    }

    public string ProfileChecksSummary => $"{ActiveProfileDescription} {SelectedCategorySummary}. Locations: {SelectedScopeSummary}. A privacy confirmation appears before every scan.";
    public IReadOnlyList<ScanLocationOption> SelectedLocations => CommonFolders.Concat(GameFolders).Concat(CustomFolders).Where(l => l.IsSelected).ToList();
    public IReadOnlyList<string> SelectedRoots => BuildRoots();
    public string SelectedScopeSummary => SelectedRoots.Count == 0 ? "No locations selected" : $"{SelectedRoots.Count} location{(SelectedRoots.Count == 1 ? "" : "s")} selected";
    public string SelectedRootsDisplay => SelectedRoots.Count == 0 ? "No scan locations selected" : string.Join(", ", SelectedRoots);
    public bool HasScanLocations => SelectedRoots.Count > 0;
    public bool HasGameFolders => GameFolders.Count > 0;
    public bool HasCustomFolders => CustomFolders.Count > 0;

    private IReadOnlyList<string> BuildRoots()
    {
        var paths = new List<string>();
        paths.AddRange(Mounts.Where(m => m.IsSelected).Select(m => m.MountPoint));
        paths.AddRange(SelectedLocations.Select(l => l.Path));
        var result = new List<string>();
        foreach (var path in paths.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.Ordinal).OrderBy(p => p.Length))
        {
            if (result.Any(existing => IsSameOrChild(existing, path))) continue;
            result.Add(path);
        }
        return result;
    }

    private static bool IsSameOrChild(string parent, string candidate)
    {
        var p = parent.TrimEnd('/');
        var c = candidate.TrimEnd('/');
        return c.Equals(p, StringComparison.Ordinal) || c.StartsWith(p + "/", StringComparison.Ordinal);
    }

    private void MountOnPropertyChanged(object? sender, PropertyChangedEventArgs e) { if (e.PropertyName == nameof(LinuxMountOption.IsSelected)) RaiseScopeProperties(); }
    private void LocationOnPropertyChanged(object? sender, PropertyChangedEventArgs e) { if (e.PropertyName == nameof(ScanLocationOption.IsSelected)) RaiseScopeProperties(); }

    private void RaiseScopeProperties()
    {
        OnPropertyChanged(nameof(SelectedRoots));
        OnPropertyChanged(nameof(SelectedRootsDisplay));
        OnPropertyChanged(nameof(SelectedScopeSummary));
        OnPropertyChanged(nameof(HasScanLocations));
        OnPropertyChanged(nameof(SelectedCategorySummary));
        OnPropertyChanged(nameof(ProfileChecksSummary));
        StartScanCommand?.RaiseCanExecuteChanged();
    }

    private void SelectAllMounts() { foreach (var mount in Mounts) mount.IsSelected = true; RaiseScopeProperties(); }
    private void ClearLocations()
    {
        foreach (var mount in Mounts) mount.IsSelected = false;
        foreach (var folder in CommonFolders.Concat(GameFolders).Concat(CustomFolders)) folder.IsSelected = false;
        RaiseScopeProperties();
    }

    private async Task AddCustomFolderAsync()
    {
        var paths = await LinuxDialogs.PickFoldersAsync();
        foreach (var path in paths)
        {
            if (!Directory.Exists(path) || CustomFolders.Any(c => c.Path == path)) continue;
            var option = new ScanLocationOption
            {
                Label = Path.GetFileName(path.TrimEnd('/')),
                Path = path,
                Kind = ScanLocationKind.Custom,
                IsCustom = true,
                IsSelected = true
            };
            option.PropertyChanged += LocationOnPropertyChanged;
            CustomFolders.Add(option);
        }
        OnPropertyChanged(nameof(HasCustomFolders));
        RaiseScopeProperties();
    }

    private void RemoveCustomFolder(ScanLocationOption? folder)
    {
        if (folder is null) return;
        folder.PropertyChanged -= LocationOnPropertyChanged;
        CustomFolders.Remove(folder);
        OnPropertyChanged(nameof(HasCustomFolders));
        RaiseScopeProperties();
    }

    public bool IsBusy => IsScanning || IsClamScanning;
    public bool IsScanning => ScanState == LinuxScanState.Running;
    public LinuxScanState ScanState
    {
        get => _scanState;
        private set
        {
            if (!SetProperty(ref _scanState, value)) return;
            OnPropertyChanged(nameof(IsScanning));
            OnPropertyChanged(nameof(IsBusy));
            OnPropertyChanged(nameof(ScanActivityActive));
            OnPropertyChanged(nameof(ShowScanActivity));
            OnPropertyChanged(nameof(ScanStatusLabel));
            OnPropertyChanged(nameof(PcStatusLabel));
            OnPropertyChanged(nameof(PcStatusDetail));
            OnPropertyChanged(nameof(PcStatusTone));
            StartScanCommand?.RaiseCanExecuteChanged();
            CancelScanCommand?.RaiseCanExecuteChanged();
            PauseScanCommand?.RaiseCanExecuteChanged();
            ResumeScanCommand?.RaiseCanExecuteChanged();
            RunClamAvCommand?.RaiseCanExecuteChanged();
            CloseResultsCommand?.RaiseCanExecuteChanged();
        }
    }

    public bool IsPaused
    {
        get => _isPaused;
        private set
        {
            if (!SetProperty(ref _isPaused, value)) return;
            OnPropertyChanged(nameof(ScanActivityActive));
            OnPropertyChanged(nameof(ShowScanActivity));
            OnPropertyChanged(nameof(ScanStatusLabel));
            OnPropertyChanged(nameof(PcStatusLabel));
            OnPropertyChanged(nameof(PcStatusDetail));
            OnPropertyChanged(nameof(PcStatusTone));
            PauseScanCommand?.RaiseCanExecuteChanged();
            ResumeScanCommand?.RaiseCanExecuteChanged();
        }
    }

    public bool ScanActivityActive => IsScanning && !IsPaused;
    public bool ShowScanActivity => IsScanning && !IsPaused && !EffectiveReduceMotion;
    public bool HasScanOutcome { get => _hasScanOutcome; private set { if (SetProperty(ref _hasScanOutcome, value)) OnPropertyChanged(nameof(ShowResults)); } }
    public bool ShowResults => HasScanOutcome || Findings.Count > 0;
    public long FilesChecked { get => _filesChecked; private set { if (SetProperty(ref _filesChecked, value)) OnPropertyChanged(nameof(FilesCheckedText)); } }
    public string FilesCheckedText => AppFormat.Count(FilesChecked);
    public string DirectoriesCheckedText => AppFormat.Count(_directoriesChecked);
    public string InaccessibleCountText => AppFormat.Count(_inaccessibleCount);
    public string FindingCountText => AppFormat.Count(Findings.Count);
    public string HighCountText => AppFormat.Count(Findings.Count(f => f.Risk == RiskLevel.High));
    public string MediumCountText => AppFormat.Count(Findings.Count(f => f.Risk == RiskLevel.Medium));
    public string LowCountText => AppFormat.Count(Findings.Count(f => f.Risk is RiskLevel.Low or RiskLevel.Info));
    public string ScanElapsedText { get => _scanElapsedText; private set => SetProperty(ref _scanElapsedText, value); }
    public string CurrentPath { get => _currentPath; private set => SetProperty(ref _currentPath, value); }
    public string LastScanText { get => _lastScanText; private set => SetProperty(ref _lastScanText, value); }
    public string ScanSummaryText { get => _scanSummaryText; private set => SetProperty(ref _scanSummaryText, value); }
    public string ScanScopeDisplay { get => _scanScopeDisplay; private set => SetProperty(ref _scanScopeDisplay, value); }
    public string ScannedAreasDisplay { get => _scannedAreasDisplay; private set => SetProperty(ref _scannedAreasDisplay, value); }
    public string ScanConfigurationSummary { get => _scanConfigurationSummary; private set => SetProperty(ref _scanConfigurationSummary, value); }
    public string ArchiveTruncationNote { get => _archiveTruncationNote; private set => SetProperty(ref _archiveTruncationNote, value); }
    public int InaccessibleCount { get => _inaccessibleCount; private set { if (SetProperty(ref _inaccessibleCount, value)) OnPropertyChanged(nameof(InaccessibleCountText)); } }
    public string LuaFilesCheckedText => AppFormat.Count(_luaFilesChecked);
    public string JarFilesCheckedText => AppFormat.Count(_jarFilesChecked);
    public string MinecraftArchivesText => AppFormat.Count(_minecraftArchivesInspected);
    public string MinecraftModsReviewedText => AppFormat.Count(_minecraftModsReviewed);
    public string LiveScanMetrics => $"{LuaFilesCheckedText} Lua files checked | {JarFilesCheckedText} JAR files seen | {AppFormat.Count(_reparsePointsSkipped)} reparse points skipped";
    public string MinecraftSummaryText => _jarFilesChecked == 0
        ? "No Minecraft JAR archives were checked in this scan."
        : $"{JarFilesCheckedText} JAR files checked | {MinecraftArchivesText} archives inspected | {MinecraftModsReviewedText} mod review items | {AppFormat.Count(Findings.Count(f => f.Classification == FindingClassification.KnownCheatClient))} known cheat indicators";
    public bool HasMinecraftScanData => _jarFilesChecked > 0 || Findings.Any(f => f.Category == FindingCategory.MinecraftReview);
    public bool HasArchiveIssues => ArchiveIssues.Count > 0;
    public bool FindingLimitReached => _findingLimitReached;
    public string ArchiveIssueCountText => AppFormat.Count(ArchiveIssues.Count);

    public string ScanStatusLabel => ScanState switch
    {
        LinuxScanState.Running when IsPaused => "Paused",
        LinuxScanState.Running => "Scanning",
        LinuxScanState.Cancelled => "Scan incomplete",
        LinuxScanState.Failed => "Scan stopped",
        LinuxScanState.Completed => Findings.Count > 0 ? "Review needed" : "Scan finished",
        _ => "Not scanned"
    };
    public string PcStatusLabel => ScanState switch
    {
        LinuxScanState.Running when IsPaused => "Scan paused",
        LinuxScanState.Running => "Scan in progress",
        LinuxScanState.Cancelled => "Scan incomplete",
        LinuxScanState.Failed => "Scan stopped",
        LinuxScanState.Completed => Findings.Count > 0 ? "Review needed" : "No items flagged",
        _ => "Not checked yet"
    };
    public string PcStatusDetail => ScanState switch
    {
        LinuxScanState.Running when IsPaused => "The scan is paused. Resume to continue. Counts stop advancing while paused.",
        LinuxScanState.Running => "WTX PC CHECK is checking the selected Linux locations. Counts come from the running scan.",
        LinuxScanState.Completed when Findings.Count > 0 => $"{Findings.Count} review item{(Findings.Count == 1 ? "" : "s")} found. Indicators are not proof of malware, and a clean result is not guaranteed.",
        LinuxScanState.Completed => "No review indicators were flagged in accessible locations. This does not guarantee that the PC is clean.",
        LinuxScanState.Cancelled => "The scan was stopped before it finished. Results are partial.",
        LinuxScanState.Failed => "The scan stopped before completion. No conclusion about this PC can be drawn.",
        _ => "Select a profile and locations, then start a scan. WTX PC CHECK never guarantees a clean PC."
    };
    public string PcStatusTone => ScanState switch
    {
        LinuxScanState.Running when IsPaused => "Warning",
        LinuxScanState.Running => "Active",
        LinuxScanState.Completed when Findings.Count > 0 => "Warning",
        LinuxScanState.Completed => "Positive",
        LinuxScanState.Cancelled or LinuxScanState.Failed => "Danger",
        _ => "Neutral"
    };

    public string SelectedFilterKey
    {
        get => _selectedFilterKey;
        set { if (SetProperty(ref _selectedFilterKey, value)) ApplyFilter(); }
    }

    private void ApplyFilter()
    {
        FilteredFindings.Clear();
        foreach (var finding in Findings.Where(MatchesFilter)) FilteredFindings.Add(finding);
        OnPropertyChanged(nameof(HasVisibleFindings));
        OnPropertyChanged(nameof(FindingsEmptyText));
    }

    private bool MatchesFilter(ScanFinding finding) => SelectedFilterKey switch
    {
        "roblox" => finding.Category == FindingCategory.ExecutorIndicator,
        "minecraft" => finding.Category == FindingCategory.MinecraftReview,
        "known" => finding.Classification == FindingClassification.KnownCheatClient,
        "suspicious" => finding.Classification == FindingClassification.PotentiallySuspicious,
        "unknown" => finding.Classification is FindingClassification.UnknownFile or FindingClassification.LikelyLegitimateMod,
        "malware" => finding.Classification is FindingClassification.MalwareDetectedByWindowsSecurity or FindingClassification.MalwareDetectedByLocalScanner || finding.Category == FindingCategory.MalwareIndicator,
        _ => true
    };
    public bool HasVisibleFindings => FilteredFindings.Count > 0;
    public string FindingsEmptyText => Findings.Count == 0
        ? (IsScanning ? (IsPaused ? "The scan is paused. Resume to continue." : "Findings will appear here as the scan proceeds.") : HasScanOutcome ? "No items were flagged in this scan. This does not guarantee that the PC is clean." : "Run a scan to review files on this Linux PC.")
        : "No findings match this filter.";

    private async Task StartScanAsync()
    {
        if (IsBusy) return;
        if (!HasSelectedFileCategories && !IncludeLinuxSecurity)
        {
            await LinuxDialogs.ShowMessageAsync("Select a scan category", "Choose at least one file category or the Linux security category before starting.", "OK", null, true);
            return;
        }
        var roots = SelectedRoots;
        if (HasSelectedFileCategories && roots.Count == 0)
        {
            await LinuxDialogs.ShowMessageAsync("Select at least one location", "Choose a mount, detected game folder, common folder, or add a custom folder before starting.", "OK", null, true);
            return;
        }
        if (!await LinuxDialogs.ShowPrivacyAsync(EffectiveReduceMotion)) return;

        CloseResultsInternal();
        OpenScanWorkspace();
        ScanState = LinuxScanState.Running;
        IsPaused = false;
        HasScanOutcome = false;
        FilesChecked = 0;
        _directoriesChecked = 0;
        InaccessibleCount = 0;
        CurrentPath = string.Empty;
        ScanElapsedText = "0s";
        LastScanText = string.Empty;
        ScanSummaryText = string.Empty;
        _luaFilesChecked = 0;
        _jarFilesChecked = 0;
        _minecraftArchivesInspected = 0;
        _minecraftModsReviewed = 0;
        _hashChecksPerformed = 0;
        _signatureChecksPerformed = 0;
        _reparsePointsSkipped = 0;
        _findingLimitReached = false;
        ArchiveIssues.Clear();
        InaccessibleAreas.Clear();
        ScanScopeDisplay = roots.Count == 0 ? "Linux security check only" : string.Join(", ", roots);
        ScanConfigurationSummary = SelectedCategorySummary;
        _scanStopwatch = Stopwatch.StartNew();
        _scanTimer.Start();
        _pause = new ScanPauseController();
        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;
        var sequence = ++_scanSequence;
        var request = new ScanRequest
        {
            Roots = HasSelectedFileCategories ? roots : [],
            ScanRobloxExecutables = ScanRobloxExecutables,
            ScanLuaScripts = ScanLuaScripts,
            AnalyzeLuaContents = ScanLuaScripts,
            ScanMinecraftJars = ScanMinecraftJars,
            DetectMinecraftCheatIndicators = DetectMinecraftCheatIndicators,
            ReviewMinecraftJars = ScanMinecraftJars,
            MaxFindings = 1000,
            MaxMinecraftReviewFindings = 300
        };
        var progress = new Progress<ScanProgress>(value =>
        {
            if (sequence != _scanSequence || !IsScanning) return;
            FilesChecked = value.FilesChecked;
            _directoriesChecked = value.DirectoriesChecked;
            InaccessibleCount = value.InaccessibleCount;
            if (!string.IsNullOrWhiteSpace(value.CurrentPath)) CurrentPath = value.CurrentPath;
            ScanElapsedText = AppFormat.Duration(value.Elapsed);
            _luaFilesChecked = value.LuaFilesChecked;
            _jarFilesChecked = value.JarFilesChecked;
            _reparsePointsSkipped = value.ReparsePointsSkipped;
            OnPropertyChanged(nameof(LiveScanMetrics));
            OnPropertyChanged(nameof(LuaFilesCheckedText));
            OnPropertyChanged(nameof(JarFilesCheckedText));
            OnPropertyChanged(nameof(MinecraftSummaryText));
        });
        var findingProgress = new Progress<ScanFinding>(finding =>
        {
            if (sequence != _scanSequence || !IsScanning) return;
            Findings.Add(finding);
            ApplyFilter();
            RaiseFindingCounts();
        });
        ScanOutcome? outcome = null;
        try { outcome = await Task.Run(() => _scanEngine.Scan(request, progress, findingProgress, token, _pause), token); }
        catch (OperationCanceledException)
        {
            if (sequence == _scanSequence)
            {
                ScanState = LinuxScanState.Cancelled;
                ScanSummaryText = "The scan was cancelled before it could finish. Results are partial.";
                LastScanText = $"Stopped {AppFormat.Date(DateTime.Now)}";
                HasScanOutcome = true;
            }
        }
        catch
        {
            if (sequence == _scanSequence)
            {
                ScanState = LinuxScanState.Failed;
                ScanSummaryText = "The scan stopped because of an unexpected error. No conclusion about this PC can be drawn.";
                LastScanText = $"Stopped {AppFormat.Date(DateTime.Now)}";
                HasScanOutcome = true;
            }
        }
        finally
        {
            _scanTimer.Stop();
            _scanStopwatch?.Stop();
            _pause?.Dispose();
            _pause = null;
            IsPaused = false;
            _scanCts?.Dispose();
            _scanCts = null;
        }
        if (outcome is not null && sequence == _scanSequence) LoadOutcome(outcome);
        if (IncludeLinuxSecurity) _ = RefreshSecurityAsync();
        if (_deferredUpdatePrompt && !IsBusy) await PromptForUpdateRestartAsync();
    }

    private void LoadOutcome(ScanOutcome outcome)
    {
        ScanState = outcome.Cancelled ? LinuxScanState.Cancelled : outcome.Failed ? LinuxScanState.Failed : LinuxScanState.Completed;
        FilesChecked = outcome.FilesChecked;
        _directoriesChecked = outcome.DirectoriesChecked;
        InaccessibleCount = outcome.InaccessibleTotal;
        _luaFilesChecked = outcome.LuaFilesChecked;
        _jarFilesChecked = outcome.JarFilesChecked;
        _minecraftArchivesInspected = outcome.MinecraftArchivesInspected;
        _minecraftModsReviewed = outcome.MinecraftModsReviewed;
        _hashChecksPerformed = outcome.HashChecksPerformed;
        _signatureChecksPerformed = outcome.SignatureChecksPerformed;
        _reparsePointsSkipped = outcome.ReparsePointsSkipped;
        _findingLimitReached = outcome.FindingLimitReached;
        Findings.Clear();
        foreach (var finding in outcome.Findings.OrderByDescending(f => f.Risk).ThenBy(f => f.FileName, StringComparer.OrdinalIgnoreCase)) Findings.Add(finding);
        InaccessibleAreas.Clear();
        foreach (var area in outcome.InaccessibleAreas) InaccessibleAreas.Add(area);
        ArchiveIssues.Clear();
        foreach (var issue in outcome.ArchiveIssues) ArchiveIssues.Add(issue);
        ArchiveTruncationNote = outcome.ArchiveListTruncated ? "The archive issue list is capped; the total count is shown." : string.Empty;
        ApplyFilter();
        RaiseFindingCounts();
        HasScanOutcome = true;
        LastScanText = $"{(outcome.Cancelled ? "Stopped" : "Completed")} {AppFormat.Date(outcome.CompletedUtc)} | {AppFormat.Duration(outcome.Duration)}";
        ScannedAreasDisplay = string.Join(" | ", outcome.Roots);
        var inaccessibleNote = outcome.InaccessibleTotal > 0 ? $" {AppFormat.Count(outcome.InaccessibleTotal)} files/folders could not be fully read." : " No inaccessible items were reported.";
        var minecraftNote = outcome.JarFilesChecked > 0 ? $" Minecraft: {AppFormat.Count(outcome.MinecraftArchivesInspected)} JAR archives inspected, {AppFormat.Count(outcome.MinecraftModsReviewed)} mod review items." : string.Empty;
        var archiveNote = outcome.ArchiveIssueTotal > 0 ? $" {AppFormat.Count(outcome.ArchiveIssueTotal)} archives could not be checked." : string.Empty;
        ScanSummaryText = outcome.Cancelled
            ? $"The scan was cancelled after checking {AppFormat.Count(outcome.FilesChecked)} files. Results are partial.{inaccessibleNote}{archiveNote}"
            : $"Checked {AppFormat.Count(outcome.FilesChecked)} files in {AppFormat.Duration(outcome.Duration)}. {outcome.Findings.Count} item{(outcome.Findings.Count == 1 ? "" : "s")} were flagged.{minecraftNote}{inaccessibleNote}{archiveNote} This does not guarantee that the PC is clean.";
        OnPropertyChanged(nameof(ShowResults));
        OnPropertyChanged(nameof(HasMinecraftScanData));
        OnPropertyChanged(nameof(HasArchiveIssues));
        OnPropertyChanged(nameof(MinecraftSummaryText));
    }

    private void RaiseFindingCounts()
    {
        OnPropertyChanged(nameof(FindingCountText));
        OnPropertyChanged(nameof(HighCountText));
        OnPropertyChanged(nameof(MediumCountText));
        OnPropertyChanged(nameof(LowCountText));
        OnPropertyChanged(nameof(HasVisibleFindings));
        OnPropertyChanged(nameof(FindingsEmptyText));
        OnPropertyChanged(nameof(ShowResults));
        OnPropertyChanged(nameof(HasMinecraftScanData));
        OnPropertyChanged(nameof(MinecraftSummaryText));
        OnPropertyChanged(nameof(PcStatusLabel));
        OnPropertyChanged(nameof(PcStatusDetail));
        OnPropertyChanged(nameof(PcStatusTone));
        CloseResultsCommand?.RaiseCanExecuteChanged();
    }

    private void PauseScan() { if (!IsScanning || IsPaused) return; _pause?.Pause(); IsPaused = true; ScanSummaryText = "Scan paused. Resume to continue."; }
    private void ResumeScan() { if (!IsScanning || !IsPaused) return; _pause?.Resume(); IsPaused = false; ScanSummaryText = "Resuming the scan..."; }
    private void CancelScan() { if (!IsScanning) return; _pause?.Resume(); _scanCts?.Cancel(); ScanSummaryText = "Cancelling the scan..."; }
    private void CloseResults() { if (HasScanOutcome || Findings.Count > 0) CloseResultsInternal(); }

    private void CloseResultsInternal()
    {
        Findings.Clear();
        FilteredFindings.Clear();
        InaccessibleAreas.Clear();
        ArchiveIssues.Clear();
        ArchiveTruncationNote = string.Empty;
        _luaFilesChecked = 0;
        _jarFilesChecked = 0;
        _minecraftArchivesInspected = 0;
        _minecraftModsReviewed = 0;
        _hashChecksPerformed = 0;
        _signatureChecksPerformed = 0;
        _reparsePointsSkipped = 0;
        FilesChecked = 0;
        _directoriesChecked = 0;
        InaccessibleCount = 0;
        CurrentPath = string.Empty;
        ScanElapsedText = "0s";
        LastScanText = string.Empty;
        ScanSummaryText = string.Empty;
        ScanScopeDisplay = string.Empty;
        ScanConfigurationSummary = string.Empty;
        ScannedAreasDisplay = string.Empty;
        HasScanOutcome = false;
        ScanState = LinuxScanState.Idle;
        RaiseFindingCounts();
    }

    private async void ViewDetails(ScanFinding? finding) { if (finding is not null) await LinuxDialogs.ShowFindingDetailsAsync(finding, EffectiveReduceMotion); }
    private async void OpenFindingLocation(ScanFinding? finding)
    {
        if (finding is null) return;
        var confirmed = await LinuxDialogs.ShowMessageAsync("Open File Location", "This opens the parent folder in your file manager. WTX PC CHECK will not execute or open the file as an application.", "Open folder", "Cancel", true);
        if (!confirmed) return;
        var (ok, error) = await LinuxDialogs.OpenLocationAsync(finding.FullPath);
        if (!ok) await LinuxDialogs.ShowMessageAsync("Location unavailable", error, "OK", null, true);
    }
    private async void OpenProcessLocation(LinuxProcessInfo? process)
    {
        if (process?.ExecutablePath is null)
        {
            await LinuxDialogs.ShowMessageAsync("No executable path", "Linux did not expose an executable path for this process, usually because it is protected or has exited.", "OK", null);
            return;
        }
        var confirmed = await LinuxDialogs.ShowMessageAsync("Open File Location", "This opens the executable's parent folder in your file manager. WTX PC CHECK will not run or modify the process.", "Open folder", "Cancel", true);
        if (!confirmed) return;
        var (ok, error) = await LinuxDialogs.OpenLocationAsync(process.ExecutablePath);
        if (!ok) await LinuxDialogs.ShowMessageAsync("Location unavailable", error, "OK", null, true);
    }

    public LinuxSecurityOverview Security { get => _security; private set { if (SetProperty(ref _security, value)) RaiseSecurityProperties(); } }
    public bool IsSecurityChecking { get => _isSecurityChecking; private set { if (SetProperty(ref _isSecurityChecking, value)) OnPropertyChanged(nameof(SecurityCheckedText)); } }
    public string SecurityCheckedText => Security.State switch
    {
        LinuxSecurityState.Checking => "Checking Linux security status...",
        LinuxSecurityState.Available when Security.CheckedUtc is not null => $"Checked {AppFormat.Relative(Security.CheckedUtc)}",
        LinuxSecurityState.Partial => "Security status partially available",
        LinuxSecurityState.Unavailable => "Security status unavailable",
        _ => "Security status not checked yet"
    };
    public string DistributionText => $"{Security.Distribution} ({Security.DistributionId})";
    public string SupportNote => Security.SupportNote;
    public string FirewallStatusText => Security.Firewall.Summary;
    public string FirewallDetailText => Security.Firewall.Detail;
    public string UpdateStatusText => Security.Updates.Summary;
    public string UpdateDetailText => Security.Updates.Detail;
    public string WindowsEquivalentText => "Windows Defender and Windows Security are not available on Linux. ClamAV is optional and is never installed automatically.";
    public string ProcessSummaryText => Security.ProcessCount == 0 ? "No running-process snapshot available." : $"{AppFormat.Count(Security.ProcessCount)} processes visible | {AppFormat.Count(Security.Processes.Count(p => p.Risk >= RiskLevel.Medium))} need review." + (Security.ProcessListTruncated ? " List capped." : "");
    public string ProcessNote => Security.ProcessNote;
    public IReadOnlyList<LinuxProcessInfo> Processes => Security.Processes;
    public IReadOnlyList<LinuxStartupEntry> StartupEntries => Security.StartupEntries;
    public string StartupSummaryText => Security.StartupEntryCount == 0 ? "No supported startup entries found." : $"{AppFormat.Count(Security.StartupEntryCount)} startup entries found in XDG autostart and user systemd locations.";
    public ClamAvStatus ClamAv { get => _clamAv; private set { if (SetProperty(ref _clamAv, value)) { OnPropertyChanged(nameof(ClamAvAvailable)); OnPropertyChanged(nameof(ClamAvStatusText)); RunClamAvCommand?.RaiseCanExecuteChanged(); } } }
    public bool ClamAvAvailable => ClamAv.Available;
    public string ClamAvStatusText => ClamAv.Available ? $"{ClamAv.Version} at {ClamAv.Executable}" : ClamAv.Detail;
    public bool IsClamScanning { get => _isClamScanning; private set { if (SetProperty(ref _isClamScanning, value)) { OnPropertyChanged(nameof(IsBusy)); OnPropertyChanged(nameof(ClamAvResultText)); StartScanCommand?.RaiseCanExecuteChanged(); RunClamAvCommand?.RaiseCanExecuteChanged(); CancelClamAvCommand?.RaiseCanExecuteChanged(); } } }
    public string ClamProgressText { get => _clamProgressText; private set => SetProperty(ref _clamProgressText, value); }
    public ClamAvScanResult ClamResult { get => _clamResult; private set { if (SetProperty(ref _clamResult, value)) OnPropertyChanged(nameof(ClamAvResultText)); } }
    public string ClamAvResultText => ClamResult.Summary;

    private void RaiseSecurityProperties()
    {
        OnPropertyChanged(nameof(SecurityCheckedText));
        OnPropertyChanged(nameof(DistributionText));
        OnPropertyChanged(nameof(SupportNote));
        OnPropertyChanged(nameof(FirewallStatusText));
        OnPropertyChanged(nameof(FirewallDetailText));
        OnPropertyChanged(nameof(UpdateStatusText));
        OnPropertyChanged(nameof(UpdateDetailText));
        OnPropertyChanged(nameof(ProcessSummaryText));
        OnPropertyChanged(nameof(ProcessNote));
        OnPropertyChanged(nameof(Processes));
        OnPropertyChanged(nameof(StartupEntries));
        OnPropertyChanged(nameof(StartupSummaryText));
    }

    public async Task RefreshSecurityAsync()
    {
        if (IsSecurityChecking) return;
        IsSecurityChecking = true;
        Security.State = LinuxSecurityState.Checking;
        RaiseSecurityProperties();
        _securityCts?.Cancel();
        _securityCts = new CancellationTokenSource();
        try
        {
            var result = await _securityService.GetOverviewAsync(_securityCts.Token);
            if (!_securityCts.Token.IsCancellationRequested)
            {
                Security = result;
                ClamAv = result.ClamAv;
            }
        }
        catch (OperationCanceledException) { }
        catch
        {
            Security.State = LinuxSecurityState.Unavailable;
            Security.ErrorEnglish = "Linux security information could not be read. Some checks may require unavailable tools or permissions.";
            RaiseSecurityProperties();
        }
        finally { IsSecurityChecking = false; }
    }

    public async Task HandleStartupAsync()
    {
        _ = RefreshSecurityAsync();
        if (AutomaticUpdates && _updateConfiguration.IsConfigured) _ = CheckForUpdatesAsync(true);
    }

    private async Task RunClamAvAsync()
    {
        if (IsBusy) return;
        if (!ClamAv.Available)
        {
            await LinuxDialogs.ShowMessageAsync("ClamAV not available", "ClamAV is not installed or not in PATH. WTX PC CHECK does not install it. Install ClamAV with your normal package manager if you want a local malware scan.", "OK", null, true);
            return;
        }
        var roots = SelectedRoots;
        if (roots.Count == 0)
        {
            await LinuxDialogs.ShowMessageAsync("Select a location", "Select at least one local location before running ClamAV.", "OK", null, true);
            return;
        }
        if (!await LinuxDialogs.ShowPrivacyAsync(EffectiveReduceMotion)) return;
        var confirmed = await LinuxDialogs.ShowMessageAsync("Run ClamAV scan", "This runs your installed ClamAV scanner read-only on the selected locations. It does not install ClamAV, update signatures, remove files, quarantine files, or use root. A ClamAV scan can take a long time. Continue?", "Run ClamAV", "Cancel", true);
        if (!confirmed) return;
        _clamCts = new CancellationTokenSource();
        _clamStopwatch = Stopwatch.StartNew();
        _clamTimer.Start();
        IsClamScanning = true;
        ClamProgressText = "ClamAV is scanning the selected locations...";
        try
        {
            var result = await _securityService.RunClamAvAsync(roots, null, _clamCts.Token);
            ClamResult = result;
            AddClamAvFindings(result);
            if (result.State == ClamAvScanState.NotAvailable) await LinuxDialogs.ShowMessageAsync("ClamAV not available", result.Summary, "OK", null, true);
        }
        catch (OperationCanceledException)
        {
            ClamResult = new ClamAvScanResult { State = ClamAvScanState.Cancelled, Summary = "The ClamAV scan was cancelled.", CompletedUtc = DateTimeOffset.UtcNow };
        }
        finally
        {
            _clamTimer.Stop();
            _clamStopwatch?.Stop();
            _clamCts?.Dispose();
            _clamCts = null;
            IsClamScanning = false;
            ClamProgressText = string.Empty;
        }
    }

    private void AddClamAvFindings(ClamAvScanResult result)
    {
        if (result.Findings.Count == 0) return;
        foreach (var detection in result.Findings)
        {
            if (Findings.Any(f => f.FullPath.Equals(detection.Path, StringComparison.Ordinal) && f.Classification == FindingClassification.MalwareDetectedByLocalScanner)) continue;
            FileInfo? info = null;
            try { info = new FileInfo(detection.Path); } catch { }
            var hash = info?.Exists == true && info.Length <= HashService.MaxHashBytes
                ? HashService.TryComputeSha256(detection.Path, info.Length, CancellationToken.None)
                : new HashResult { Note = "Hash not computed." };
            Findings.Add(new ScanFinding
            {
                FileName = Path.GetFileName(detection.Path),
                FullPath = detection.Path,
                FileType = FileRules.FileTypeLabel(detection.Path),
                Explanation = "ClamAV reported a malware detection for this file. WTX PC CHECK did not create the detection, execute the file, or remove or quarantine it. Review ClamAV's own result and the file source.",
                DetectionMethod = "ClamAV local signature scan, read-only.",
                Limitations = "ClamAV signatures and database freshness affect results. A detection is not a guarantee that the file is malicious and may be a false positive. WTX PC CHECK did not update ClamAV signatures.",
                Category = FindingCategory.SecurityObservation,
                Classification = FindingClassification.MalwareDetectedByLocalScanner,
                Confidence = ConfidenceLevel.Medium,
                Evidence = $"ClamAV signature: {detection.Signature}",
                Risk = RiskLevel.High,
                SizeBytes = info?.Exists == true ? info.Length : 0,
                ModifiedUtc = info?.Exists == true ? info.LastWriteTimeUtc : DateTime.UtcNow,
                Signature = SignatureInfo.NotChecked("ELF publisher signatures are not verified on Linux."),
                Sha256 = hash.Success ? hash.Sha256 : null,
                HashNote = hash.Success ? null : hash.Note,
                MatchedRule = detection.Signature,
                IsScriptFile = FileRules.IsLuaFile(detection.Path)
            });
        }
        HasScanOutcome = true;
        LastScanText = $"ClamAV detection record | {AppFormat.Date(DateTime.Now)}";
        ScanSummaryText = $"{result.Findings.Count} ClamAV detection{(result.Findings.Count == 1 ? "" : "s")} added to the findings. WTX PC CHECK did not remove or quarantine anything.";
        ApplyFilter();
        RaiseFindingCounts();
    }

    private void CancelClamAv() { if (!IsClamScanning) return; _clamCts?.Cancel(); ClamProgressText = "Cancelling the ClamAV scan..."; }

    public bool AutomaticUpdates
    {
        get => Settings.AutomaticUpdates;
        set
        {
            if (Settings.AutomaticUpdates == value) return;
            Settings.AutomaticUpdates = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(AutomaticUpdatesText));
            SaveSettings();
            ConfigureUpdateTimer();
            if (!value) { _updateCts?.Cancel(); if (_stagedUpdatePath is null) SetUpdate(LinuxUpdateState.Disabled, "Automatic updates are off. You can still check manually."); }
            else if (_updateConfiguration.IsConfigured) _ = CheckForUpdatesAsync(true);
            else SetUpdate(LinuxUpdateState.NotConfigured, UpdateConfigurationMessage());
        }
    }
    public string AutomaticUpdatesText => AutomaticUpdates ? "On" : "Off";
    public bool ReduceMotion
    {
        get => Settings.ReduceMotion;
        set
        {
            if (Settings.ReduceMotion == value) return;
            Settings.ReduceMotion = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(EffectiveReduceMotion));
            SaveSettings();
        }
    }
    public bool EffectiveReduceMotion => Settings.ReduceMotion;
    public int UpdateIntervalHours
    {
        get => Settings.UpdateIntervalHours;
        set
        {
            if (Settings.UpdateIntervalHours == value) return;
            Settings.UpdateIntervalHours = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(Interval1));
            OnPropertyChanged(nameof(Interval6));
            OnPropertyChanged(nameof(Interval12));
            OnPropertyChanged(nameof(Interval24));
            SaveSettings();
            ConfigureUpdateTimer();
        }
    }
    public bool Interval1 { get => UpdateIntervalHours == 1; set { if (value) UpdateIntervalHours = 1; } }
    public bool Interval6 { get => UpdateIntervalHours == 6; set { if (value) UpdateIntervalHours = 6; } }
    public bool Interval12 { get => UpdateIntervalHours == 12; set { if (value) UpdateIntervalHours = 12; } }
    public bool Interval24 { get => UpdateIntervalHours == 24; set { if (value) UpdateIntervalHours = 24; } }

    private void SaveSettings() { if (!_settingsService.Save(Settings)) { HasNotice = true; NoticeText = "Preferences could not be saved. Changes apply for this session only."; } }
    private void ConfigureUpdateTimer()
    {
        _updateTimer.Stop();
        if (!AutomaticUpdates || !_updateConfiguration.IsConfigured) return;
        _updateTimer.Interval = TimeSpan.FromHours(Math.Clamp(UpdateIntervalHours, 1, 24));
        _updateTimer.Start();
    }

    public LinuxUpdateSnapshot Update { get => _update; private set { if (SetProperty(ref _update, value)) RaiseUpdateProperties(); } }
    private void RaiseUpdateProperties()
    {
        OnPropertyChanged(nameof(UpdateMessage));
        OnPropertyChanged(nameof(UpdateStateLabel));
        OnPropertyChanged(nameof(UpdateTone));
        OnPropertyChanged(nameof(UpdateVersionText));
        OnPropertyChanged(nameof(UpdateProgress));
        OnPropertyChanged(nameof(UpdateProgressText));
        OnPropertyChanged(nameof(UpdateSourceDisplay));
        OnPropertyChanged(nameof(UpdateConfigurationStatus));
        OnPropertyChanged(nameof(InstallKindText));
        InstallUpdateCommand?.RaiseCanExecuteChanged();
    }
    public string UpdateMessage => Update.Message;
    public string UpdateStateLabel => Update.State switch
    {
        LinuxUpdateState.NotConfigured => "Not configured",
        LinuxUpdateState.Disabled => "Off",
        LinuxUpdateState.Checking => "Checking...",
        LinuxUpdateState.UpToDate => "Up to date",
        LinuxUpdateState.UpdateAvailable => "Update available",
        LinuxUpdateState.Downloading => "Downloading...",
        LinuxUpdateState.ReadyToInstall => "Update ready",
        LinuxUpdateState.Failed => "Update failed",
        _ => "Not checked"
    };
    public string UpdateTone => Update.State switch
    {
        LinuxUpdateState.UpToDate => "Positive",
        LinuxUpdateState.ReadyToInstall or LinuxUpdateState.UpdateAvailable => "Warning",
        LinuxUpdateState.Failed => "Danger",
        LinuxUpdateState.NotConfigured => "Warning",
        LinuxUpdateState.Checking or LinuxUpdateState.Downloading => "Active",
        _ => "Neutral"
    };
    public string UpdateVersionText => Update.Version is null ? string.Empty : $"Version {Update.Version}";
    public double UpdateProgress => Update.ProgressPercent ?? 0;
    public bool UpdateProgressVisible => Update.State == LinuxUpdateState.Downloading && Update.ProgressPercent is not null;
    public string UpdateProgressText => Update.TotalBytes is > 0 ? $"{AppFormat.Bytes(Update.BytesReceived)} of {AppFormat.Bytes(Update.TotalBytes.Value)}" : (Update.BytesReceived > 0 ? $"{AppFormat.Bytes(Update.BytesReceived)} downloaded" : string.Empty);
    public string UpdateSourceDisplay => _updateConfiguration.IsConfigured ? _updateConfiguration.ManifestUrl : "Not configured (placeholder)";
    public string UpdateConfigurationStatus { get { _updateConfiguration.Validate(out var reason); return _updateConfiguration.IsConfigured ? "Linux update source and OpenPGP fingerprint are configured." : reason; } }
    public string InstallKindText => LinuxPaths.IsAppImage ? $"Running as AppImage: {LinuxPaths.AppImagePath}" : "Running from an archive or package-managed installation. Updates must be applied through the package manager or by replacing the archive manually.";

    private void SetUpdate(LinuxUpdateState state, string message, string? version = null, DateTimeOffset? checkedUtc = null, double? percent = null, string? stagedPath = null, string? sha = null, string? notes = null)
    {
        Update = new LinuxUpdateSnapshot
        {
            State = state,
            Message = message,
            Version = version ?? Update.Version,
            CheckedUtc = checkedUtc ?? Update.CheckedUtc,
            ProgressPercent = percent,
            BytesReceived = Update.BytesReceived,
            TotalBytes = Update.TotalBytes,
            StagedPath = stagedPath,
            Sha256 = sha,
            ReleaseNotes = notes
        };
    }

    public void RefreshUpdateState()
    {
        if (!_updateConfiguration.IsConfigured) SetUpdate(LinuxUpdateState.NotConfigured, UpdateConfigurationMessage());
        else if (!AutomaticUpdates) SetUpdate(LinuxUpdateState.Disabled, "Automatic updates are off. You can check manually.");
        else SetUpdate(LinuxUpdateState.Idle, "Updates have not been checked in this session.");
    }
    private string UpdateConfigurationMessage() { _updateConfiguration.Validate(out var reason); return $"Automatic updates are not configured for this Linux build. {reason} The app works offline."; }

    private async Task CheckForUpdatesAsync(bool automatic)
    {
        if (_updateBusy) return;
        if (!_updateConfiguration.IsConfigured) { SetUpdate(LinuxUpdateState.NotConfigured, UpdateConfigurationMessage()); return; }
        _updateBusy = true;
        SetUpdate(LinuxUpdateState.Checking, automatic ? "Checking for updates automatically..." : "Checking for updates...");
        _updateCts?.Dispose();
        _updateCts = new CancellationTokenSource();
        var token = _updateCts.Token;
        var progress = new Progress<LinuxUpdateProgress>(p =>
        {
            if (token.IsCancellationRequested) return;
            Update = new LinuxUpdateSnapshot
            {
                State = p.Percent is null && p.BytesReceived == 0 ? LinuxUpdateState.Checking : LinuxUpdateState.Downloading,
                Message = p.Status,
                Version = Update.Version,
                ProgressPercent = p.Percent,
                BytesReceived = p.BytesReceived,
                TotalBytes = p.TotalBytes,
                CheckedUtc = Update.CheckedUtc
            };
        });
        try
        {
            var result = await _updateService.CheckAndStageAsync(progress, token);
            if (result.NotConfigured) SetUpdate(LinuxUpdateState.NotConfigured, result.Message);
            else if (result.UpdateAvailable)
            {
                _stagedUpdatePath = result.StagedPath;
                _stagedUpdateHash = result.Sha256;
                _stagedUpdateVersion = result.Manifest?.Version;
                _stagedUpdateNotes = result.Manifest?.ReleaseNotes;
                SetUpdate(result.Installable ? LinuxUpdateState.ReadyToInstall : LinuxUpdateState.UpdateAvailable, result.Message, _stagedUpdateVersion, DateTimeOffset.UtcNow, 100, result.StagedPath, result.Sha256, _stagedUpdateNotes);
                if (result.Installable) await PromptForUpdateRestartAsync();
            }
            else if (result.Succeeded) SetUpdate(LinuxUpdateState.UpToDate, result.Message, result.Manifest?.Version, DateTimeOffset.UtcNow, 100);
            else SetUpdate(LinuxUpdateState.Failed, result.Message, null, DateTimeOffset.UtcNow);
        }
        catch (OperationCanceledException) { if (!_disposed) SetUpdate(LinuxUpdateState.Idle, "The update check was cancelled. The app remains usable offline."); }
        catch { SetUpdate(LinuxUpdateState.Failed, "The update check failed. The app remains usable offline.", null, DateTimeOffset.UtcNow); }
        finally
        {
            _updateBusy = false;
            OnPropertyChanged(nameof(UpdateStateLabel));
            _updateCts?.Dispose();
            _updateCts = null;
            InstallUpdateCommand?.RaiseCanExecuteChanged();
        }
    }

    private async Task PromptForUpdateRestartAsync()
    {
        if (_stagedUpdatePath is null || _stagedUpdateHash is null) { _deferredUpdatePrompt = false; return; }
        if (IsBusy) { _deferredUpdatePrompt = true; return; }
        _deferredUpdatePrompt = false;
        var confirmed = await LinuxDialogs.ShowUpdateRestartAsync(_stagedUpdateVersion ?? "new version", _stagedUpdateNotes, EffectiveReduceMotion);
        if (!confirmed) { _stagedUpdatePath = null; _stagedUpdateHash = null; SetUpdate(LinuxUpdateState.Idle, "The verified update was not installed. You can check again later."); return; }
        var (started, error) = await _updateService.StartApplyAsync(_stagedUpdatePath, _stagedUpdateHash, _stagedUpdateVersion ?? "unknown", CancellationToken.None);
        if (!started) { SetUpdate(LinuxUpdateState.Failed, error); await LinuxDialogs.ShowMessageAsync("Update could not start", error, "OK", null, true); return; }
        SetUpdate(LinuxUpdateState.ReadyToInstall, "Restarting to install the verified update...");
        LinuxDialogs.ShutdownApplication();
    }

    private async Task InstallUpdateAsync() => await PromptForUpdateRestartAsync();
    private void OpenInstallLocation() { var path = LinuxPaths.AppImagePath ?? LinuxPaths.ExecutablePath; _ = LinuxDialogs.OpenLocationAsync(path); }

    public string SettingsPathDisplay => LinuxPaths.SettingsFile;
    public string VersionText => AppInfo.VersionLabel;
    public string ProductName => AppInfo.ProductName;
    public string PublisherName => AppInfo.Publisher;
    public string PlatformText => LinuxPaths.IsAppImage ? "Linux x64 | AppImage" : "Linux x64 | archive/package";
    public bool HasNotice { get => _hasNotice; private set => SetProperty(ref _hasNotice, value); }
    public string NoticeText { get => _noticeText; private set => SetProperty(ref _noticeText, value); }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _scanTimer.Stop();
        _clamTimer.Stop();
        _updateTimer.Stop();
        _scanCts?.Cancel();
        _securityCts?.Cancel();
        _clamCts?.Cancel();
        _updateCts?.Cancel();
        _pause?.Dispose();
        _updateService.Dispose();
    }
}



