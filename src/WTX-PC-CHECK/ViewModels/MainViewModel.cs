using System.IO;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using WtxPcCheck.Models;
using WtxPcCheck.Services;
using WtxPcCheck.Views;

namespace WtxPcCheck.ViewModels;

public enum ScanUiState
{
    Idle,
    Running,
    Completed,
    Cancelled,
    Failed
}

public sealed record NavigationItem(string Key, string Label, string IconData);

public sealed record FindingFilterOption(string Key, string Label);

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly SettingsService _settingsService = new();
    private readonly IndicatorDatabase _indicators = IndicatorDatabase.LoadEmbedded();
    private readonly ScanEngine _scanEngine;
    private readonly SecurityStatusService _securityService = new();
    private readonly DefenderScanService _defenderService = new();
    private readonly UpdateConfiguration _updateConfiguration = new();
    private readonly UpdateService _updateService;
    private readonly UpdateApplyService _updateApplyService = new();
    private readonly DispatcherTimer _updateTimer;
    private readonly DispatcherTimer _scanTimer;
    private readonly DispatcherTimer _defenderTimer;

    private CancellationTokenSource? _scanCts;
    private CancellationTokenSource? _securityCts;
    private CancellationTokenSource? _defenderCts;
    private CancellationTokenSource? _updateCts;
    private Stopwatch? _scanStopwatch;
    private Stopwatch? _defenderStopwatch;
    private int _scanSequence;
    private bool _disposed;
    private bool _drivesInitialized;

    private string? _pendingStagedPath;
    private string? _pendingSha256;
    private string? _pendingVersion;
    private string? _pendingReleaseNotes;
    private bool _deferredUpdatePrompt;
    private bool _updateBusy;
    private UpdateManifest? _startupDownloadManifest;

    private ScanUiState _scanState;
    private long _filesChecked;
    private long _directoriesChecked;
    private int _inaccessibleCount;
    private string _currentPath = string.Empty;
    private string _scanElapsedText = "0s";
    private string _lastScanText = string.Empty;
    private bool _hasScanOutcome;
    private bool _findingLimitReached;
    private long _luaFilesChecked;
    private long _peFilesChecked;
    private long _hashChecksPerformed;
    private long _signatureChecksPerformed;
    private long _reparsePointsSkipped;
    private long _cloudFilesSkipped;
    private string _inaccessibleTruncationNote = string.Empty;
    private string _noticeText = string.Empty;
    private bool _hasNotice;
    private string _currentPageKey = "dashboard";
    private FindingFilterOption _selectedFilter;
    private SecurityOverview _security = new();
    private bool _isSecurityChecking;
    private DefenderScanResult _defenderResult = new();
    private UpdateSnapshot _update = new();
    private string _defenderProgressText = string.Empty;
    private string _scanSummaryText = string.Empty;
    private string _scanScopeDisplay = string.Empty;
    private string _scannedAreasDisplay = string.Empty;
    private string _defenderCurrentRoot = string.Empty;

    public MainViewModel(AppSettings settings, string? startupWarning, UpdateCheckOutcome? startupUpdate)
    {
        Settings = settings;
        _update = new UpdateSnapshot { CheckedUtc = settings.LastUpdateCheckUtc };
        _scanEngine = new ScanEngine(_indicators);
        _updateService = new UpdateService(_updateConfiguration);

        NavigationItems =
        [
            new NavigationItem("dashboard", "Dashboard", "M3,3 H10 V10 H3 Z M14,3 H21 V10 H14 Z M3,14 H10 V21 H3 Z M14,14 H21 V21 H14 Z"),
            new NavigationItem("scan", "Scan", "M4,5 H20 V19 H4 Z M4,9 H20 M8,5 V19 M12,12 H17"),
            new NavigationItem("settings", "Settings", "M12,8 A4,4 0 1 0 12,16 A4,4 0 1 0 12,8 M12,2 V5 M12,19 V22 M2,12 H5 M19,12 H22 M5,5 L7,7 M17,17 L19,19 M19,5 L17,7 M7,17 L5,19"),
            new NavigationItem("about", "About", "M12,3 A9,9 0 1 0 12,21 A9,9 0 1 0 12,3 M12,11 V16 M12,8 V8.1")
        ];

        FindingFilters =
        [
            new FindingFilterOption("all", "All"),
            new FindingFilterOption("executor", "Executor indicators"),
            new FindingFilterOption("script", "Script review"),
            new FindingFilterOption("malware", "Malware indicators")
        ];
        _selectedFilter = FindingFilters[0];

        FindingsView = CollectionViewSource.GetDefaultView(Findings);
        FindingsView.Filter = FilterFinding;
        Findings.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(HasFindings));
            OnPropertyChanged(nameof(FindingCountText));
            OnPropertyChanged(nameof(HighCountText));
            OnPropertyChanged(nameof(MediumCountText));
            OnPropertyChanged(nameof(LowCountText));
            OnPropertyChanged(nameof(FindingsEmptyText));
            OnPropertyChanged(nameof(HasVisibleFindings));
            OnPropertyChanged(nameof(PcStatusLabel));
            OnPropertyChanged(nameof(PcStatusDetail));
            OnPropertyChanged(nameof(PcStatusTone));
        };

        RefreshDrives(initial: true);
        AddNotice(startupWarning);
        ApplyInitialUpdate(startupUpdate);

        _scanTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _scanTimer.Tick += (_, _) =>
        {
            if (_scanStopwatch is not null) ScanElapsedText = AppFormat.Duration(_scanStopwatch.Elapsed);
        };
        _defenderTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _defenderTimer.Tick += (_, _) =>
        {
            if (_defenderStopwatch is not null && IsDefenderScanning)
                DefenderProgressText = $"Windows Defender is scanning {_defenderCurrentRoot} · {AppFormat.Duration(_defenderStopwatch.Elapsed)}";
        };

        _updateTimer = new DispatcherTimer();
        _updateTimer.Tick += async (_, _) =>
        {
            if (!AutomaticUpdates || _updateBusy) return;
            await CheckForUpdatesAsync(automatic: true);
        };
        ConfigureUpdateTimer();

        StartScanCommand = new AsyncRelayCommand(StartScanAsync, () => !IsBusy);
        CancelScanCommand = new RelayCommand(CancelScan, () => IsScanning);
        RunDefenderScanCommand = new AsyncRelayCommand(RunDefenderScanAsync, () => !IsBusy);
        CancelDefenderScanCommand = new RelayCommand(CancelDefenderScan, () => IsDefenderScanning);
        RefreshSecurityCommand = new AsyncRelayCommand(RefreshSecurityAsync, () => !IsSecurityChecking);
        CheckUpdatesCommand = new AsyncRelayCommand(() => CheckForUpdatesAsync(automatic: false), () => !_updateBusy);
        InstallUpdateCommand = new AsyncRelayCommand(InstallPendingUpdateAsync, () => CanInstallUpdate && !IsBusy);
        RefreshDrivesCommand = new RelayCommand(() => RefreshDrives(false), () => !IsBusy);
        SelectFixedDrivesCommand = new RelayCommand(SelectFixedDrives, () => !IsBusy);
        ClearDriveSelectionCommand = new RelayCommand(ClearDriveSelection, () => !IsBusy);
        ViewFindingDetailsCommand = new RelayCommand<ScanFinding>(OpenFindingDetails);
        OpenFindingLocationCommand = new RelayCommand<ScanFinding>(OpenFindingLocation);
        OpenStartupLocationCommand = new RelayCommand<StartupEntry>(OpenStartupLocation);
        CloseResultsCommand = new RelayCommand(CloseResults, () => HasScanOutcome && !IsScanning);
        DismissNoticeCommand = new RelayCommand(DismissNotice);
        OpenWindowsSecurityCommand = new RelayCommand(OpenWindowsSecurity);
        OpenWindowsUpdateCommand = new RelayCommand(OpenWindowsUpdate);
        OpenLocalDataFolderCommand = new RelayCommand(OpenLocalDataFolder);
        SetUpdateIntervalCommand = new RelayCommand<string?>(SetUpdateInterval);
        NavigateCommand = new RelayCommand<string?>(Navigate);
        NavigateScanCommand = new RelayCommand(() => Navigate("scan"));
        NavigateSettingsCommand = new RelayCommand(() => Navigate("settings"));
        RefreshUpdateConfigurationState();
        SystemParameters.StaticPropertyChanged += SystemParameters_StaticPropertyChanged;
    }

    public AppSettings Settings { get; }
    public IReadOnlyList<NavigationItem> NavigationItems { get; }
    public IReadOnlyList<FindingFilterOption> FindingFilters { get; }
    public ObservableCollection<DriveOption> Drives { get; } = [];
    public ObservableCollection<ScanFinding> Findings { get; } = [];
    public ObservableCollection<InaccessibleArea> InaccessibleAreas { get; } = [];
    public ICollectionView FindingsView { get; }

    public RelayCommand<ScanFinding> ViewFindingDetailsCommand { get; }
    public RelayCommand<ScanFinding> OpenFindingLocationCommand { get; }
    public RelayCommand<StartupEntry> OpenStartupLocationCommand { get; }
    public AsyncRelayCommand StartScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public AsyncRelayCommand RunDefenderScanCommand { get; }
    public RelayCommand CancelDefenderScanCommand { get; }
    public AsyncRelayCommand RefreshSecurityCommand { get; }
    public AsyncRelayCommand CheckUpdatesCommand { get; }
    public AsyncRelayCommand InstallUpdateCommand { get; }
    public RelayCommand RefreshDrivesCommand { get; }
    public RelayCommand SelectFixedDrivesCommand { get; }
    public RelayCommand ClearDriveSelectionCommand { get; }
    public RelayCommand CloseResultsCommand { get; }
    public RelayCommand DismissNoticeCommand { get; }
    public RelayCommand OpenWindowsSecurityCommand { get; }
    public RelayCommand OpenWindowsUpdateCommand { get; }
    public RelayCommand OpenLocalDataFolderCommand { get; }
    public RelayCommand<string?> SetUpdateIntervalCommand { get; }
    public RelayCommand<string?> NavigateCommand { get; }
    public RelayCommand NavigateScanCommand { get; }
    public RelayCommand NavigateSettingsCommand { get; }

    public string CurrentPageKey
    {
        get => _currentPageKey;
        set
        {
            if (!SetProperty(ref _currentPageKey, value)) return;
            OnPropertyChanged(nameof(IsDashboardPage));
            OnPropertyChanged(nameof(IsScanPage));
            OnPropertyChanged(nameof(IsSettingsPage));
            OnPropertyChanged(nameof(IsAboutPage));
            OnPropertyChanged(nameof(CurrentPageTitle));
            OnPropertyChanged(nameof(CurrentPageSubtitle));
        }
    }

    public bool IsDashboardPage => CurrentPageKey == "dashboard";
    public bool IsScanPage => CurrentPageKey == "scan";
    public bool IsSettingsPage => CurrentPageKey == "settings";
    public bool IsAboutPage => CurrentPageKey == "about";

    public string CurrentPageTitle => CurrentPageKey switch
    {
        "scan" => "Scan",
        "settings" => "Settings",
        "about" => "About",
        _ => "Dashboard"
    };

    public string CurrentPageSubtitle => CurrentPageKey switch
    {
        "scan" => "Choose drives, scan locally, and review every result with its limits.",
        "settings" => "Updates, motion, and local preferences.",
        "about" => "Purpose, privacy, detection limits, and update configuration.",
        _ => "A local, honest check of this PC."
    };

    public void Navigate(string? key)
    {
        if (key is "dashboard" or "scan" or "settings" or "about")
            CurrentPageKey = key;
    }

    public bool HasNotice => _hasNotice;
    public string NoticeText => _noticeText;

    private void AddNotice(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        _noticeText = text;
        _hasNotice = true;
        OnPropertyChanged(nameof(NoticeText));
        OnPropertyChanged(nameof(HasNotice));
    }

    private void DismissNotice()
    {
        _hasNotice = false;
        OnPropertyChanged(nameof(HasNotice));
    }

    public string VersionText => AppInfo.VersionLabel;
    public string ProductName => AppInfo.ProductName;
    public string PublisherName => AppInfo.Publisher;

    public void RefreshDrives(bool initial)
    {
        var previouslySelected = Drives.Where(d => d.IsSelected).Select(d => d.RootPath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var drive in Drives) drive.PropertyChanged -= DriveOnPropertyChanged;
        Drives.Clear();

        List<DriveInfo> discovered;
        try
        {
            discovered = DriveInfo.GetDrives()
                .Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable or DriveType.Network)
                .OrderBy(d => d.DriveType == DriveType.Fixed ? 0 : d.DriveType == DriveType.Removable ? 1 : 2)
                .ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            discovered = [];
        }

        foreach (var drive in discovered)
        {
            var option = new DriveOption(drive);
            option.PropertyChanged += DriveOnPropertyChanged;
            if (initial || !_drivesInitialized)
                option.IsSelected = option.IsFixed;
            else
                option.IsSelected = previouslySelected.Contains(option.RootPath);
            Drives.Add(option);
        }

        _drivesInitialized = true;
        RaiseScopeProperties();
    }

    private void DriveOnPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(DriveOption.IsSelected))
            RaiseScopeProperties();
    }

    private void SelectFixedDrives()
    {
        foreach (var drive in Drives) drive.IsSelected = drive.IsFixed;
        RaiseScopeProperties();
    }

    private void ClearDriveSelection()
    {
        foreach (var drive in Drives) drive.IsSelected = false;
        RaiseScopeProperties();
    }

    private void RaiseScopeProperties()
    {
        OnPropertyChanged(nameof(HasSelectedDrives));
        OnPropertyChanged(nameof(SelectedDriveCount));
        OnPropertyChanged(nameof(SelectedScopeSummary));
        OnPropertyChanged(nameof(SelectedRootsDisplay));
        OnPropertyChanged(nameof(SelectedDrives));
        StartScanCommand?.RaiseCanExecuteChanged();
        RunDefenderScanCommand?.RaiseCanExecuteChanged();
    }

    public IReadOnlyList<DriveOption> SelectedDrives => Drives.Where(d => d.IsSelected).ToList();
    public bool HasSelectedDrives => Drives.Any(d => d.IsSelected);
    public int SelectedDriveCount => Drives.Count(d => d.IsSelected);
    public string SelectedRootsDisplay => string.Join(", ", Drives.Where(d => d.IsSelected).Select(d => d.RootPath));
    public string SelectedScopeSummary
    {
        get
        {
            var selected = Drives.Where(d => d.IsSelected).ToList();
            if (selected.Count == 0) return "No drives selected";
            var bytes = selected.Sum(d => d.TotalBytes);
            return $"{selected.Count} drive{(selected.Count == 1 ? "" : "s")} selected · {AppFormat.Bytes(bytes)} total";
        }
    }

    public bool IsScanning => ScanState == ScanUiState.Running;
    public ScanUiState ScanState
    {
        get => _scanState;
        private set
        {
            if (!SetProperty(ref _scanState, value)) return;
            OnPropertyChanged(nameof(IsScanning));
            OnPropertyChanged(nameof(IsBusy));
            OnPropertyChanged(nameof(ShowScanMetrics));
            OnPropertyChanged(nameof(PcStatusLabel));
            OnPropertyChanged(nameof(PcStatusDetail));
            OnPropertyChanged(nameof(PcStatusTone));
            OnPropertyChanged(nameof(ScanStatusLabel));
            OnPropertyChanged(nameof(ScanStatusDetail));
            OnPropertyChanged(nameof(FindingsEmptyText));
            CancelScanCommand?.RaiseCanExecuteChanged();
            StartScanCommand?.RaiseCanExecuteChanged();
            RunDefenderScanCommand?.RaiseCanExecuteChanged();
            RefreshDrivesCommand?.RaiseCanExecuteChanged();
            SelectFixedDrivesCommand?.RaiseCanExecuteChanged();
            ClearDriveSelectionCommand?.RaiseCanExecuteChanged();
            CloseResultsCommand?.RaiseCanExecuteChanged();
            InstallUpdateCommand?.RaiseCanExecuteChanged();
        }
    }

    public bool IsBusy => IsScanning || IsDefenderScanning;
    public bool ShowScanMetrics => IsScanning || HasScanOutcome;
    public bool HasScanOutcome
    {
        get => _hasScanOutcome;
        private set
        {
            if (!SetProperty(ref _hasScanOutcome, value)) return;
            OnPropertyChanged(nameof(ShowResults));
            OnPropertyChanged(nameof(ShowScanMetrics));
            CloseResultsCommand?.RaiseCanExecuteChanged();
        }
    }

    public bool ShowResults => HasScanOutcome || Findings.Count > 0;
    public long FilesChecked
    {
        get => _filesChecked;
        private set
        {
            if (!SetProperty(ref _filesChecked, value)) return;
            OnPropertyChanged(nameof(FilesCheckedText));
        }
    }
    public string FilesCheckedText => AppFormat.Count(FilesChecked);
    public long DirectoriesChecked
    {
        get => _directoriesChecked;
        private set
        {
            if (!SetProperty(ref _directoriesChecked, value)) return;
            OnPropertyChanged(nameof(DirectoriesCheckedText));
        }
    }
    public string DirectoriesCheckedText => AppFormat.Count(DirectoriesChecked);
    public int InaccessibleCount
    {
        get => _inaccessibleCount;
        private set
        {
            if (!SetProperty(ref _inaccessibleCount, value)) return;
            OnPropertyChanged(nameof(InaccessibleCountText));
        }
    }
    public string InaccessibleCountText => AppFormat.Count(InaccessibleCount);
    public string CurrentPath
    {
        get => _currentPath;
        private set => SetProperty(ref _currentPath, value);
    }
    public string ScanElapsedText
    {
        get => _scanElapsedText;
        private set => SetProperty(ref _scanElapsedText, value);
    }
    public string LastScanText
    {
        get => _lastScanText;
        private set => SetProperty(ref _lastScanText, value);
    }
    public string ScanSummaryText
    {
        get => _scanSummaryText;
        private set => SetProperty(ref _scanSummaryText, value);
    }
    public string ScanScopeDisplay
    {
        get => _scanScopeDisplay;
        private set => SetProperty(ref _scanScopeDisplay, value);
    }
    public string ScannedAreasDisplay
    {
        get => _scannedAreasDisplay;
        private set => SetProperty(ref _scannedAreasDisplay, value);
    }
    public string InaccessibleTruncationNote
    {
        get => _inaccessibleTruncationNote;
        private set => SetProperty(ref _inaccessibleTruncationNote, value);
    }
    public bool FindingLimitReached
    {
        get => _findingLimitReached;
        private set => SetProperty(ref _findingLimitReached, value);
    }
    public string FindingCountText => AppFormat.Count(Findings.Count);
    public string HighCountText => AppFormat.Count(Findings.Count(f => f.Risk == RiskLevel.High));
    public string MediumCountText => AppFormat.Count(Findings.Count(f => f.Risk == RiskLevel.Medium));
    public string LowCountText => AppFormat.Count(Findings.Count(f => f.Risk is RiskLevel.Low or RiskLevel.Info));
    public bool HasFindings => Findings.Count > 0;

    public string ScanStatusLabel => ScanState switch
    {
        ScanUiState.Running => "Scanning",
        ScanUiState.Cancelled => "Scan incomplete",
        ScanUiState.Failed => "Scan stopped",
        ScanUiState.Completed => HasFindings ? "Review needed" : "Scan finished",
        _ => "Not scanned"
    };

    public string PcStatusLabel => ScanState switch
    {
        ScanUiState.Running => "Scan in progress",
        ScanUiState.Cancelled => "Scan incomplete",
        ScanUiState.Failed => "Scan stopped",
        ScanUiState.Completed => HasFindings ? "Review needed" : "No items flagged",
        _ => "Not checked yet"
    };

    public string PcStatusDetail => ScanState switch
    {
        ScanUiState.Running => "WTX PC CHECK is checking the selected drives. The file count and current path come from the running scan.",
        ScanUiState.Cancelled => "The scan was stopped before it finished. Results are partial, and no conclusion about this PC can be drawn.",
        ScanUiState.Failed => "The scan stopped because of an unexpected error. No conclusion about this PC can be drawn.",
        ScanUiState.Completed when HasFindings =>
            $"{Findings.Count} item{(Findings.Count == 1 ? "" : "s")} matched review indicators. Indicators are not proof of malware. Review each item, its detection method, and its limitations.",
        ScanUiState.Completed =>
            "No executor indicators or script concerns were flagged in the areas that could be read. This does not mean the PC is clean. Some files may have been inaccessible, and detection is not perfect.",
        _ => "Run a scan to review selected drives. WTX PC CHECK never guarantees that a PC is clean or that every threat has been found."
    };

    public string PcStatusTone => ScanState switch
    {
        ScanUiState.Running => "Active",
        ScanUiState.Cancelled or ScanUiState.Failed => "Danger",
        ScanUiState.Completed when HasFindings => "Warning",
        ScanUiState.Completed => "Positive",
        _ => "Neutral"
    };

    public string ScanStatusDetail => ScanState switch
    {
        ScanUiState.Running => "Files are being inspected locally. The current path below reflects the scan's actual position.",
        ScanUiState.Completed => ScanSummaryText,
        ScanUiState.Cancelled => "The scan was cancelled. Any findings shown are partial and the inaccessible-area list may be incomplete.",
        ScanUiState.Failed => ScanSummaryText,
        _ => "Choose drives and start a scan. A privacy confirmation appears before every scan."
    };

    private void RaiseScanCounters()
    {
        OnPropertyChanged(nameof(ScanStatusLabel));
        OnPropertyChanged(nameof(ScanStatusDetail));
        OnPropertyChanged(nameof(PcStatusLabel));
        OnPropertyChanged(nameof(PcStatusDetail));
        OnPropertyChanged(nameof(PcStatusTone));
        OnPropertyChanged(nameof(HasFindings));
        OnPropertyChanged(nameof(FindingCountText));
        OnPropertyChanged(nameof(HighCountText));
        OnPropertyChanged(nameof(MediumCountText));
        OnPropertyChanged(nameof(LowCountText));
        OnPropertyChanged(nameof(FindingsEmptyText));
        OnPropertyChanged(nameof(HasVisibleFindings));
    }

    private async Task StartScanAsync()
    {
        if (IsBusy) return;
        if (!HasSelectedDrives)
        {
            MessageDialog.Show(Owner, "Select at least one drive",
                "No drive is selected. Open Scan and select at least one local, removable, or network drive before starting.",
                "Open Scan", "Cancel", warning: true);
            Navigate("scan");
            return;
        }

        if (!PrivacyDialog.Show(Owner, EffectiveReduceMotion)) return;

        CloseResultsInternal();
        Navigate("scan");
        CurrentPath = string.Empty;
        ScanElapsedText = "0s";
        ScanSummaryText = string.Empty;
        HasScanOutcome = false;
        ScanState = ScanUiState.Running;
        ScanScopeDisplay = string.Join(", ", SelectedDrives.Select(d => d.RootPath));
        _scanStopwatch = Stopwatch.StartNew();
        _scanTimer.Start();

        var sequence = ++_scanSequence;
        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;
        var request = new ScanRequest
        {
            Roots = SelectedDrives.Select(d => d.RootPath).ToList(),
            AnalyzeLuaContents = true,
            MaxFindings = 1000
        };

        var progress = new Progress<ScanProgress>(value =>
        {
            if (sequence != _scanSequence || !IsScanning) return;
            ApplyProgress(value);
        });
        var findingProgress = new Progress<ScanFinding>(finding =>
        {
            if (sequence != _scanSequence || !IsScanning) return;
            Findings.Add(finding);
            OnPropertyChanged(nameof(HasVisibleFindings));
            OnPropertyChanged(nameof(FindingsEmptyText));
        });

        ScanOutcome? outcome = null;
        try
        {
            outcome = await Task.Run(() => _scanEngine.Scan(request, progress, findingProgress, token), token);
        }
        catch (OperationCanceledException)
        {
            if (sequence == _scanSequence)
            {
                ScanState = ScanUiState.Cancelled;
                ScanSummaryText = "The scan was cancelled before it could finish. No reliable conclusion about this PC can be drawn.";
                LastScanText = $"Stopped {AppFormat.Date(DateTime.Now)}";
                ScanElapsedText = _scanStopwatch is null ? "0s" : AppFormat.Duration(_scanStopwatch.Elapsed);
                HasScanOutcome = true;
                OnPropertyChanged(nameof(ScanStatusDetail));
            }
        }
        catch
        {
            if (sequence == _scanSequence)
            {
                ScanState = ScanUiState.Failed;
                ScanSummaryText = "The scan stopped because of an unexpected error. No conclusion about this PC can be drawn. You can try again or review Windows Security separately.";
                LastScanText = $"Stopped {AppFormat.Date(DateTime.Now)}";
                ScanElapsedText = _scanStopwatch is null ? "0s" : AppFormat.Duration(_scanStopwatch.Elapsed);
                HasScanOutcome = true;
                OnPropertyChanged(nameof(ScanStatusDetail));
            }
        }
        finally
        {
            _scanTimer.Stop();
            _scanStopwatch?.Stop();
            _scanCts?.Dispose();
            _scanCts = null;
        }

        if (outcome is not null && sequence == _scanSequence)
        {
            LoadScanOutcome(outcome);
        }

        StartScanCommand.RaiseCanExecuteChanged();
        RunDefenderScanCommand.RaiseCanExecuteChanged();
        InstallUpdateCommand.RaiseCanExecuteChanged();

        if (Security.State == SecurityQueryState.NotChecked)
            _ = RefreshSecurityAsync();

        if (_deferredUpdatePrompt && !IsBusy)
            await PromptForUpdateRestartAsync();
    }

    private void ApplyProgress(ScanProgress progress)
    {
        FilesChecked = progress.FilesChecked;
        DirectoriesChecked = progress.DirectoriesChecked;
        InaccessibleCount = progress.InaccessibleCount;
        if (!string.IsNullOrWhiteSpace(progress.CurrentPath)) CurrentPath = progress.CurrentPath;
        ScanElapsedText = AppFormat.Duration(progress.Elapsed);
        _luaFilesChecked = progress.LuaFilesChecked;
        _reparsePointsSkipped = progress.ReparsePointsSkipped;
        _cloudFilesSkipped = progress.CloudFilesSkipped;
        OnPropertyChanged(nameof(LiveScanMetrics));
        OnPropertyChanged(nameof(LuaFilesCheckedText));
        OnPropertyChanged(nameof(ReparseSkippedText));
        OnPropertyChanged(nameof(CloudFilesSkippedText));
    }

    public string LiveScanMetrics
        => $"{LuaFilesCheckedText} Lua files checked · {ReparseSkippedText} reparse points skipped · {CloudFilesSkippedText} cloud placeholders skipped";

    public string LuaFilesCheckedText => AppFormat.Count(_luaFilesChecked);
    public string ReparseSkippedText => AppFormat.Count(_reparsePointsSkipped);
    public string CloudFilesSkippedText => AppFormat.Count(_cloudFilesSkipped);
    public string PeFilesCheckedText => AppFormat.Count(_peFilesChecked);
    public string HashChecksText => AppFormat.Count(_hashChecksPerformed);
    public string SignatureChecksText => AppFormat.Count(_signatureChecksPerformed);

    private void LoadScanOutcome(ScanOutcome outcome)
    {
        ScanState = outcome.Cancelled ? ScanUiState.Cancelled
            : outcome.Failed ? ScanUiState.Failed
            : ScanUiState.Completed;

        FilesChecked = outcome.FilesChecked;
        DirectoriesChecked = outcome.DirectoriesChecked;
        InaccessibleCount = outcome.InaccessibleTotal;
        CurrentPath = string.Empty;
        _luaFilesChecked = outcome.LuaFilesChecked;
        _peFilesChecked = outcome.PeFilesChecked;
        _hashChecksPerformed = outcome.HashChecksPerformed;
        _signatureChecksPerformed = outcome.SignatureChecksPerformed;
        _reparsePointsSkipped = outcome.ReparsePointsSkipped;
        _cloudFilesSkipped = outcome.CloudFilesSkipped;
        FindingLimitReached = outcome.FindingLimitReached;
        InaccessibleTruncationNote = outcome.InaccessibleListTruncated
            ? $"The list below shows the first {AppFormat.Count(outcome.InaccessibleAreas.Count)} of {AppFormat.Count(outcome.InaccessibleTotal)} inaccessible items. The count is complete; the path list is capped for display."
            : string.Empty;

        Findings.Clear();
        foreach (var finding in outcome.Findings
                     .OrderByDescending(f => f.Risk)
                     .ThenBy(f => f.Category)
                     .ThenBy(f => f.FileName, StringComparer.OrdinalIgnoreCase))
        {
            Findings.Add(finding);
        }

        InaccessibleAreas.Clear();
        foreach (var area in outcome.InaccessibleAreas) InaccessibleAreas.Add(area);

        HasScanOutcome = true;
        ScanElapsedText = AppFormat.Duration(outcome.Duration);
        LastScanText = $"{(outcome.Cancelled ? "Stopped" : "Completed")} {AppFormat.Date(outcome.CompletedUtc)} · {AppFormat.Duration(outcome.Duration)}";
        ScannedAreasDisplay = string.Join("  ·  ", outcome.Roots);
        var high = outcome.Findings.Count(f => f.Risk == RiskLevel.High);
        var medium = outcome.Findings.Count(f => f.Risk == RiskLevel.Medium);
        var low = outcome.Findings.Count - high - medium;
        var limitNote = outcome.FindingLimitReached
            ? " The finding display reached its 1,000-item cap; additional matches were not listed."
            : string.Empty;
        var inaccessibleNote = outcome.InaccessibleTotal > 0
            ? $" {AppFormat.Count(outcome.InaccessibleTotal)} file{(outcome.InaccessibleTotal == 1 ? "" : "s")} or folder{(outcome.InaccessibleTotal == 1 ? "" : "s")} could not be fully read."
            : " No inaccessible items were reported.";
        var hashNote = _indicators.HasKnownHashes
            ? $" {AppFormat.Count(outcome.HashChecksPerformed)} SHA-256 checks were performed."
            : " No known-hash list is configured in this build, so hash matching was not used.";
        ScanSummaryText = outcome.Cancelled
            ? $"The scan was cancelled after checking {AppFormat.Count(outcome.FilesChecked)} files. Results are partial.{inaccessibleNote}{limitNote}"
            : $"Checked {AppFormat.Count(outcome.FilesChecked)} files in {AppFormat.Duration(outcome.Duration)}. " +
              $"{high} high, {medium} medium, and {low} low or informational item{(outcome.Findings.Count == 1 ? "" : "s")} were flagged.{inaccessibleNote}{limitNote}{hashNote} " +
              "This does not guarantee that the PC is clean.";

        RaiseScanCounters();
        OnPropertyChanged(nameof(LiveScanMetrics));
        OnPropertyChanged(nameof(LuaFilesCheckedText));
        OnPropertyChanged(nameof(PeFilesCheckedText));
        OnPropertyChanged(nameof(HashChecksText));
        OnPropertyChanged(nameof(SignatureChecksText));
        OnPropertyChanged(nameof(ReparseSkippedText));
        OnPropertyChanged(nameof(CloudFilesSkippedText));
        OnPropertyChanged(nameof(ShowResults));
        CloseResultsCommand.RaiseCanExecuteChanged();
    }

    private void CancelScan()
    {
        if (!IsScanning) return;
        _scanCts?.Cancel();
        ScanSummaryText = "Cancelling the scan and waiting for the current file operation to stop…";
        OnPropertyChanged(nameof(ScanStatusDetail));
    }

    private void CloseResults()
    {
        if (!HasScanOutcome && Findings.Count == 0) return;
        var confirmed = MessageDialog.Show(Owner, "Close scan results",
            "This removes all findings, scan counts, and inaccessible-area details from this session. Nothing is saved, so these results cannot be reopened after closing them.",
            "Close results", "Keep results", warning: true);
        if (!confirmed) return;
        CloseResultsInternal();
        OnPropertyChanged(nameof(ScanStatusDetail));
    }

    private void CloseResultsInternal()
    {
        Findings.Clear();
        InaccessibleAreas.Clear();
        InaccessibleTruncationNote = string.Empty;
        InaccessibleCount = 0;
        FilesChecked = 0;
        DirectoriesChecked = 0;
        FindingLimitReached = false;
        _peFilesChecked = 0;
        _luaFilesChecked = 0;
        _hashChecksPerformed = 0;
        _signatureChecksPerformed = 0;
        _reparsePointsSkipped = 0;
        _cloudFilesSkipped = 0;
        CurrentPath = string.Empty;
        ScanSummaryText = string.Empty;
        ScanElapsedText = "0s";
        LastScanText = string.Empty;
        ScannedAreasDisplay = string.Empty;
        ScanScopeDisplay = string.Empty;
        HasScanOutcome = false;
        if (!IsScanning) ScanState = ScanUiState.Idle;
        RaiseScanCounters();
        OnPropertyChanged(nameof(LiveScanMetrics));
        OnPropertyChanged(nameof(LuaFilesCheckedText));
        OnPropertyChanged(nameof(PeFilesCheckedText));
        OnPropertyChanged(nameof(HashChecksText));
        OnPropertyChanged(nameof(SignatureChecksText));
        OnPropertyChanged(nameof(ReparseSkippedText));
        OnPropertyChanged(nameof(CloudFilesSkippedText));
        OnPropertyChanged(nameof(ShowResults));
    }

    public FindingFilterOption SelectedFilter
    {
        get => _selectedFilter;
        set
        {
            if (!SetProperty(ref _selectedFilter, value)) return;
            FindingsView.Refresh();
            OnPropertyChanged(nameof(HasVisibleFindings));
            OnPropertyChanged(nameof(FindingsEmptyText));
        }
    }

    public bool HasVisibleFindings => !FindingsView.IsEmpty;
    public string FindingsEmptyText => Findings.Count == 0
        ? (IsScanning ? "Findings will appear here as the scan proceeds." :
            HasScanOutcome ? "No items were flagged in this scan. This does not guarantee that the PC is clean." :
            "Run a scan to review files on this PC.")
        : "No findings match this filter.";

    private bool FilterFinding(object item)
    {
        if (item is not ScanFinding finding) return false;
        return SelectedFilter.Key switch
        {
            "executor" => finding.Category == FindingCategory.ExecutorIndicator,
            "script" => finding.Category == FindingCategory.ScriptReview,
            "malware" => finding.Category == FindingCategory.MalwareIndicator,
            _ => true
        };
    }

    private static Window? Owner => Application.Current?.MainWindow;

    private void OpenFindingDetails(ScanFinding? finding)
    {
        if (finding is null) return;
        FindingDetailsWindow.Show(Owner, finding, EffectiveReduceMotion);
    }

    private void OpenFindingLocation(ScanFinding? finding)
    {
        if (finding is null) return;
        var confirmed = MessageDialog.Show(Owner, "Open File Location",
            "This opens File Explorer with the item selected. WTX PC CHECK will not run, change, delete, or quarantine the file. Files can still be dangerous if you choose to open them yourself.",
            "Open File Location", "Cancel", warning: true);
        if (!confirmed) return;
        if (!WindowsIntegration.OpenFileLocation(finding.FullPath, out var error))
            MessageDialog.Show(Owner, "Location unavailable", error, "OK", null, warning: true);
    }

    private void OpenStartupLocation(StartupEntry? entry)
    {
        if (entry?.ExecutablePath is null)
        {
            MessageDialog.Show(Owner, "No executable path",
                "The startup command did not contain a path that WTX PC CHECK could resolve. Review the command text in the security section.",
                "OK", null);
            return;
        }

        var confirmed = MessageDialog.Show(Owner, "Open File Location",
            "This opens File Explorer with the startup executable selected. WTX PC CHECK will not run, change, delete, or quarantine the file.",
            "Open File Location", "Cancel", warning: entry.Risk >= RiskLevel.Medium);
        if (!confirmed) return;
        if (!WindowsIntegration.OpenFileLocation(entry.ExecutablePath, out var error))
            MessageDialog.Show(Owner, "Location unavailable", error, "OK", null, warning: true);
    }

    public bool IsDefenderScanning { get; private set; }
    public DefenderScanResult DefenderResult
    {
        get => _defenderResult;
        private set
        {
            if (!SetProperty(ref _defenderResult, value)) return;
            OnPropertyChanged(nameof(DefenderResultSummary));
            OnPropertyChanged(nameof(DefenderResultTone));
        }
    }
    public string DefenderResultSummary => DefenderResult.Summary;
    public string DefenderResultTone => DefenderResult.State switch
    {
        DefenderScanState.NoThreats => "Positive",
        DefenderScanState.ThreatsFound => "Warning",
        DefenderScanState.Failed or DefenderScanState.Cancelled => "Danger",
        DefenderScanState.Running => "Active",
        _ => "Neutral"
    };
    public string DefenderProgressText
    {
        get => _defenderProgressText;
        private set => SetProperty(ref _defenderProgressText, value);
    }

    private async Task RunDefenderScanAsync()
    {
        if (IsBusy) return;
        var localRoots = Drives.Where(d => d.IsSelected && d.DriveType != DriveType.Network)
            .Select(d => d.RootPath).ToList();
        if (localRoots.Count == 0)
        {
            MessageDialog.Show(Owner, "Select a local drive",
                "Windows Defender cannot scan a network location through this action. Select at least one fixed or removable local drive.",
                "OK", null, warning: true);
            return;
        }

        if (!PrivacyDialog.Show(Owner, EffectiveReduceMotion)) return;

        var confirmed = MessageDialog.Show(Owner, "Run a Windows Defender scan",
            "Windows Defender will use its own engine to scan the selected local drives. A full custom scan can take a long time. WTX PC CHECK passes the no-remediation option for this custom scan, so Defender will report detections instead of applying actions. Windows real-time protection can still act according to your Windows settings. WTX PC CHECK shows Defender's exit result, not a fabricated list of detections. Continue?",
            "Run Defender scan", "Cancel", warning: true);
        if (!confirmed) return;

        Navigate("scan");
        _defenderCts = new CancellationTokenSource();
        IsDefenderScanning = true;
        OnPropertyChanged(nameof(IsDefenderScanning));
        OnPropertyChanged(nameof(IsBusy));
        RaiseBusyCommands();
        _defenderStopwatch = Stopwatch.StartNew();
        _defenderTimer.Start();
        DefenderResult = new DefenderScanResult
        {
            State = DefenderScanState.Running,
            Summary = "Windows Defender is running a custom scan with remediation disabled. This can take a long time.",
            StartedUtc = DateTimeOffset.UtcNow
        };
        _defenderCurrentRoot = localRoots[0];
        DefenderProgressText = $"Windows Defender is scanning {_defenderCurrentRoot} · 0s";

        var progress = new Progress<DefenderProgress>(value =>
        {
            if (!IsDefenderScanning) return;
            _defenderCurrentRoot = value.CurrentRoot;
            DefenderProgressText = $"Windows Defender is scanning {value.CurrentRoot} ({value.CurrentRootIndex} of {value.TotalRoots}) · {AppFormat.Duration(value.Elapsed)}";
        });

        try
        {
            var result = await _defenderService.RunSelectedDrivesAsync(localRoots, progress, _defenderCts.Token);
            DefenderResult = result;
            if (result.State == DefenderScanState.ThreatsFound)
            {
                var open = MessageDialog.Show(Owner, "Windows Defender reported a result",
                    result.Summary + " Open Windows Security for Defender's own detection details.",
                    "Open Windows Security", "Close", warning: true);
                if (open) OpenWindowsSecurity();
            }
            else if (result.State == DefenderScanState.Failed || result.State == DefenderScanState.NotAvailable)
            {
                var open = MessageDialog.Show(Owner, "Windows Defender scan did not complete",
                    result.Summary, "Open Windows Security", "Close", warning: true);
                if (open) OpenWindowsSecurity();
            }
        }
        catch (OperationCanceledException)
        {
            DefenderResult = new DefenderScanResult
            {
                State = DefenderScanState.Cancelled,
                Summary = "The Windows Defender scan was cancelled. Its result is incomplete.",
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }
        catch
        {
            DefenderResult = new DefenderScanResult
            {
                State = DefenderScanState.Failed,
                Summary = "Windows Defender could not be run. Open Windows Security to run a scan from there.",
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }
        finally
        {
            _defenderTimer.Stop();
            _defenderStopwatch?.Stop();
            _defenderCts?.Dispose();
            _defenderCts = null;
            IsDefenderScanning = false;
            OnPropertyChanged(nameof(IsDefenderScanning));
            OnPropertyChanged(nameof(IsBusy));
            DefenderProgressText = string.Empty;
            RaiseBusyCommands();
            if (_deferredUpdatePrompt && !IsBusy) await PromptForUpdateRestartAsync();
        }
    }

    private void CancelDefenderScan()
    {
        if (!IsDefenderScanning) return;
        _defenderCts?.Cancel();
        DefenderProgressText = "Cancelling the Windows Defender scan…";
    }

    private void RaiseBusyCommands()
    {
        StartScanCommand.RaiseCanExecuteChanged();
        CancelScanCommand.RaiseCanExecuteChanged();
        RunDefenderScanCommand.RaiseCanExecuteChanged();
        CancelDefenderScanCommand.RaiseCanExecuteChanged();
        RefreshSecurityCommand.RaiseCanExecuteChanged();
        InstallUpdateCommand.RaiseCanExecuteChanged();
        RefreshDrivesCommand.RaiseCanExecuteChanged();
        SelectFixedDrivesCommand.RaiseCanExecuteChanged();
        ClearDriveSelectionCommand.RaiseCanExecuteChanged();
        CloseResultsCommand.RaiseCanExecuteChanged();
    }

    public bool IsSecurityChecking => _isSecurityChecking;
    public SecurityOverview Security
    {
        get => _security;
        private set
        {
            if (!SetProperty(ref _security, value)) return;
            RaiseSecurityProperties();
        }
    }

    private void RaiseSecurityProperties()
    {
        OnPropertyChanged(nameof(WindowsStatusText));
        OnPropertyChanged(nameof(WindowsSupportText));
        OnPropertyChanged(nameof(DefenderStatusText));
        OnPropertyChanged(nameof(DefenderDetailText));
        OnPropertyChanged(nameof(FirewallStatusText));
        OnPropertyChanged(nameof(FirewallDetailText));
        OnPropertyChanged(nameof(UpdatesStatusText));
        OnPropertyChanged(nameof(UpdatesDetailText));
        OnPropertyChanged(nameof(SecurityCheckedText));
        OnPropertyChanged(nameof(SecurityStateLabel));
        OnPropertyChanged(nameof(SecurityTone));
        OnPropertyChanged(nameof(RegisteredAntivirusText));
        OnPropertyChanged(nameof(StartupEntries));
        OnPropertyChanged(nameof(HasStartupEntries));
        OnPropertyChanged(nameof(StartupSummaryText));
        OnPropertyChanged(nameof(StartupNote));
        OnPropertyChanged(nameof(SecurityErrorText));
    }

    public string WindowsStatusText => $"{Security.WindowsDisplay} · {Security.WindowsBuildDisplay}";
    public string WindowsSupportText => Security.WindowsSupported
        ? "Windows 10 22H2 or Windows 11 is supported."
        : "This Windows version is older than the supported target. Some checks may be unavailable.";
    public string DefenderStatusText => Security.State is SecurityQueryState.NotChecked
        ? "Not checked yet"
        : Security.State is SecurityQueryState.Checking ? "Checking…" : Security.Defender.Summary;
    public string DefenderDetailText
    {
        get
        {
            if (Security.State is SecurityQueryState.NotChecked) return "Windows Defender status will appear after the check.";
            if (Security.State is SecurityQueryState.Checking) return "Reading status from Windows Security.";
            if (!Security.Defender.Available) return Security.Defender.Note;
            var parts = new List<string>();
            if (Security.Defender.SignatureVersion is not null) parts.Add($"Signature {Security.Defender.SignatureVersion}");
            if (Security.Defender.SignatureUpdated is not null) parts.Add($"Updated {AppFormat.Date(Security.Defender.SignatureUpdated.Value)}");
            if (Security.Defender.TamperProtectionEnabled == true) parts.Add("Tamper protection on");
            return parts.Count > 0 ? string.Join(" · ", parts) : Security.Defender.Note;
        }
    }
    public string FirewallStatusText => Security.State is SecurityQueryState.NotChecked
        ? "Not checked yet"
        : Security.State is SecurityQueryState.Checking ? "Checking…" : Security.Firewall.Summary;
    public string FirewallDetailText => Security.State is SecurityQueryState.NotChecked
        ? "Windows Firewall status will appear after the check."
        : Security.State is SecurityQueryState.Checking
            ? "Reading status from Windows Firewall."
            : Security.Firewall.Available
                ? $"Domain: {OnOff(Security.Firewall.DomainEnabled)} · Private: {OnOff(Security.Firewall.PrivateEnabled)} · Public: {OnOff(Security.Firewall.PublicEnabled)}"
                : Security.Firewall.Note;
    public string UpdatesStatusText => Security.State is SecurityQueryState.NotChecked
        ? "Not checked yet"
        : Security.State is SecurityQueryState.Checking ? "Checking…" : Security.Updates.Summary;
    public string UpdatesDetailText => Security.State is SecurityQueryState.NotChecked
        ? "A Windows Update search will run separately from the file scan."
        : Security.State is SecurityQueryState.Checking
            ? "Searching for offered updates through Windows Update."
            : Security.Updates.Note;
    public string SecurityCheckedText => Security.State switch
    {
        SecurityQueryState.Checking => "Checking Windows security status…",
        SecurityQueryState.Available when Security.CheckedUtc is not null => $"Checked {AppFormat.Relative(Security.CheckedUtc)}",
        SecurityQueryState.Unavailable => "Security status is partially unavailable.",
        _ => "Security status has not been checked yet."
    };
    public string SecurityStateLabel => Security.State switch
    {
        SecurityQueryState.Checking => "Checking",
        SecurityQueryState.Available => "Checked",
        SecurityQueryState.Unavailable => "Limited",
        _ => "Not checked"
    };
    public string SecurityTone => Security.State switch
    {
        SecurityQueryState.Checking => "Active",
        SecurityQueryState.Available => "Neutral",
        SecurityQueryState.Unavailable => "Warning",
        _ => "Neutral"
    };
    public string RegisteredAntivirusText => Security.State is SecurityQueryState.NotChecked
        ? "Antivirus registration will appear after the check."
        : Security.State is SecurityQueryState.Checking
            ? "Reading registered antivirus products…"
            : Security.RegisteredAntivirus.Count == 0
                ? "No antivirus product was listed by Windows Security."
                : $"Registered with Windows Security: {string.Join(", ", Security.RegisteredAntivirus)}";
    public IReadOnlyList<StartupEntry> StartupEntries => Security.StartupEntries;
    public bool HasStartupEntries => Security.StartupEntries.Count > 0;
    public string StartupSummaryText => Security.StartupEntryCount == 0
        ? "No startup entries were found in the locations checked."
        : $"{Security.StartupEntryCount} startup entr{(Security.StartupEntryCount == 1 ? "y" : "ies")} found in the locations checked." +
          (Security.StartupListTruncated ? " The list is capped at 50 entries." : "");
    public string StartupNote => Security.StartupNote;
    public string SecurityErrorText => Security.ErrorEnglish ?? string.Empty;

    private static string OnOff(bool? value) => value switch
    {
        true => "On",
        false => "Off",
        _ => "Unknown"
    };

    public async Task RefreshSecurityAsync()
    {
        if (_isSecurityChecking) return;
        _securityCts?.Cancel();
        _securityCts?.Dispose();
        _securityCts = new CancellationTokenSource();
        var token = _securityCts.Token;
        _isSecurityChecking = true;
        OnPropertyChanged(nameof(IsSecurityChecking));
        Security.State = SecurityQueryState.Checking;
        RaiseSecurityProperties();
        RefreshSecurityCommand.RaiseCanExecuteChanged();
        try
        {
            var result = await _securityService.GetOverviewAsync(token);
            if (!token.IsCancellationRequested)
            {
                Security = result;
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch
        {
            if (!token.IsCancellationRequested)
            {
                Security.State = SecurityQueryState.Unavailable;
                Security.ErrorEnglish = "Windows security information could not be read. Some checks may be unavailable on this PC.";
                RaiseSecurityProperties();
            }
        }
        finally
        {
            _isSecurityChecking = false;
            OnPropertyChanged(nameof(IsSecurityChecking));
            RaiseSecurityProperties();
            RefreshSecurityCommand.RaiseCanExecuteChanged();
        }
    }

    private void OpenWindowsSecurity()
    {
        if (!WindowsIntegration.OpenWindowsSecurity(out var error))
            MessageDialog.Show(Owner, "Windows Security unavailable", error, "OK", null, warning: true);
    }

    private void OpenWindowsUpdate()
    {
        if (!WindowsIntegration.OpenWindowsUpdate(out var error))
            MessageDialog.Show(Owner, "Windows Update unavailable", error, "OK", null, warning: true);
    }

    private void OpenLocalDataFolder()
    {
        if (!WindowsIntegration.OpenLocalDataFolder(out var error))
            MessageDialog.Show(Owner, "Settings folder unavailable", error, "OK", null, warning: true);
    }

    public string SettingsPathDisplay => AppPaths.SettingsFile;
    public string DataDirectoryDisplay => AppPaths.LocalDataDirectory;

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
            if (!value)
            {
                _updateCts?.Cancel();
                if (CanInstallUpdate)
                    SetUpdate(UpdateState.ReadyToInstall, $"Update {_pendingVersion} is verified and ready. You can restart and install it now.", _pendingVersion);
                else
                    SetUpdate(UpdateState.Disabled, "Automatic updates are off. You can still check for updates manually.");
            }
            else
            {
                if (!_updateConfiguration.IsConfigured)
                    SetUpdate(UpdateState.NotConfigured, UpdateConfigurationMessage());
                else if (!_updateBusy)
                    _ = CheckForUpdatesAsync(automatic: true);
            }
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
            OnPropertyChanged(nameof(ReduceMotionDetail));
            SaveSettings();
        }
    }

    public bool EffectiveReduceMotion => Settings.ReduceMotion || !SystemParameters.ClientAreaAnimation;
    public string ReduceMotionDetail => Settings.ReduceMotion
        ? "Reduced motion is on. Scan-line and page animations are disabled."
        : SystemParameters.ClientAreaAnimation
            ? "Short fades and scan activity may be shown. Windows animations are enabled."
            : "Windows reports that animations are disabled, so WTX PC CHECK is already reducing motion.";

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

    private void SetUpdateInterval(string? hours)
    {
        if (int.TryParse(hours, out var value) && value is 1 or 6 or 12 or 24)
            UpdateIntervalHours = value;
    }

    private void ConfigureUpdateTimer()
    {
        _updateTimer.Stop();
        if (!Settings.AutomaticUpdates || !_updateConfiguration.IsConfigured) return;
        _updateTimer.Interval = TimeSpan.FromHours(Math.Clamp(Settings.UpdateIntervalHours, 1, 24));
        _updateTimer.Start();
    }

    private void SaveSettings()
    {
        if (!_settingsService.TrySave(Settings))
        {
            AddNotice("Preferences could not be saved. Changes will apply for this session only. No scan data is stored either way.");
        }
    }

    public UpdateSnapshot Update
    {
        get => _update;
        private set
        {
            if (!SetProperty(ref _update, value)) return;
            OnPropertyChanged(nameof(UpdateMessage));
            OnPropertyChanged(nameof(UpdateStateLabel));
            OnPropertyChanged(nameof(UpdateTone));
            OnPropertyChanged(nameof(UpdateProgressPercent));
            OnPropertyChanged(nameof(UpdateProgressText));
            OnPropertyChanged(nameof(UpdateProgressIsIndeterminate));
            OnPropertyChanged(nameof(UpdateShowProgress));
            OnPropertyChanged(nameof(UpdateLatestVersionText));
            OnPropertyChanged(nameof(LastUpdateCheckText));
            OnPropertyChanged(nameof(CanInstallUpdate));
            OnPropertyChanged(nameof(IsUpdateBusy));
            OnPropertyChanged(nameof(UpdateButtonLabel));
            InstallUpdateCommand?.RaiseCanExecuteChanged();
            CheckUpdatesCommand?.RaiseCanExecuteChanged();
        }
    }

    public string UpdateMessage => Update.Message;
    public string UpdateStateLabel => Update.State switch
    {
        UpdateState.NotConfigured => "Not configured",
        UpdateState.Disabled => "Off",
        UpdateState.Checking => "Checking…",
        UpdateState.UpToDate => "Up to date",
        UpdateState.Downloading => "Downloading…",
        UpdateState.ReadyToInstall => "Update ready",
        UpdateState.Failed => "Update failed",
        UpdateState.Applying => "Installing…",
        _ => "Not checked"
    };
    public string UpdateTone => Update.State switch
    {
        UpdateState.UpToDate => "Positive",
        UpdateState.ReadyToInstall => "Warning",
        UpdateState.Failed => "Danger",
        UpdateState.NotConfigured => "Warning",
        UpdateState.Checking or UpdateState.Downloading or UpdateState.Applying => "Active",
        _ => "Neutral"
    };
    public bool IsUpdateBusy => _updateBusy;
    public double UpdateProgressPercent => Update.ProgressPercent ?? 0;
    public bool UpdateProgressIsIndeterminate => Update.ProgressPercent is null;
    public bool UpdateShowProgress => Update.State == UpdateState.Downloading && Update.ProgressPercent is not null;
    public string UpdateProgressText
    {
        get
        {
            if (Update.State != UpdateState.Downloading) return string.Empty;
            if (Update.TotalBytes is > 0)
                return $"{AppFormat.Bytes(Update.BytesReceived)} of {AppFormat.Bytes(Update.TotalBytes.Value)}";
            return Update.BytesReceived > 0 ? $"{AppFormat.Bytes(Update.BytesReceived)} downloaded" : string.Empty;
        }
    }
    public string UpdateLatestVersionText => Update.LatestVersion is null ? string.Empty : $"Version {Update.LatestVersion}";
    public string LastUpdateCheckText => Update.CheckedUtc is null
        ? "Last check: never"
        : $"Last check: {AppFormat.Relative(Update.CheckedUtc)}";
    public bool CanInstallUpdate => _pendingStagedPath is not null && Update.State == UpdateState.ReadyToInstall;
    public string UpdateButtonLabel => CanInstallUpdate ? "Restart and install" : "Check for updates";
    public string UpdateSourceDisplay => _updateConfiguration.IsConfigured ? _updateConfiguration.ManifestUrl : "Not configured (placeholder)";
    public string UpdateSignerDisplay => _updateConfiguration.IsConfigured
        ? _updateConfiguration.ExpectedThumbprint
        : "Not configured (placeholder)";
    public string UpdateConfigurationStatus
    {
        get
        {
            _updateConfiguration.Validate(out var reason);
            return _updateConfiguration.IsConfigured
                ? "Update source and publisher pin are configured. Updates are verified by HTTPS, SHA-256, and Authenticode with a pinned certificate."
                : reason;
        }
    }
    public string UpdateConfigurationTone => _updateConfiguration.IsConfigured ? "Positive" : "Warning";

    private void ApplyInitialUpdate(UpdateCheckOutcome? outcome)
    {
        if (outcome is not null)
        {
            if (outcome.NotConfigured)
            {
                SetUpdate(UpdateState.NotConfigured, outcome.Message);
                return;
            }
            Settings.LastUpdateCheckUtc = DateTimeOffset.UtcNow;
            SaveSettings();
            if (outcome.UpdateAvailable && string.IsNullOrWhiteSpace(outcome.StagedExePath) && outcome.Manifest is not null)
            {
                _startupDownloadManifest = outcome.Manifest;
                SetUpdate(UpdateState.Checking,
                    $"Update {outcome.Manifest.Version} is available. The verified download will start after the app opens.",
                    outcome.Manifest.Version, DateTimeOffset.UtcNow);
                return;
            }
            if (outcome.UpdateAvailable)
            {
                _pendingStagedPath = outcome.StagedExePath;
                _pendingSha256 = outcome.StagedSha256;
                _pendingVersion = outcome.Manifest?.Version;
                _pendingReleaseNotes = outcome.Manifest?.ReleaseNotes;
                SetUpdate(UpdateState.ReadyToInstall,
                    $"Update {_pendingVersion} was downloaded and its publisher signature was verified. Restart to install it.",
                    _pendingVersion, DateTimeOffset.UtcNow, 100);
                _deferredUpdatePrompt = true;
                return;
            }
            if (outcome.Succeeded)
            {
                SetUpdate(UpdateState.UpToDate, outcome.Message, outcome.Manifest?.Version,
                    DateTimeOffset.UtcNow, 100);
                return;
            }
            SetUpdate(UpdateState.Failed, outcome.Message, null, DateTimeOffset.UtcNow);
            return;
        }

        RefreshUpdateConfigurationState();
    }

    private void RefreshUpdateConfigurationState()
    {
        if (!_updateConfiguration.IsConfigured)
            SetUpdate(UpdateState.NotConfigured, UpdateConfigurationMessage());
        else if (!AutomaticUpdates)
            SetUpdate(UpdateState.Disabled, "Automatic updates are off. You can still check for updates manually.");
        else
            SetUpdate(UpdateState.Idle, "Updates have not been checked in this session yet.");
    }

    private string UpdateConfigurationMessage()
    {
        _updateConfiguration.Validate(out var reason);
        return $"Automatic updates are not configured in this build. {reason} The app will continue to work offline.";
    }

    private void SetUpdate(UpdateState state, string message, string? latestVersion = null,
        DateTimeOffset? checkedUtc = null, double? percent = null)
    {
        Update = new UpdateSnapshot
        {
            State = state,
            Message = message,
            LatestVersion = latestVersion,
            CheckedUtc = checkedUtc ?? Update.CheckedUtc,
            ProgressPercent = percent,
            BytesReceived = Update.BytesReceived,
            TotalBytes = Update.TotalBytes,
            ReleaseNotes = Update.ReleaseNotes
        };
    }

    public async Task HandleStartupAsync()
    {
        _ = RefreshSecurityAsync();
        if (_startupDownloadManifest is not null)
        {
            var manifest = _startupDownloadManifest;
            _startupDownloadManifest = null;
            await DownloadPendingManifestAsync(manifest);
        }
        if (_deferredUpdatePrompt && CanInstallUpdate)
            await PromptForUpdateRestartAsync();
    }

    private async Task DownloadPendingManifestAsync(UpdateManifest manifest)
    {
        if (_updateBusy) return;
        _updateBusy = true;
        OnPropertyChanged(nameof(IsUpdateBusy));
        CheckUpdatesCommand.RaiseCanExecuteChanged();
        SetUpdate(UpdateState.Downloading, $"Downloading update {manifest.Version}…", manifest.Version);
        _updateCts?.Dispose();
        _updateCts = new CancellationTokenSource();
        var token = _updateCts.Token;
        var progress = new Progress<UpdateProgress>(value =>
        {
            if (token.IsCancellationRequested) return;
            Update = new UpdateSnapshot
            {
                State = UpdateState.Downloading,
                Message = value.Status,
                LatestVersion = manifest.Version,
                ProgressPercent = value.Percent,
                BytesReceived = value.BytesReceived,
                TotalBytes = value.TotalBytes,
                CheckedUtc = Update.CheckedUtc,
                ReleaseNotes = manifest.ReleaseNotes
            };
        });
        try
        {
            var outcome = await _updateService.DownloadAndStageAsync(manifest, progress, token);
            Settings.LastUpdateCheckUtc = DateTimeOffset.UtcNow;
            SaveSettings();
            if (outcome.UpdateAvailable)
            {
                _pendingStagedPath = outcome.StagedExePath;
                _pendingSha256 = outcome.StagedSha256;
                _pendingVersion = outcome.Manifest?.Version ?? manifest.Version;
                _pendingReleaseNotes = outcome.Manifest?.ReleaseNotes ?? manifest.ReleaseNotes;
                SetUpdate(UpdateState.ReadyToInstall,
                    $"Update {_pendingVersion} was downloaded and its publisher signature was verified.",
                    _pendingVersion, DateTimeOffset.UtcNow, 100);
                OnPropertyChanged(nameof(CanInstallUpdate));
                InstallUpdateCommand.RaiseCanExecuteChanged();
                _deferredUpdatePrompt = true;
            }
            else
            {
                SetUpdate(UpdateState.Failed, outcome.Message);
            }
        }
        catch (OperationCanceledException)
        {
            if (!_disposed) SetUpdate(UpdateState.Idle, "The update download was cancelled. The app remains usable offline.");
        }
        catch
        {
            SetUpdate(UpdateState.Failed, "The update download failed. The app remains usable offline.");
        }
        finally
        {
            _updateBusy = false;
            OnPropertyChanged(nameof(IsUpdateBusy));
            CheckUpdatesCommand.RaiseCanExecuteChanged();
            InstallUpdateCommand.RaiseCanExecuteChanged();
            _updateCts?.Dispose();
            _updateCts = null;
        }
    }

    private async Task CheckForUpdatesAsync(bool automatic)
    {
        if (_updateBusy || CanInstallUpdate) return;
        if (!_updateConfiguration.IsConfigured)
        {
            SetUpdate(UpdateState.NotConfigured, UpdateConfigurationMessage());
            return;
        }

        _updateBusy = true;
        OnPropertyChanged(nameof(IsUpdateBusy));
        CheckUpdatesCommand.RaiseCanExecuteChanged();
        SetUpdate(UpdateState.Checking, automatic
            ? "Checking for updates automatically…"
            : "Checking for updates…");
        _updateCts?.Dispose();
        _updateCts = new CancellationTokenSource();
        var token = _updateCts.Token;
        var checkStarted = DateTimeOffset.UtcNow;
        var progress = new Progress<UpdateProgress>(value =>
        {
            if (token.IsCancellationRequested) return;
            Update = new UpdateSnapshot
            {
                State = value.Percent is null && value.BytesReceived == 0 ? UpdateState.Checking : UpdateState.Downloading,
                Message = value.Status,
                LatestVersion = Update.LatestVersion,
                ProgressPercent = value.Percent,
                BytesReceived = value.BytesReceived,
                TotalBytes = value.TotalBytes,
                CheckedUtc = Update.CheckedUtc,
                ReleaseNotes = Update.ReleaseNotes
            };
        });

        try
        {
            var outcome = await _updateService.CheckAndStageAsync(progress, token);
            Settings.LastUpdateCheckUtc = DateTimeOffset.UtcNow;
            SaveSettings();
            if (outcome.NotConfigured)
            {
                SetUpdate(UpdateState.NotConfigured, outcome.Message, null, checkStarted);
            }
            else if (outcome.UpdateAvailable)
            {
                _pendingStagedPath = outcome.StagedExePath;
                _pendingSha256 = outcome.StagedSha256;
                _pendingVersion = outcome.Manifest?.Version;
                _pendingReleaseNotes = outcome.Manifest?.ReleaseNotes;
                SetUpdate(UpdateState.ReadyToInstall,
                    $"Update {_pendingVersion} was downloaded and its publisher signature was verified.",
                    _pendingVersion, checkStarted, 100);
                await PromptForUpdateRestartAsync();
            }
            else if (outcome.Succeeded)
            {
                SetUpdate(UpdateState.UpToDate, outcome.Message, outcome.Manifest?.Version, checkStarted, 100);
            }
            else
            {
                SetUpdate(UpdateState.Failed, outcome.Message, null, checkStarted);
            }
        }
        catch (OperationCanceledException)
        {
            if (!_disposed)
                SetUpdate(UpdateState.Idle, "The update check was cancelled. The app remains usable offline.");
        }
        catch
        {
            SetUpdate(UpdateState.Failed, "The update check failed. The app remains usable offline.", null, checkStarted);
        }
        finally
        {
            _updateBusy = false;
            OnPropertyChanged(nameof(IsUpdateBusy));
            CheckUpdatesCommand.RaiseCanExecuteChanged();
            InstallUpdateCommand.RaiseCanExecuteChanged();
            _updateCts?.Dispose();
            _updateCts = null;
        }
    }

    private async Task PromptForUpdateRestartAsync()
    {
        if (!CanInstallUpdate)
        {
            _deferredUpdatePrompt = false;
            return;
        }
        if (IsBusy)
        {
            _deferredUpdatePrompt = true;
            return;
        }
        _deferredUpdatePrompt = false;
        var confirmed = UpdateRestartDialog.Show(Owner, _pendingVersion ?? "new version", _pendingReleaseNotes, EffectiveReduceMotion);
        if (confirmed)
        {
            await ApplyStagedUpdateAsync();
        }
        else
        {
            UpdateService.CleanupStaging(_pendingStagedPath);
            _pendingStagedPath = null;
            _pendingSha256 = null;
            _pendingVersion = null;
            _pendingReleaseNotes = null;
            SetUpdate(UpdateState.Idle, "The verified update was not installed. You can check for updates again later.");
            OnPropertyChanged(nameof(CanInstallUpdate));
            InstallUpdateCommand.RaiseCanExecuteChanged();
        }
    }

    private async Task InstallPendingUpdateAsync()
    {
        if (!CanInstallUpdate || _pendingStagedPath is null || _pendingSha256 is null) return;
        if (IsBusy)
        {
            _deferredUpdatePrompt = true;
            return;
        }

        var confirmed = UpdateRestartDialog.Show(Owner, _pendingVersion ?? "new version", _pendingReleaseNotes, EffectiveReduceMotion);
        if (!confirmed) return;
        await ApplyStagedUpdateAsync();
    }

    private async Task ApplyStagedUpdateAsync()
    {
        if (!CanInstallUpdate || _pendingStagedPath is null || _pendingSha256 is null) return;
        SetUpdate(UpdateState.Applying, "Preparing to restart and install the verified update…", _pendingVersion);
        var (started, error) = await _updateApplyService.StartApplyAsync(
            _pendingStagedPath, _pendingSha256, _pendingVersion ?? "unknown", CancellationToken.None);
        if (!started)
        {
            SetUpdate(UpdateState.Failed, error);
            MessageDialog.Show(Owner, "Update could not start", error, "OK", null, warning: true);
            return;
        }

        Application.Current.Shutdown();
    }

    private void SystemParameters_StaticPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SystemParameters.ClientAreaAnimation))
        {
            OnPropertyChanged(nameof(EffectiveReduceMotion));
            OnPropertyChanged(nameof(ReduceMotionDetail));
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _updateTimer.Stop();
        _scanTimer.Stop();
        _defenderTimer.Stop();
        _scanCts?.Cancel();
        _defenderCts?.Cancel();
        _securityCts?.Cancel();
        _updateCts?.Cancel();
        _scanCts?.Dispose();
        _defenderCts?.Dispose();
        _securityCts?.Dispose();
        _updateCts?.Dispose();
        _updateService.Dispose();
        SystemParameters.StaticPropertyChanged -= SystemParameters_StaticPropertyChanged;
        foreach (var drive in Drives) drive.PropertyChanged -= DriveOnPropertyChanged;
    }
}









