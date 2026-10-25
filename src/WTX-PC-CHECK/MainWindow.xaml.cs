using System.ComponentModel;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using WtxPcCheck.ViewModels;

namespace WtxPcCheck;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private bool _scanAnimationRunning;

    public MainWindow(MainViewModel viewModel)
    {
        _viewModel = viewModel;
        InitializeComponent();
        DataContext = viewModel;
        Loaded += MainWindow_Loaded;
        StateChanged += (_, _) => UpdateMaximizeGlyph();
        _viewModel.PropertyChanged += ViewModel_PropertyChanged;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        var workArea = SystemParameters.WorkArea;
        Width = Math.Max(MinWidth, Math.Min(Width, workArea.Width - 32));
        Height = Math.Max(MinHeight, Math.Min(Height, workArea.Height - 32));
        Left = workArea.Left + Math.Max(0, (workArea.Width - Width) / 2);
        Top = workArea.Top + Math.Max(0, (workArea.Height - Height) / 2);

        if (!_viewModel.EffectiveReduceMotion)
        {
            PageHost.Opacity = 0;
            PageHost.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            });
        }

        UpdateScanAnimation();
        await _viewModel.HandleStartupAsync();
    }

    private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(MainViewModel.CurrentPageKey):
                AnimatePage();
                break;
            case nameof(MainViewModel.IsScanning):
            case nameof(MainViewModel.EffectiveReduceMotion):
                UpdateScanAnimation();
                break;
            case nameof(MainViewModel.HasScanOutcome) when _viewModel.HasScanOutcome:
                AnimateResults();
                break;
        }
    }

    private void AnimatePage()
    {
        if (_viewModel.EffectiveReduceMotion)
        {
            PageHost.Opacity = 1;
            PageHost.RenderTransform = Transform.Identity;
            return;
        }

        var translate = new TranslateTransform(0, 8);
        PageHost.RenderTransform = translate;
        PageHost.BeginAnimation(OpacityProperty, new DoubleAnimation(0.35, 1, TimeSpan.FromMilliseconds(180))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        });
        translate.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(8, 0, TimeSpan.FromMilliseconds(180))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        });
    }

    private void AnimateResults()
    {
        if (_viewModel.EffectiveReduceMotion) return;
        FindingsList.Opacity = 0;
        FindingsList.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        });
    }

    private void UpdateScanAnimation()
    {
        if (_viewModel.IsScanning && !_viewModel.EffectiveReduceMotion)
        {
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded, new Action(StartScanAnimation));
        }
        else
        {
            StopScanAnimation();
        }
    }

    private void StartScanAnimation()
    {
        if (_scanAnimationRunning || !_viewModel.IsScanning || _viewModel.EffectiveReduceMotion) return;
        _scanAnimationRunning = true;
        var track = ScanLine.Parent as FrameworkElement;
        var target = Math.Max(320, track?.ActualWidth ?? 860);
        var animation = new DoubleAnimation(-ScanLine.Width, target, TimeSpan.FromMilliseconds(1500))
        {
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        ScanLineTransform.BeginAnimation(TranslateTransform.XProperty, animation);
    }

    private void StopScanAnimation()
    {
        _scanAnimationRunning = false;
        ScanLineTransform.BeginAnimation(TranslateTransform.XProperty, null);
        ScanLineTransform.X = 0;
    }

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source && FindAncestor<ButtonBase>(source) is not null) return;
        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void ToggleMaximize()
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match) return match;
            current = VisualTreeHelper.GetParent(current);
        }
        return null;
    }

    private void UpdateMaximizeGlyph()
    {
        if (MaximizeGlyph is null) return;
        MaximizeGlyph.Data = Geometry.Parse(WindowState == WindowState.Maximized
            ? "M6,9 H13 V16 H6 Z M9,6 H16 V13"
            : "M4,4 H16 V16 H4 Z");
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        _viewModel.PropertyChanged -= ViewModel_PropertyChanged;
        _viewModel.Dispose();
    }
}
