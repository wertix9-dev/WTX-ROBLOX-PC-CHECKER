using System;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Threading;

namespace WtxPcCheck.Linux.Views;

public partial class SplashWindow : Window
{
    private readonly RotateTransform? _ring;
    private readonly RotateTransform? _innerRing;
    private readonly TextBlock? _statusText;
    private readonly TextBlock? _detailText;
    private readonly DispatcherTimer _timer;
    private double _angle;
    private bool _reduceMotion;

    public SplashWindow(bool reduceMotion)
    {
        _reduceMotion = reduceMotion;
        InitializeComponent();
        _ring = this.FindControl<Ellipse>("OuterArc")?.RenderTransform as RotateTransform;
        _innerRing = this.FindControl<Ellipse>("InnerArc")?.RenderTransform as RotateTransform;
        _statusText = this.FindControl<TextBlock>("StatusText");
        _detailText = this.FindControl<TextBlock>("DetailText");
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(30) };
        _timer.Tick += (_, _) =>
        {
            if (_ring is null) return;
            _angle = (_angle + 2.2) % 360;
            _ring.Angle = _angle;
            if (_innerRing is not null) _innerRing.Angle = 120 - _angle * 0.6;
        };
        Opened += (_, _) => { if (!_reduceMotion) _timer.Start(); };
        Closed += (_, _) => _timer.Stop();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    public void SetReducedMotion(bool reduceMotion)
    {
        _reduceMotion = reduceMotion;
        if (reduceMotion) _timer.Stop();
        else if (IsVisible) _timer.Start();
    }

    public void SetStatus(string status, string? detail = null)
    {
        if (_statusText is not null) _statusText.Text = status;
        if (detail is not null && _detailText is not null) _detailText.Text = detail;
    }
}


