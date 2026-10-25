using System.Windows;
using System.Windows.Media.Animation;

namespace WtxPcCheck.Views;

public partial class SplashWindow : Window
{
    private bool _reduceMotion;
    private Storyboard? _outerStoryboard;
    private Storyboard? _innerStoryboard;

    public SplashWindow(bool reduceMotion)
    {
        _reduceMotion = reduceMotion;
        InitializeComponent();
        Loaded += OnLoaded;
    }

    public void SetStatus(string status, string? detail = null)
    {
        StatusText.Text = status;
        if (detail is not null) DetailText.Text = detail;
    }

    public void SetReducedMotion(bool reduceMotion)
    {
        _reduceMotion = reduceMotion;
        if (reduceMotion)
        {
            _outerStoryboard?.Stop(this);
            _innerStoryboard?.Stop(this);
            RingRotate.Angle = 0;
            InnerRingRotate.Angle = 120;
        }
        else if (IsLoaded)
        {
            StartAnimations();
        }
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (!_reduceMotion) StartAnimations();
    }

    private void StartAnimations()
    {
        if (_outerStoryboard is not null) return;

        var outer = new DoubleAnimation(0, 360, TimeSpan.FromMilliseconds(1500))
        {
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseInOut }
        };
        Storyboard.SetTarget(outer, RingRotate);
        Storyboard.SetTargetProperty(outer, new PropertyPath("Angle"));
        _outerStoryboard = new Storyboard();
        _outerStoryboard.Children.Add(outer);
        _outerStoryboard.Begin(this, true);

        var inner = new DoubleAnimation(120, 480, TimeSpan.FromMilliseconds(2200))
        {
            RepeatBehavior = RepeatBehavior.Forever
        };
        Storyboard.SetTarget(inner, InnerRingRotate);
        Storyboard.SetTargetProperty(inner, new PropertyPath("Angle"));
        _innerStoryboard = new Storyboard();
        _innerStoryboard.Children.Add(inner);
        _innerStoryboard.Begin(this, true);
    }

    protected override void OnClosed(EventArgs e)
    {
        _outerStoryboard?.Stop(this);
        _innerStoryboard?.Stop(this);
        base.OnClosed(e);
    }
}
