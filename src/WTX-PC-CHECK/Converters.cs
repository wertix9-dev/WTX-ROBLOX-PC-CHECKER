using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using WtxPcCheck.Models;

namespace WtxPcCheck;

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var flag = value is bool b && b;
        if (parameter is string text && text.Equals("invert", StringComparison.OrdinalIgnoreCase)) flag = !flag;
        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : true;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : true;
}

public sealed class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => string.IsNullOrWhiteSpace(value as string) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class RiskToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush High = new(Color.FromRgb(0xF0, 0x6A, 0x6A));
    private static readonly SolidColorBrush Medium = new(Color.FromRgb(0xE8, 0xB0, 0x4B));
    private static readonly SolidColorBrush Low = new(Color.FromRgb(0x8F, 0xA6, 0xB0));
    private static readonly SolidColorBrush Info = new(Color.FromRgb(0x7F, 0x91, 0x99));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var risk = value is RiskLevel level ? level : RiskLevel.Info;
        var brush = risk switch
        {
            RiskLevel.High => High,
            RiskLevel.Medium => Medium,
            RiskLevel.Low => Low,
            _ => Info
        };
        if (parameter is string mode && mode.Equals("soft", StringComparison.OrdinalIgnoreCase))
        {
            var c = brush.Color;
            return new SolidColorBrush(Color.FromArgb(30, c.R, c.G, c.B));
        }
        return brush;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class ToneToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Positive = new(Color.FromRgb(0xA6, 0xE2, 0x2E));
    private static readonly SolidColorBrush Warning = new(Color.FromRgb(0xE8, 0xB0, 0x4B));
    private static readonly SolidColorBrush Danger = new(Color.FromRgb(0xF0, 0x6A, 0x6A));
    private static readonly SolidColorBrush Active = new(Color.FromRgb(0x2F, 0xD4, 0xC4));
    private static readonly SolidColorBrush Neutral = new(Color.FromRgb(0x7F, 0x91, 0x99));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var tone = value as string ?? "Neutral";
        var brush = tone switch
        {
            "Positive" => Positive,
            "Warning" => Warning,
            "Danger" => Danger,
            "Active" => Active,
            _ => Neutral
        };
        if (parameter is string mode && mode.Equals("soft", StringComparison.OrdinalIgnoreCase))
        {
            var c = brush.Color;
            return new SolidColorBrush(Color.FromArgb(26, c.R, c.G, c.B));
        }
        return brush;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var visible = value is int count && count > 0;
        if (parameter is string text && text.Equals("invert", StringComparison.OrdinalIgnoreCase)) visible = !visible;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

