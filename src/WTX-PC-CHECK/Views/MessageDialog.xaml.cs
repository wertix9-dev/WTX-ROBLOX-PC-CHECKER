using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace WtxPcCheck.Views;

public partial class MessageDialog : Window
{
    private bool _result;

    public MessageDialog()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            MaxHeight = Math.Max(300, SystemParameters.WorkArea.Height - 48);
            PrimaryButton.Focus();
        };
    }

    public static bool Show(Window? owner, string title, string message, string primaryLabel = "OK",
        string? secondaryLabel = null, bool warning = false)
    {
        var dialog = new MessageDialog();
        dialog.TitleText.Text = title;
        dialog.MessageText.Text = message;
        dialog.PrimaryButton.Content = primaryLabel;
        if (secondaryLabel is null)
        {
            dialog.SecondaryButton.Visibility = Visibility.Collapsed;
        }
        else
        {
            dialog.SecondaryButton.Content = secondaryLabel;
        }

        if (warning)
        {
            dialog.IconPath.Stroke = new SolidColorBrush(Color.FromRgb(0xE8, 0xB0, 0x4B));
            dialog.IconBorder.Background = new SolidColorBrush(Color.FromRgb(0x2C, 0x24, 0x16));
            dialog.IconBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5B, 0x48, 0x25));
        }

        if (owner is not null && owner.IsVisible)
        {
            dialog.Owner = owner;
            dialog.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }
        else
        {
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }

        dialog.ShowDialog();
        return dialog._result;
    }

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            _result = false;
            Close();
        }
    }

    private void Primary_Click(object sender, RoutedEventArgs e)
    {
        _result = true;
        Close();
    }

    private void Secondary_Click(object sender, RoutedEventArgs e)
    {
        _result = false;
        Close();
    }
}
