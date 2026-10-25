using System.Windows;
using System.Windows.Input;

namespace WtxPcCheck.Views;

public partial class PrivacyDialog : Window
{
    public PrivacyDialog()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            MaxHeight = Math.Max(440, SystemParameters.WorkArea.Height - 48);
            Height = Math.Min(Height, MaxHeight);
            ConfirmBox.Focus();
        };
    }

    public static bool Show(Window? owner, bool reduceMotion)
    {
        var dialog = new PrivacyDialog();
        if (owner is not null && owner.IsVisible)
        {
            dialog.Owner = owner;
            dialog.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }
        else
        {
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }
        return dialog.ShowDialog() == true;
    }

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            DialogResult = false;
            Close();
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void StartScan_Click(object sender, RoutedEventArgs e)
    {
        if (ConfirmBox.IsChecked != true) return;
        DialogResult = true;
        Close();
    }
}
