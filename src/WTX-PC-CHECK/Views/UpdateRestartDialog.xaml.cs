using System.Windows;
using System.Windows.Input;

namespace WtxPcCheck.Views;

public partial class UpdateRestartDialog : Window
{
    private bool _confirmed;

    public UpdateRestartDialog()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            MaxHeight = Math.Max(420, SystemParameters.WorkArea.Height - 48);
            if (string.IsNullOrWhiteSpace(NotesText.Text)) NotesPanel.Visibility = Visibility.Collapsed;
        };
    }

    public static bool Show(Window? owner, string version, string? notes, bool reduceMotion)
    {
        var dialog = new UpdateRestartDialog();
        dialog.VersionText.Text = $"Version {version} · Made by WERTIX";
        dialog.NotesText.Text = string.IsNullOrWhiteSpace(notes)
            ? "No release notes were provided by the update server."
            : notes.Length > 2000 ? notes[..2000] + "\n\n[Release notes truncated]" : notes;
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
        return dialog._confirmed;
    }

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            _confirmed = false;
            Close();
        }
    }

    private void Later_Click(object sender, RoutedEventArgs e)
    {
        _confirmed = false;
        Close();
    }

    private void Restart_Click(object sender, RoutedEventArgs e)
    {
        _confirmed = true;
        Close();
    }
}
