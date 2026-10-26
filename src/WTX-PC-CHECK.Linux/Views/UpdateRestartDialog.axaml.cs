using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace WtxPcCheck.Linux.Views;

public partial class UpdateRestartDialog : Window
{
    private bool _confirmed;
    private readonly TextBlock _versionText;
    private readonly TextBlock _notesText;
    public UpdateRestartDialog()
    {
        InitializeComponent();
        _versionText = this.FindControl<TextBlock>("VersionText")!;
        _notesText = this.FindControl<TextBlock>("NotesText")!;
    }
    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
    public static async Task<bool> ShowAsync(Window? owner, string version, string? notes, bool reduceMotion)
    {
        var dialog = new UpdateRestartDialog();
        dialog._versionText.Text = $"Version {version} · Made by WERTIX";
        dialog._notesText.Text = string.IsNullOrWhiteSpace(notes) ? "No release notes were provided by the update server." : notes;
        if (owner is not null) await dialog.ShowDialog<bool?>(owner);
        else dialog.Show();
        return dialog._confirmed;
    }
    private void Later_Click(object? sender, RoutedEventArgs e) { _confirmed = false; Close(); }
    private void Restart_Click(object? sender, RoutedEventArgs e) { _confirmed = true; Close(); }
}

