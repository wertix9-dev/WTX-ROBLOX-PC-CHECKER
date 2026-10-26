using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using WtxPcCheck.Models;
using WtxPcCheck.Services;

namespace WtxPcCheck.Linux.Views;

public partial class FindingDetailsWindow : Window
{
    private readonly ScanFinding _finding;
    private readonly CheckBox _previewConfirm;
    private readonly Button _loadPreviewButton;
    private readonly TextBlock _previewNote;
    private readonly TextBox _previewBox;
    public FindingDetailsWindow(ScanFinding finding)
    {
        _finding = finding;
        InitializeComponent();
        DataContext = finding;
        _previewConfirm = this.FindControl<CheckBox>("PreviewConfirm")!;
        _loadPreviewButton = this.FindControl<Button>("LoadPreviewButton")!;
        _previewNote = this.FindControl<TextBlock>("PreviewNote")!;
        _previewBox = this.FindControl<TextBox>("PreviewBox")!;
        _previewConfirm.IsCheckedChanged += (_, _) => _loadPreviewButton.IsEnabled = _previewConfirm.IsChecked == true;
    }
    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    public static async Task ShowAsync(Window? owner, ScanFinding finding, bool reduceMotion)
    {
        var window = new FindingDetailsWindow(finding);
        if (owner is not null) await window.ShowDialog(owner);
        else window.Show();
    }

    private void LoadPreview_Click(object? sender, RoutedEventArgs e)
    {
        var preview = ScriptPreviewService.TryRead(_finding.FullPath);
        _previewNote.Text = preview.Note;
        if (preview.Success)
        {
            _previewBox.Text = preview.Text;
            _previewBox.IsVisible = true;
            _loadPreviewButton.IsEnabled = false;
        }
    }

    private async void OpenLocation_Click(object? sender, RoutedEventArgs e)
    {
        var confirmed = await MessageDialog.ShowAsync(this, "Open File Location", "This opens the parent folder in your file manager. WTX PC CHECK will not execute or open the file as an application.", "Open folder", "Cancel", true);
        if (!confirmed) return;
        var (ok, error) = await LinuxDialogs.OpenLocationAsync(_finding.FullPath);
        if (!ok) await MessageDialog.ShowAsync(this, "Location unavailable", error, "OK", null, true);
    }

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();
}

