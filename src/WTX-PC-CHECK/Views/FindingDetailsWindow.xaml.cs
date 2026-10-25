using System.Windows;
using System.Windows.Input;
using WtxPcCheck.Models;
using WtxPcCheck.Services;

namespace WtxPcCheck.Views;

public partial class FindingDetailsWindow : Window
{
    private readonly ScanFinding _finding;

    public FindingDetailsWindow(ScanFinding finding)
    {
        _finding = finding;
        InitializeComponent();
        DataContext = finding;
        Loaded += (_, _) =>
        {
            MaxHeight = Math.Max(MinHeight, SystemParameters.WorkArea.Height - 32);
            MaxWidth = Math.Max(MinWidth, SystemParameters.WorkArea.Width - 32);
        };
    }

    public static void Show(Window? owner, ScanFinding finding, bool reduceMotion)
    {
        var dialog = new FindingDetailsWindow(finding);
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
    }

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape) Close();
    }

    private void LoadPreview_Click(object sender, RoutedEventArgs e)
    {
        var preview = ScriptPreviewService.TryRead(_finding.FullPath);
        PreviewNote.Text = preview.Note;
        if (preview.Success)
        {
            PreviewBox.Text = preview.Text;
            PreviewBox.Visibility = Visibility.Visible;
            LoadPreviewButton.IsEnabled = false;
        }
        else
        {
            PreviewBox.Visibility = Visibility.Collapsed;
        }
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        var confirmed = MessageDialog.Show(Owner, "Open File Location",
            "This opens File Explorer with the item selected. WTX PC CHECK will not run, change, delete, or quarantine the file. Files can still be dangerous if you choose to open them yourself.",
            "Open File Location", "Cancel", warning: true);
        if (!confirmed) return;
        if (!WindowsIntegration.OpenFileLocation(_finding.FullPath, out var error))
            MessageDialog.Show(Owner, "Location unavailable", error, "OK", null, warning: true);
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}

