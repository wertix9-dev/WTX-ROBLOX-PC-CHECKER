using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Media;

namespace WtxPcCheck.Linux.Views;

public partial class MessageDialog : Window
{
    private bool _result;
    private readonly TextBlock _titleText;
    private readonly TextBlock _messageText;
    private readonly TextBlock _iconText;
    private readonly Button _primaryButton;
    private readonly Button _secondaryButton;
    public MessageDialog()
    {
        InitializeComponent();
        _titleText = this.FindControl<TextBlock>("TitleText")!;
        _messageText = this.FindControl<TextBlock>("MessageText")!;
        _iconText = this.FindControl<TextBlock>("IconText")!;
        _primaryButton = this.FindControl<Button>("PrimaryButton")!;
        _secondaryButton = this.FindControl<Button>("SecondaryButton")!;
    }
    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    public static async Task<bool> ShowAsync(Window? owner, string title, string message, string primaryLabel = "OK", string? secondaryLabel = null, bool warning = false)
    {
        var dialog = new MessageDialog();
        dialog._titleText.Text = title;
        dialog._messageText.Text = message;
        dialog._primaryButton.Content = primaryLabel;
        if (secondaryLabel is null) dialog._secondaryButton.IsVisible = false;
        else dialog._secondaryButton.Content = secondaryLabel;
        if (warning) dialog._iconText.Foreground = new SolidColorBrush(Color.Parse("#E8B04B"));
        if (owner is not null) await dialog.ShowDialog<bool?>(owner);
        else dialog.Show();
        return dialog._result;
    }

    private void Primary_Click(object? sender, RoutedEventArgs e) { _result = true; Close(); }
    private void Secondary_Click(object? sender, RoutedEventArgs e) { _result = false; Close(); }
}

