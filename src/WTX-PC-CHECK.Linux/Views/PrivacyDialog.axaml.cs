using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace WtxPcCheck.Linux.Views;

public partial class PrivacyDialog : Window
{
    private readonly CheckBox _confirmBox;
    private readonly Button _startScanButton;
    public PrivacyDialog()
    {
        InitializeComponent();
        _confirmBox = this.FindControl<CheckBox>("ConfirmBox")!;
        _startScanButton = this.FindControl<Button>("StartScanButton")!;
        _confirmBox.IsCheckedChanged += (_, _) => _startScanButton.IsEnabled = _confirmBox.IsChecked == true;
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Cancel_Click(object? sender, RoutedEventArgs e) => Close(false);
    private void StartScan_Click(object? sender, RoutedEventArgs e)
    {
        if (_confirmBox.IsChecked == true) Close(true);
    }
}

