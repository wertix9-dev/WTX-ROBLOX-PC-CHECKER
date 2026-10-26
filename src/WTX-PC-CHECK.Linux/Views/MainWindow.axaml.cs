using System.IO;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using WtxPcCheck.Linux.Models;
using WtxPcCheck.Linux.ViewModels;

namespace WtxPcCheck.Linux.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;

    public MainWindow(MainViewModel viewModel)
    {
        _viewModel = viewModel;
        InitializeComponent();
        DataContext = viewModel;
        Opened += async (_, _) => await _viewModel.HandleStartupAsync();
        _viewModel.PropertyChanged += ViewModel_OnPropertyChanged;
        Closing += (_, _) => { _viewModel.PropertyChanged -= ViewModel_OnPropertyChanged; _viewModel.Dispose(); };
        var findingsFilterList = this.FindControl<ListBox>("FindingsFilterList");
        if (findingsFilterList is not null) findingsFilterList.SelectedIndex = 0;
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void ViewModel_OnPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(MainViewModel.SelectedNav)) return;
        if (_viewModel.EffectiveReduceMotion)
        {
            PagesGrid.Opacity = 1;
            return;
        }
        PagesGrid.Opacity = 0;
        Dispatcher.UIThread.Post(() => PagesGrid.Opacity = 1, DispatcherPriority.Background);
    }

    private void FindingsFilter_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is ListBox { SelectedItem: LinuxFindingFilter filter })
            _viewModel.SelectedFilterKey = filter.Key;
    }

    private void ViewDetailsRow_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: WtxPcCheck.Models.ScanFinding finding })
            _viewModel.ViewDetailsCommand.Execute(finding);
    }

    private void OpenLocationRow_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: WtxPcCheck.Models.ScanFinding finding })
            _viewModel.OpenLocationCommand.Execute(finding);
    }

    private void RemoveCustomFolder_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: WtxPcCheck.ViewModels.ScanLocationOption folder })
            _viewModel.RemoveCustomFolderCommand.Execute(folder);
    }

    private void OpenProcessLocation_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: LinuxProcessInfo process })
            _viewModel.OpenProcessLocationCommand.Execute(process);
    }
}


