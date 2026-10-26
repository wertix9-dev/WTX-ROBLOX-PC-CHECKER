using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using WtxPcCheck.Linux.Services;
using WtxPcCheck.Linux.ViewModels;
using WtxPcCheck.Linux.Views;

namespace WtxPcCheck.Linux;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override async void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var splash = new SplashWindow(false);
            desktop.MainWindow = splash;
            splash.Show();
            splash.SetStatus("Loading settings...", "Reading local preferences only. No scan data is loaded.");
            await Task.Yield();
            var settings = await Task.Run(() => new LinuxSettingsService().Load());
            var configuration = new LinuxUpdateConfiguration();
            if (!configuration.IsConfigured)
                splash.SetStatus("Update source not configured.", "Continuing offline. Signed updates can be configured by the maintainer.");
            else if (settings.AutomaticUpdates)
                splash.SetStatus("Updates are configured.", "The update check continues after the local app opens.");
            else
                splash.SetStatus("Automatic updates are off.", "Opening the local dashboard.");
            splash.SetStatus("Preparing local scan engine...", "No scan starts automatically.");
            var viewModel = new MainViewModel(settings);
            var main = new MainWindow(viewModel);
            desktop.MainWindow = main;
            main.Show();
            splash.Close();
            desktop.ShutdownMode = ShutdownMode.OnMainWindowClose;
        }
        base.OnFrameworkInitializationCompleted();
    }
}
