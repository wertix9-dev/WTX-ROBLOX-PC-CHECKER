using System.Windows;
using System.Windows.Threading;
using WtxPcCheck.Models;
using WtxPcCheck.Services;
using WtxPcCheck.ViewModels;
using WtxPcCheck.Views;

namespace WtxPcCheck;

public partial class App : Application
{
    private MainViewModel? _viewModel;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        DispatcherUnhandledException += (_, args) =>
        {
            args.Handled = true;
            try
            {
                MessageDialog.Show(MainWindow, "Unexpected error",
                    "WTX PC CHECK encountered an unexpected error. No scan data was saved, and no file was changed. The app will close.",
                    "Close", null, warning: true);
            }
            catch
            {
            }
            Shutdown(1);
        };
        TaskScheduler.UnobservedTaskException += (_, args) => args.SetObserved();
        AppDomain.CurrentDomain.UnhandledException += (_, _) => { };

        UpdateService.CleanupOldStaging();
        var splash = new SplashWindow(!SystemParameters.ClientAreaAnimation);
        splash.Show();
        splash.SetStatus("Loading settings…", "Reading local preferences only. No scan data is loaded.");
        await Dispatcher.Yield(DispatcherPriority.Background);

        var loaded = await Task.Run(() => new SettingsService().Load());
        var reduceMotion = loaded.Settings.ReduceMotion || !SystemParameters.ClientAreaAnimation;
        splash.SetReducedMotion(reduceMotion);

        UpdateCheckOutcome? initialUpdate = null;
        var notice = loaded.Warning;
        var previousUpdate = UpdateApplyService.ReadAndConsumeState();
        var updateNotice = UpdateApplyService.DescribeStartupState(previousUpdate);
        if (!string.IsNullOrWhiteSpace(updateNotice))
        {
            notice = string.IsNullOrWhiteSpace(notice) ? updateNotice : $"{notice} {updateNotice}";
        }

        if (loaded.Settings.AutomaticUpdates)
        {
            splash.SetStatus("Checking for updates…", "The app can continue offline if the update source is unavailable.");
            await Dispatcher.Yield(DispatcherPriority.Background);
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                using var updateService = new UpdateService(new UpdateConfiguration());
                initialUpdate = await updateService.CheckOnlyAsync(cts.Token);
                if (initialUpdate.NotConfigured)
                {
                    splash.SetStatus("Update source not configured.", "Continuing offline. A maintainer can configure signed updates later.");
                }
                else if (initialUpdate.UpdateAvailable)
                {
                    splash.SetStatus($"Update {initialUpdate.Manifest?.Version} found.", "The verified download can start after the app opens.");
                }
                else if (initialUpdate.Succeeded)
                {
                    splash.SetStatus("WTX PC CHECK is up to date.", "Opening the local dashboard.");
                }
                else
                {
                    splash.SetStatus("Update check did not complete.", "Continuing offline. You can try again in Settings.");
                }
            }
            catch (OperationCanceledException)
            {
                initialUpdate = new UpdateCheckOutcome
                {
                    Message = "The startup update check timed out. The app can continue offline."
                };
                splash.SetStatus("Update check timed out.", "Continuing offline. You can try again in Settings.");
            }
            catch
            {
                initialUpdate = new UpdateCheckOutcome
                {
                    Message = "The startup update check failed. The app can continue offline."
                };
                splash.SetStatus("Could not check for updates.", "Continuing offline. You can try again in Settings.");
            }
        }
        else
        {
            splash.SetStatus("Automatic updates are off.", "Opening the local dashboard.");
        }

        splash.Close();
        _viewModel = new MainViewModel(loaded.Settings, notice, initialUpdate);
        var window = new MainWindow(_viewModel);
        MainWindow = window;
        window.Show();
        ShutdownMode = ShutdownMode.OnMainWindowClose;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _viewModel?.Dispose();
        base.OnExit(e);
    }
}




