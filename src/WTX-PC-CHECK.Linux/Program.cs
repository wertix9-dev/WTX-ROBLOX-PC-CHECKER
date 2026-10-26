using Avalonia;

namespace WtxPcCheck.Linux;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0].Equals("--self-test", StringComparison.OrdinalIgnoreCase))
        {
            var output = args.Length > 1 ? args[1] : Path.Combine(Path.GetTempPath(), "wtx-linux-selftest.txt");
            return LinuxSelfTest.Run(output);
        }
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return 0;
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}

