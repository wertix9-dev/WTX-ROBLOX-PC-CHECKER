using System.IO;
using System.Windows;

namespace WtxPcCheck;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0].Equals("--self-test", StringComparison.OrdinalIgnoreCase))
        {
            var output = args.Length > 1
                ? args[1]
                : Path.Combine(Path.GetTempPath(), "wtx-selftest.txt");
            return SelfTest.Run(output);
        }

        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }
}

