using Avalonia;
using Avalonia.Media;
using Nova.Core;

namespace Nova.Desktop;

internal static class Program
{
    public const string FontFamilyUri = "avares://NovaDesktopSecurity/Assets/Fonts#Poppins";

    public static bool StartMinimized { get; private set; }

    public static string? StartPage { get; private set; }

    public static string ActivationSignalPath => Path.Combine(AppPaths.Root, "activate.signal");

    [STAThread]
    public static int Main(string[] args)
    {
        StartMinimized = args.Contains("--minimized", StringComparer.OrdinalIgnoreCase);
        StartPage = args.FirstOrDefault(a => a.StartsWith("--page=", StringComparison.OrdinalIgnoreCase))?["--page=".Length..];

        using var mutex = new Mutex(true, "NovaDesktopSecurity.SingleInstance", out var isFirst);
        if (!isFirst && args.Contains("--wait-for-previous", StringComparer.OrdinalIgnoreCase))
        {
            try { isFirst = mutex.WaitOne(TimeSpan.FromSeconds(10)); }
            catch (AbandonedMutexException) { isFirst = true; }
        }
        if (!isFirst)
        {
            try { File.WriteAllText(ActivationSignalPath, DateTime.UtcNow.ToString("O")); } catch { }
            return 0;
        }

        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new FontManagerOptions { DefaultFamilyName = FontFamilyUri })
            .With(new MacOSPlatformOptions { ShowInDock = true })
            .LogToTrace();
}
