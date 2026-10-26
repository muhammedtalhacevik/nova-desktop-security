using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform;
using Avalonia.Threading;
using Material.Icons;
using Nova.Core;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;
using Nova.Desktop.ViewModels;
using Nova.Desktop.Views;

namespace Nova.Desktop;

public partial class App : Application
{
    private NovaCore _core = null!;
    private MainWindow _window = null!;
    private IClassicDesktopStyleApplicationLifetime? _desktop;
    private NativeMenuItem? _realTimeItem;
    private FileSystemWatcher? _activationWatcher;
    private bool _exiting;
    private bool _trayHintShown;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            _desktop = desktop;
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;

            _core = new NovaCore();
            AppServices.Core = _core;

            var shell = new MainWindowViewModel(_core);
            _window = new MainWindow { DataContext = shell };
            AppServices.MainWindow = _window;
            _window.Closing += OnWindowClosing;

            if (!Program.StartMinimized)
                desktop.MainWindow = _window;

            SetupTray();
            SetupMacMenu();
            WatchActivationSignal();

            _core.RealTime.ThreatBlocked += (_, e) => AppServices.Toasts.Show(
                e.Quarantined ? "Tehdit engellendi" : "Tehdit algılandı",
                $"{e.Threat.FileName} — {e.Threat.ThreatName}" + (e.Quarantined ? " karantinaya alındı." : ". İşlem yapmanız gerekiyor."),
                Tone.Danger, MaterialIconKind.ShieldAlert,
                () => { ShowWindow(); AppServices.Shell.Navigate("center"); },
                force: true);
            _core.RealTime.StateChanged += (_, _) => Dispatcher.UIThread.Post(UpdateTrayState);

            _core.Automation.ScheduledScanHandler = type => Dispatcher.UIThread.InvokeAsync(() => shell.Scan.TryStartAutomated(type)).GetTask();
            _core.Automation.NewDriveHandler = path => Dispatcher.UIThread.InvokeAsync(() => shell.Scan.ScanNewDriveAsync(path));

            _core.Start();
            UpdateTrayState();
            if (Program.StartPage is { Length: > 0 } page)
                Dispatcher.UIThread.Post(() => shell.Navigate(page), DispatcherPriority.Background);
            desktop.Exit += (_, _) => _core.Dispose();
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void OnWindowClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_exiting) return;
        if (_core.Settings.Current.MinimizeToTray)
        {
            e.Cancel = true;
            _window.Hide();
            if (!_trayHintShown)
            {
                _trayHintShown = true;
                AppServices.Toasts.Show("Nova arka planda çalışıyor",
                    "Gerçek zamanlı koruma etkin kalır. Açmak için sistem tepsisindeki Nova simgesine tıklayın.", Tone.Accent, force: true);
            }
            return;
        }
        Exit();
    }

    public void ShowWindow()
    {
        if (_desktop is not null && _desktop.MainWindow is null) _desktop.MainWindow = _window;
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    public void ExitApplication() => Exit();

    private void Exit()
    {
        _exiting = true;
        _activationWatcher?.Dispose();
        _core.Dispose();
        _desktop?.Shutdown();
    }

    private void SetupTray()
    {
        var open = new NativeMenuItem("Nova'yı Aç");
        open.Click += (_, _) => ShowWindow();

        var quick = new NativeMenuItem("Hızlı Tarama");
        quick.Click += (_, _) =>
        {
            ShowWindow();
            AppServices.Shell.Navigate("scan");
            AppServices.Shell.Scan.QuickScanCommand.Execute(null);
        };

        _realTimeItem = new NativeMenuItem("Gerçek Zamanlı Koruma") { ToggleType = NativeMenuItemToggleType.CheckBox };
        _realTimeItem.Click += (_, _) => _core.RealTime.SetEnabled(!_core.RealTime.IsRunning);

        var center = new NativeMenuItem("Güvenlik Merkezi");
        center.Click += (_, _) => { ShowWindow(); AppServices.Shell.Navigate("center"); };

        var exit = new NativeMenuItem("Çıkış");
        exit.Click += (_, _) => Exit();

        var tray = new TrayIcon
        {
            Icon = new WindowIcon(AssetLoader.Open(new Uri(OperatingSystem.IsWindows()
                ? "avares://NovaDesktopSecurity/Assets/nova.ico"
                : "avares://NovaDesktopSecurity/Assets/nova-logo-256.png"))),
            ToolTipText = "Nova Desktop Security",
            Menu = new NativeMenu
            {
                Items = { open, quick, new NativeMenuItemSeparator(), _realTimeItem, center, new NativeMenuItemSeparator(), exit }
            }
        };
        tray.Clicked += (_, _) => ShowWindow();
        TrayIcon.SetIcons(this, new TrayIcons { tray });
    }

    private void UpdateTrayState()
    {
        if (_realTimeItem is not null) _realTimeItem.IsChecked = _core.RealTime.IsRunning;
        if (TrayIcon.GetIcons(this) is { Count: > 0 } icons)
            icons[0].ToolTipText = _core.RealTime.IsRunning ? "Nova Desktop Security — Koruma etkin" : "Nova Desktop Security — Gerçek zamanlı koruma kapalı";
    }

    private void SetupMacMenu()
    {
        if (!OperatingSystem.IsMacOS()) return;
        var about = new NativeMenuItem("Nova Desktop Security Hakkında");
        about.Click += (_, _) => { ShowWindow(); AppServices.Shell.Navigate("settings"); };
        var settings = new NativeMenuItem("Ayarlar…");
        settings.Click += (_, _) => { ShowWindow(); AppServices.Shell.Navigate("settings"); };
        NativeMenu.SetMenu(this, new NativeMenu { Items = { about, new NativeMenuItemSeparator(), settings } });
    }

    private void WatchActivationSignal()
    {
        try
        {
            _activationWatcher = new FileSystemWatcher(AppPaths.Root, Path.GetFileName(Program.ActivationSignalPath))
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime,
                EnableRaisingEvents = true
            };
            _activationWatcher.Changed += (_, _) => Dispatcher.UIThread.Post(ShowWindow);
            _activationWatcher.Created += (_, _) => Dispatcher.UIThread.Post(ShowWindow);
        }
        catch (Exception) { }
    }
}
