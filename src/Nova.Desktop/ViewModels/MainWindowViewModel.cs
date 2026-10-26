using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed partial class NavItemViewModel(string key, string title, MaterialIconKind icon, PageViewModel page) : ObservableObject
{
    public string Key { get; } = key;
    public string Title { get; } = title;
    public MaterialIconKind Icon { get; } = icon;
    public PageViewModel Page { get; } = page;

    [ObservableProperty] private int _badge;
    public bool HasBadge => Badge > 0;
    partial void OnBadgeChanged(int value) => OnPropertyChanged(nameof(HasBadge));

    public override string ToString() => Title;
}

public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly NovaCore _core;

    public MainWindowViewModel(NovaCore core)
    {
        _core = core;
        AppServices.Shell = this;

        Home = new DashboardViewModel(core);
        Scan = new ScanViewModel(core);
        Web = new WebSafetyViewModel(core);
        Network = new NetworkViewModel(core);
        Breach = new BreachViewModel(core);
        Privacy = new PrivacyViewModel(core);
        Center = new SecurityCenterViewModel(core);
        Settings = new SettingsViewModel(core);
        if (NovaCore.HasWindowsTools)
        {
            Audit = new SecurityAuditViewModel(core);
            Cleaner = new CleanerViewModel(core);
            Updater = new UpdaterViewModel(core);
        }

        NavItems =
        [
            new("home", "Ana Ekran", MaterialIconKind.ViewDashboardOutline, Home),
            new("scan", "Virüs Taraması", MaterialIconKind.ShieldSearch, Scan),
            new("web", "Web Güvenliği", MaterialIconKind.Web, Web),
            new("network", "Ağ Güvenliği", MaterialIconKind.WifiLock, Network),
            new("breach", "Veri İhlali", MaterialIconKind.EmailAlertOutline, Breach),
            new("privacy", "Gizlilik ve Başlangıç", MaterialIconKind.ShieldAccountOutline, Privacy)
        ];
        if (Audit is not null && Cleaner is not null && Updater is not null)
        {
            NavItems.Add(new("audit", "Güvenlik Denetimi", MaterialIconKind.ClipboardCheckOutline, Audit));
            NavItems.Add(new("cleaner", "Temizleyici", MaterialIconKind.Broom, Cleaner));
            NavItems.Add(new("updater", "Yazılım Güncelleyici", MaterialIconKind.PackageUp, Updater));
        }
        NavItems.Add(new("center", "Güvenlik Merkezi", MaterialIconKind.ShieldHalfFull, Center));
        NavItems.Add(new("settings", "Ayarlar", MaterialIconKind.CogOutline, Settings));
        _selectedNav = NavItems[0];
        _currentPage = Home;

        core.Events.Changed += (_, _) => OnUi(RefreshBadges);
        core.History.Changed += (_, _) => OnUi(RefreshStatus);
        core.Quarantine.Changed += (_, _) => OnUi(RefreshStatus);
        core.RealTime.StateChanged += (_, _) => OnUi(RefreshStatus);
        core.Settings.Changed += (_, _) => OnUi(RefreshStatus);
        RefreshBadges();
        RefreshStatus();
    }

    public DashboardViewModel Home { get; }
    public ScanViewModel Scan { get; }
    public WebSafetyViewModel Web { get; }
    public NetworkViewModel Network { get; }
    public BreachViewModel Breach { get; }
    public PrivacyViewModel Privacy { get; }
    public SecurityCenterViewModel Center { get; }
    public SettingsViewModel Settings { get; }
    public SecurityAuditViewModel? Audit { get; }
    public CleanerViewModel? Cleaner { get; }
    public UpdaterViewModel? Updater { get; }

    public ObservableCollection<NavItemViewModel> NavItems { get; }
    public ObservableCollection<ToastViewModel> Toasts => AppServices.Toasts.Items;

    public string Version => $"v{typeof(MainWindowViewModel).Assembly.GetName().Version?.ToString(3)} · {NovaCore.PlatformName}";
    public bool IsMac => OperatingSystem.IsMacOS();
    public bool IsWindows => OperatingSystem.IsWindows();

    [ObservableProperty] private NavItemViewModel? _selectedNav;
    [ObservableProperty] private PageViewModel _currentPage;
    [ObservableProperty] private ConfirmDialogViewModel? _dialog;
    [ObservableProperty] private int _unreadCount;
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private string _statusTone = Tone.Success;
    [ObservableProperty] private MaterialIconKind _statusIcon = MaterialIconKind.ShieldCheck;

    public bool HasUnread => UnreadCount > 0;
    public bool HasDialog => Dialog is not null;
    public string UnreadText => UnreadCount > 99 ? "99+" : UnreadCount.ToString();

    partial void OnUnreadCountChanged(int value)
    {
        OnPropertyChanged(nameof(HasUnread));
        OnPropertyChanged(nameof(UnreadText));
    }

    partial void OnDialogChanged(ConfirmDialogViewModel? value) => OnPropertyChanged(nameof(HasDialog));

    partial void OnSelectedNavChanged(NavItemViewModel? value)
    {
        if (value is null) return;
        CurrentPage = value.Page;
        value.Page.OnNavigatedTo();
    }

    public void Navigate(string key)
    {
        var item = NavItems.FirstOrDefault(n => n.Key == key);
        if (item is null) return;
        if (SelectedNav == item) item.Page.OnNavigatedTo();
        else SelectedNav = item;
    }

    [RelayCommand]
    private void Go(string key) => Navigate(key);

    [RelayCommand]
    private void OpenNotifications()
    {
        Center.SelectedTab = 0;
        Navigate("center");
    }

    public void ResolveIssue(string key)
    {
        switch (key)
        {
            case "threats":
                Center.SelectedTab = 0;
                Navigate("center");
                break;
            case "realtime":
                _core.RealTime.SetEnabled(true);
                AppServices.Toasts.Show("Gerçek zamanlı koruma açıldı", "Yeni dosyalar anında taranıyor.", Tone.Success, force: true);
                break;
            case "scan":
                Navigate("scan");
                Scan.QuickScanCommand.Execute(null);
                break;
            case "signatures":
                Navigate("scan");
                Scan.UpdateSignaturesCommand.Execute(null);
                break;
            case "network":
                Navigate("network");
                break;
            case "audit":
                Navigate("audit");
                break;
        }
    }

    private void RefreshBadges()
    {
        UnreadCount = _core.Events.UnreadCount;
        var center = NavItems.First(n => n.Key == "center");
        center.Badge = _core.History.UnresolvedThreats.Count;
    }

    public void NotifyStatusChanged() => OnUi(RefreshStatus);

    private void RefreshStatus()
    {
        var status = _core.GetStatus();
        StatusText = status.Headline;
        (StatusTone, StatusIcon) = status.Level switch
        {
            ProtectionLevel.AtRisk => (Tone.Danger, MaterialIconKind.ShieldAlert),
            ProtectionLevel.Attention => (Tone.Warning, MaterialIconKind.ShieldAlertOutline),
            _ => (Tone.Success, MaterialIconKind.ShieldCheck)
        };
        RefreshBadges();
    }
}
