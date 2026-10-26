using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed partial class DashboardViewModel : PageViewModel
{
    private readonly NovaCore _core;
    private readonly DispatcherTimer _refreshThrottle;
    private bool _syncing;

    public DashboardViewModel(NovaCore core)
    {
        _core = core;
        _refreshThrottle = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        _refreshThrottle.Tick += (_, _) => { _refreshThrottle.Stop(); Refresh(); };

        void Schedule() => OnUi(() => { _refreshThrottle.Stop(); _refreshThrottle.Start(); });
        core.Events.Changed += (_, _) => Schedule();
        core.History.Changed += (_, _) => Schedule();
        core.Quarantine.Changed += (_, _) => Schedule();
        core.RealTime.StateChanged += (_, _) => Schedule();
        core.Settings.Changed += (_, _) => Schedule();

        var live = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        live.Tick += (_, _) => RealTimeDetail = BuildRealTimeDetail();
        live.Start();

        Refresh();
    }

    public override string Title => "Ana Ekran";

    [ObservableProperty] private string _headline = "";
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private string _statusTone = Tone.Success;
    [ObservableProperty] private MaterialIconKind _statusIcon = MaterialIconKind.ShieldCheck;
    [ObservableProperty] private bool _realTimeEnabled;
    [ObservableProperty] private string _realTimeDetail = "";
    [ObservableProperty] private string _lastScanText = "";
    [ObservableProperty] private string _lastScanSub = "";
    [ObservableProperty] private string _threatsText = "0";
    [ObservableProperty] private string _quarantineText = "0";
    [ObservableProperty] private string _signatureText = "";
    [ObservableProperty] private string _filesScannedText = "0";
    [ObservableProperty] private bool _hasIssues;
    [ObservableProperty] private bool _hasEvents;
    [ObservableProperty] private string _greeting = "";

    public ObservableCollection<IssueItemViewModel> Issues { get; } = [];
    public ObservableCollection<EventItemViewModel> RecentEvents { get; } = [];

    public IReadOnlyList<SecurityTip> Tips { get; } =
    [
        new("Güçlü bir VPN kullan", "Halka açık Wi-Fi ağlarında trafiğini güvenilir bir VPN ile şifrele.", MaterialIconKind.ShieldKeyOutline, Tone.Warning),
        new("İşletim sistemini güncel tut", "Güncellemeler, saldırganların kullandığı güvenlik açıklarını kapatır.", MaterialIconKind.Update, Tone.Accent),
        new("Parola yöneticisi kullan", "Her hesap için benzersiz ve uzun parolalar oluştur, aynı parolayı tekrar kullanma.", MaterialIconKind.KeyChain, Tone.Purple),
        new("İki adımlı doğrulamayı aç", "E-posta ve banka hesaplarında 2FA, çalınan parolaya karşı ikinci kilit sağlar.", MaterialIconKind.CellphoneKey, Tone.Success),
        new("Bağlantılara tıklamadan önce kontrol et", "SMS ve e-postadaki kargo / banka bağlantılarını Web Güvenliği ile denetle.", MaterialIconKind.LinkVariant, Tone.Cyan)
    ];

    public override void OnNavigatedTo() => Refresh();

    partial void OnRealTimeEnabledChanged(bool value)
    {
        if (_syncing) return;
        _core.RealTime.SetEnabled(value);
        AppServices.Toasts.Show(value ? "Gerçek zamanlı koruma açıldı" : "Gerçek zamanlı koruma kapatıldı",
            value ? "Yeni ve değişen dosyalar anında taranıyor." : "Cihazınız yeni tehditlere karşı korunmuyor.",
            value ? Tone.Success : Tone.Warning, force: true);
    }

    public void Refresh()
    {
        var status = _core.GetStatus();
        Headline = status.Headline;
        Summary = status.Summary;
        (StatusTone, StatusIcon) = status.Level switch
        {
            ProtectionLevel.AtRisk => (Tone.Danger, MaterialIconKind.ShieldAlert),
            ProtectionLevel.Attention => (Tone.Warning, MaterialIconKind.ShieldAlertOutline),
            _ => (Tone.Success, MaterialIconKind.ShieldCheck)
        };

        Issues.Clear();
        foreach (var i in status.Issues.Take(3)) Issues.Add(new IssueItemViewModel(i));
        HasIssues = Issues.Count > 0;

        _syncing = true;
        RealTimeEnabled = _core.RealTime.IsRunning;
        _syncing = false;
        RealTimeDetail = BuildRealTimeDetail();

        var last = _core.History.Last;
        LastScanText = last is null ? "Henüz yok" : Format.Ago(last.FinishedAt ?? last.StartedAt);
        LastScanSub = last is null ? "İlk taramanızı başlatın" : $"{last.Type.ToTurkish()} · {last.FilesScanned:N0} dosya";
        ThreatsText = _core.History.TotalThreats.ToString("N0");
        QuarantineText = _core.Quarantine.Count.ToString("N0");
        FilesScannedText = _core.History.TotalFilesScanned.ToString("N0");
        SignatureText = _core.Settings.Current.SignaturesUpdatedAt is { } u
            ? $"{_core.Signatures.HashCount:N0} imza · {Format.Ago(u)}"
            : $"{_core.Signatures.HashCount:N0} imza · güncellenmedi";

        RecentEvents.Clear();
        foreach (var e in _core.Events.Events.Take(5)) RecentEvents.Add(new EventItemViewModel(e));
        HasEvents = RecentEvents.Count > 0;

        var hour = DateTime.Now.Hour;
        Greeting = hour < 6 ? "İyi geceler" : hour < 12 ? "Günaydın" : hour < 18 ? "İyi günler" : "İyi akşamlar";
    }

    private string BuildRealTimeDetail()
    {
        var rt = _core.RealTime;
        return rt.IsRunning
            ? $"Aktif — {rt.WatchedFolders.Count} konum izleniyor · bu oturumda {rt.FilesScanned:N0} dosya kontrol edildi"
            : "Kapalı — yeni dosyalar otomatik taranmıyor";
    }

    [RelayCommand]
    private void QuickScan()
    {
        AppServices.Shell.Navigate("scan");
        AppServices.Shell.Scan.QuickScanCommand.Execute(null);
    }

    [RelayCommand]
    private void FullScan()
    {
        AppServices.Shell.Navigate("scan");
        AppServices.Shell.Scan.FullScanCommand.Execute(null);
    }

    [RelayCommand]
    private void Go(string key) => AppServices.Shell.Navigate(key);
}
