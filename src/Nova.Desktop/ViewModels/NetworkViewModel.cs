using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Core.Services.Platform;
using Avalonia.Threading;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed partial class NetworkViewModel(NovaCore core) : PageViewModel
{
    private bool _loadedOnce;

    public override string Title => "Ağ Güvenliği";

    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _hasReport;
    [ObservableProperty] private string _networkName = "";
    [ObservableProperty] private string _networkSub = "";
    [ObservableProperty] private string _verdictText = "";
    [ObservableProperty] private string _verdictSub = "";
    [ObservableProperty] private string _verdictTone = Tone.Accent;
    [ObservableProperty] private MaterialIconKind _networkIcon = MaterialIconKind.Wifi;
    [ObservableProperty] private string _checkedAt = "";
    [ObservableProperty] private bool _needsLocation;
    [ObservableProperty] private bool _hasOtherAdapters;

    public ObservableCollection<InfoPair> Facts { get; } = [];
    public ObservableCollection<StatusRow> Checks { get; } = [];
    public ObservableCollection<InfoPair> OtherAdapters { get; } = [];

    private DispatcherTimer? _permissionPoll;

    public override void OnNavigatedTo()
    {
        if (OperatingSystem.IsMacOS()) RequestMacLocation(openSettingsIfDenied: false);
        if (!_loadedOnce) AnalyzeCommand.Execute(null);
    }

    private void RequestMacLocation(bool openSettingsIfDenied)
    {
        var status = MacLocation.Request();
        if (MacLocation.IsGranted(status)) return;

        if (status == MacLocation.NotDetermined)
        {
            _permissionPoll?.Stop();
            var ticks = 0;
            _permissionPoll = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _permissionPoll.Tick += (_, _) =>
            {
                var s = MacLocation.Status();
                if (s != MacLocation.NotDetermined || ++ticks > 60)
                {
                    _permissionPoll?.Stop();
                    if (MacLocation.IsGranted(s)) AnalyzeCommand.Execute(null);
                }
            };
            _permissionPoll.Start();
        }
        else if (openSettingsIfDenied)
        {
            ProcessRunner.Open("x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices");
        }
    }

    [RelayCommand]
    private async Task Analyze()
    {
        if (IsLoading) return;
        _loadedOnce = true;
        IsLoading = true;
        try
        {
            var report = await Task.Run(() => core.Network.AnalyzeAsync(CancellationToken.None));
            Show(report);
        }
        catch (Exception ex)
        {
            AppServices.Toasts.Show("Ağ analizi başarısız", ex.Message, Tone.Danger, force: true);
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private void OpenLocationSettings()
    {
        if (OperatingSystem.IsMacOS())
        {
            RequestMacLocation(openSettingsIfDenied: true);
            return;
        }
        ProcessRunner.Open("ms-settings:privacy-location");
    }

    private void Show(NetworkReport r)
    {
        HasReport = true;
        CheckedAt = $"Son analiz: {r.CheckedAt:HH:mm:ss}";
        var p = r.Primary;
        var wifi = r.Wifi;

        NetworkIcon = p is null ? MaterialIconKind.WifiOff
            : wifi is not null || p.IsWireless ? (wifi?.IsOpen == true ? MaterialIconKind.WifiAlert : MaterialIconKind.WifiLock)
            : MaterialIconKind.Ethernet;
        NetworkName = wifi?.Ssid ?? (p is null ? "Bağlantı yok" : p.IsWireless ? "Wi-Fi ağı" : p.Description);
        NetworkSub = p is null ? "Etkin bağlantı bulunamadı"
            : wifi?.Authentication is { } auth ? $"{(p.IsWireless ? "Wi-Fi" : p.Type)} · {auth}"
            : $"{p.Type} · {p.Name}";
        NeedsLocation = wifi is not null && wifi.Ssid is null && wifi.Note is not null;

        var fails = r.Checks.Count(c => c.State == CheckState.Fail);
        var warns = r.Checks.Count(c => c.State == CheckState.Warning);
        (VerdictText, VerdictTone, VerdictSub) = fails > 0
            ? ($"{fails} kritik risk sinyali", Tone.Danger, "Bu ağda hassas işlem yapmayın. Aşağıdaki önerileri uygulayın.")
            : warns > 0
                ? ($"{warns} uyarı", Tone.Warning, "Bazı yapılandırmalar dikkat gerektiriyor.")
                : ("Belirgin risk sinyali yok", Tone.Success, "Nova'nın kontrol edebildiği göstergelerde sorun bulunmadı.");

        Facts.Clear();
        if (p is not null)
        {
            Facts.Add(new("Bağlantı türü", p.IsWireless ? "Wi-Fi" : p.Type, p.IsWireless ? MaterialIconKind.Wifi : MaterialIconKind.Ethernet));
            Facts.Add(new("Yerel IP adresi", p.IPv4.FirstOrDefault() ?? p.IPv6.FirstOrDefault() ?? "—", MaterialIconKind.IpNetworkOutline));
            Facts.Add(new("Varsayılan ağ geçidi", p.Gateways.Count > 0 ? string.Join(", ", p.Gateways.Take(2)) : "—", MaterialIconKind.Router));
            Facts.Add(new("DNS sunucuları", p.DnsServers.Count > 0 ? string.Join(", ", p.DnsServers.Take(3)) : "—", MaterialIconKind.Dns));
            Facts.Add(new("Alt ağ maskesi", p.SubnetMask ?? "—", MaterialIconKind.Lan));
            Facts.Add(new("MAC adresi", p.Mac, MaterialIconKind.Fingerprint));
            if (p.SpeedMbps > 0) Facts.Add(new("Bağlantı hızı", $"{p.SpeedMbps:N0} Mbps", MaterialIconKind.Speedometer));
        }
        if (wifi is not null)
        {
            if (wifi.Bssid is { } b) Facts.Add(new("Erişim noktası (BSSID)", b, MaterialIconKind.AccessPoint));
            if (wifi.SignalPercent is { } s) Facts.Add(new("Sinyal gücü", $"%{s}", MaterialIconKind.WifiStrength3));
            if (wifi.PhyType is { Length: > 0 } phy) Facts.Add(new("Wi-Fi standardı", phy, MaterialIconKind.WifiSettings));
            if (wifi.Channel is { } ch) Facts.Add(new("Kanal", ch.ToString(), MaterialIconKind.SineWave));
        }
        Facts.Add(new("Genel IP adresi", r.PublicIp ?? "—", MaterialIconKind.Earth));
        if (r.Isp is { Length: > 0 } isp) Facts.Add(new("Servis sağlayıcı", isp, MaterialIconKind.DomainSwitch));
        if (r.Location is { Length: > 0 } loc) Facts.Add(new("Konum (IP)", loc, MaterialIconKind.MapMarkerOutline));

        Checks.Clear();
        foreach (var c in r.Checks.OrderBy(c => c.State switch { CheckState.Fail => 0, CheckState.Warning => 1, CheckState.Pass => 3, _ => 2 }))
            Checks.Add(new StatusRow(c.Title, c.Result, Tone.FromState(c.State), c.State switch
            {
                CheckState.Pass => MaterialIconKind.CheckCircleOutline,
                CheckState.Warning => MaterialIconKind.AlertCircleOutline,
                CheckState.Fail => MaterialIconKind.AlertOctagonOutline,
                CheckState.Info => MaterialIconKind.InformationOutline,
                _ => MaterialIconKind.MinusCircleOutline
            }, c.Advice));

        OtherAdapters.Clear();
        foreach (var a in r.Adapters.Where(a => a != p))
            OtherAdapters.Add(new(a.Description.Length > 0 ? a.Description : a.Name, $"{a.Type} · {a.IPv4.FirstOrDefault() ?? a.IPv6.FirstOrDefault() ?? "—"}",
                a.IsWireless ? MaterialIconKind.Wifi : MaterialIconKind.Lan));
        HasOtherAdapters = OtherAdapters.Count > 0;
    }
}
