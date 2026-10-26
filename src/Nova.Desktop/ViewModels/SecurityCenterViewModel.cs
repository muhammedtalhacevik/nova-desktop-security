using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Core.Services.Platform;
using Nova.Core.Services.Scanning;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed record ComponentStatus(string Title, string Value, string Tone, MaterialIconKind Icon);

public sealed partial class SessionItemViewModel(ScanSession s, SecurityCenterViewModel owner) : ObservableObject
{
    public ScanSession Session { get; } = s;
    public string TypeText => s.Type.ToTurkish();
    public string DateText => s.StartedAt.ToString("dd.MM.yyyy HH:mm");
    public string FilesText => $"{s.FilesScanned:N0} dosya";
    public string ThreatsText => s.ThreatCount == 0 ? "Temiz" : $"{s.ThreatCount} tehdit";
    public string ThreatsTone => s.ThreatCount == 0 ? Tone.Success : s.UnresolvedThreatCount > 0 ? Tone.Danger : Tone.Warning;
    public string DurationText => s.Type == ScanType.RealTime ? "Gün boyu" : Format.Duration(s.Duration);
    public string StatusText => s.Status.ToTurkish();
    public MaterialIconKind Icon => s.Type switch
    {
        ScanType.Quick => MaterialIconKind.LightningBolt,
        ScanType.Full => MaterialIconKind.Harddisk,
        ScanType.RealTime => MaterialIconKind.FlashOutline,
        _ => MaterialIconKind.FolderSearchOutline
    };

    [RelayCommand]
    private async Task Export()
    {
        var path = await Pickers.SaveFileAsync("Tarama raporunu kaydet", ReportExporter.DefaultFileName(Session), "html", "HTML raporu");
        if (path is null) return;
        await File.WriteAllTextAsync(path, ReportExporter.ToHtml(Session));
        AppServices.Toasts.Show("Rapor kaydedildi", Path.GetFileName(path), Tone.Success, MaterialIconKind.FileDocumentCheckOutline, () => ProcessRunner.Open(path), force: true);
    }

    [RelayCommand]
    private void Delete() => owner.DeleteSession(this);
}

public sealed partial class QuarantineItemViewModel(QuarantineItem item, SecurityCenterViewModel owner)
{
    public QuarantineItem Item { get; } = item;
    public string FileName => item.FileName;
    public string OriginalPath => item.OriginalPath;
    public string ThreatName => item.ThreatName;
    public string DateText => item.QuarantinedAt.ToString("dd.MM.yyyy HH:mm");
    public string SizeText => Format.Bytes(item.Size);
    public string SeverityTone => Tone.FromSeverity(item.Severity);

    [RelayCommand]
    private Task Restore() => owner.RestoreAsync(this);

    [RelayCommand]
    private Task Delete() => owner.DeleteQuarantinedAsync(this);
}

public sealed partial class SecurityCenterViewModel : PageViewModel
{
    private readonly NovaCore _core;
    private readonly DispatcherTimer _throttle;

    public SecurityCenterViewModel(NovaCore core)
    {
        _core = core;
        _throttle = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        _throttle.Tick += (_, _) => { _throttle.Stop(); Refresh(); };
        void Schedule() => OnUi(() => { _throttle.Stop(); _throttle.Start(); });
        core.Events.Changed += (_, _) => Schedule();
        core.History.Changed += (_, _) => Schedule();
        core.Quarantine.Changed += (_, _) => Schedule();
        core.RealTime.StateChanged += (_, _) => Schedule();
        Refresh();
    }

    public override string Title => "Güvenlik Merkezi";

    [ObservableProperty] private int _selectedTab;
    [ObservableProperty] private string _headline = "";
    [ObservableProperty] private string _statusTone = Tone.Success;
    [ObservableProperty] private bool _hasIssues;
    [ObservableProperty] private bool _hasPendingThreats;
    [ObservableProperty] private bool _hasEvents;
    [ObservableProperty] private bool _hasSessions;
    [ObservableProperty] private bool _hasQuarantine;
    [ObservableProperty] private string _eventsHeader = "Bildirimler";
    [ObservableProperty] private string _historyHeader = "Tarama Geçmişi";
    [ObservableProperty] private string _quarantineHeader = "Karantina";

    public ObservableCollection<ComponentStatus> Components { get; } = [];
    public ObservableCollection<IssueItemViewModel> Issues { get; } = [];
    public ObservableCollection<ThreatItemViewModel> PendingThreats { get; } = [];
    public ObservableCollection<EventItemViewModel> Events { get; } = [];
    public ObservableCollection<SessionItemViewModel> Sessions { get; } = [];
    public ObservableCollection<QuarantineItemViewModel> QuarantineItems { get; } = [];

    public override void OnNavigatedTo()
    {
        Refresh();
        if (SelectedTab == 0 && _core.Events.UnreadCount > 0)
            DispatcherTimer.RunOnce(() => _core.Events.MarkAllRead(), TimeSpan.FromSeconds(2));
    }

    partial void OnSelectedTabChanged(int value)
    {
        if (value == 0 && _core.Events.UnreadCount > 0)
            DispatcherTimer.RunOnce(() => _core.Events.MarkAllRead(), TimeSpan.FromSeconds(2));
    }

    public void Refresh()
    {
        var status = _core.GetStatus();
        Headline = status.Headline;
        StatusTone = status.Level switch { ProtectionLevel.AtRisk => Tone.Danger, ProtectionLevel.Attention => Tone.Warning, _ => Tone.Success };

        var s = _core.Settings.Current;
        var rt = _core.RealTime;
        Components.Clear();
        Components.Add(new("Gerçek zamanlı koruma", rt.IsRunning ? $"Açık · {rt.WatchedFolders.Count} konum" : "Kapalı",
            rt.IsRunning ? Tone.Success : Tone.Danger, MaterialIconKind.FlashOutline));
        Components.Add(new("Virüs imzaları", $"{_core.Signatures.HashCount:N0} · {Format.Ago(s.SignaturesUpdatedAt)}",
            s.SignaturesUpdatedAt is { } u && DateTimeOffset.Now - u < TimeSpan.FromDays(3) ? Tone.Success : Tone.Warning, MaterialIconKind.DatabaseCheckOutline));
        var last = _core.History.Last;
        Components.Add(new("Son tarama", last is null ? "Henüz yok" : $"{last.Type.ToTurkish()} · {Format.Ago(last.StartedAt)}",
            last is not null && DateTimeOffset.Now - last.StartedAt < TimeSpan.FromDays(7) ? Tone.Success : Tone.Warning, MaterialIconKind.ShieldSearch));
        if (OperatingSystem.IsWindows())
        {
            var amsi = _core.Amsi.IsAvailable && s.UseSystemAntimalwareInterface;
            Components.Add(new("Sistem antivirüs motoru", amsi ? "AMSI bağlı" : "Kullanılmıyor", amsi ? Tone.Success : Tone.Neutral, MaterialIconKind.MicrosoftWindows));
        }
        Components.Add(new("Karantina", $"{_core.Quarantine.Count} dosya", Tone.Accent, MaterialIconKind.ArchiveLockOutline));
        Components.Add(new("Engellenen tehdit", $"{_core.History.TotalThreats:N0} toplam", _core.History.TotalThreats > 0 ? Tone.Warning : Tone.Success, MaterialIconKind.ShieldOffOutline));

        Issues.Clear();
        foreach (var i in status.Issues) Issues.Add(new IssueItemViewModel(i));
        HasIssues = Issues.Count > 0;

        PendingThreats.Clear();
        foreach (var t in _core.History.UnresolvedThreats) PendingThreats.Add(new ThreatItemViewModel(t, () => DispatcherTimer.RunOnce(Refresh, TimeSpan.FromMilliseconds(100))));
        HasPendingThreats = PendingThreats.Count > 0;

        Events.Clear();
        foreach (var e in _core.Events.Events.Take(150)) Events.Add(new EventItemViewModel(e));
        HasEvents = Events.Count > 0;
        var unread = _core.Events.UnreadCount;
        EventsHeader = unread > 0 ? $"Bildirimler ({unread})" : "Bildirimler";

        Sessions.Clear();
        foreach (var x in _core.History.Sessions) Sessions.Add(new SessionItemViewModel(x, this));
        HasSessions = Sessions.Count > 0;
        HistoryHeader = $"Tarama Geçmişi ({Sessions.Count})";

        QuarantineItems.Clear();
        foreach (var q in _core.Quarantine.Items) QuarantineItems.Add(new QuarantineItemViewModel(q, this));
        HasQuarantine = QuarantineItems.Count > 0;
        QuarantineHeader = $"Karantina ({QuarantineItems.Count})";
    }

    [RelayCommand]
    private void MarkAllRead() => _core.Events.MarkAllRead();

    [RelayCommand]
    private async Task ClearEvents()
    {
        if (await ConfirmDialogViewModel.ShowAsync("Bildirimler temizlensin mi?", "Tüm bildirim geçmişi silinecek.", "Temizle", true))
            _core.Events.Clear();
    }

    [RelayCommand]
    private async Task ClearHistory()
    {
        if (await ConfirmDialogViewModel.ShowAsync("Tarama geçmişi temizlensin mi?", "Tüm tarama kayıtları ve raporları silinecek. Karantinadaki dosyalar etkilenmez.", "Temizle", true))
            _core.History.Clear();
    }

    public void DeleteSession(SessionItemViewModel item) => _core.History.Remove(item.Session.Id);

    public async Task RestoreAsync(QuarantineItemViewModel item)
    {
        if (!await ConfirmDialogViewModel.ShowAsync("Dosya geri yüklensin mi?",
                $"{item.FileName} özgün konumuna geri yüklenecek ve izin verilenler listesine eklenecek.\n\nTehdit: {item.ThreatName}\n\nYalnızca dosyanın güvenli olduğundan eminseniz devam edin.", "Geri yükle"))
            return;
        var r = _core.Quarantine.Restore(item.Item.Id);
        AppServices.Toasts.Show(r.Success ? "Geri yüklendi" : "Geri yüklenemedi", r.Message, r.Success ? Tone.Success : Tone.Danger, force: true);
    }

    public async Task DeleteQuarantinedAsync(QuarantineItemViewModel item)
    {
        if (!await ConfirmDialogViewModel.ShowAsync("Kalıcı olarak silinsin mi?", $"{item.FileName} karantinadan kalıcı olarak silinecek.", "Sil", true))
            return;
        var r = _core.Quarantine.Delete(item.Item.Id);
        AppServices.Toasts.Show(r.Success ? "Silindi" : "Silinemedi", r.Message, r.Success ? Tone.Success : Tone.Danger, force: true);
    }

    [RelayCommand]
    private async Task DeleteAllQuarantine()
    {
        if (!await ConfirmDialogViewModel.ShowAsync("Karantina boşaltılsın mı?", $"{QuarantineItems.Count} dosya kalıcı olarak silinecek.", "Tümünü sil", true))
            return;
        foreach (var q in QuarantineItems.ToList()) _core.Quarantine.Delete(q.Item.Id);
    }

    [RelayCommand]
    private void QuarantineAllPending()
    {
        var n = 0;
        foreach (var t in PendingThreats.ToList())
        {
            if (_core.Quarantine.Quarantine(t.Threat).Success) n++;
            _core.History.ThreatUpdated(t.Threat);
        }
        AppServices.Toasts.Show("Karantina", $"{n} tehdit karantinaya alındı.", Tone.Success, force: true);
        Refresh();
    }
}
