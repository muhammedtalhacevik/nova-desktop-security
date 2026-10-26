using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Nova.Core;
using Nova.Core.Models;
using Nova.Core.Services;
using Nova.Core.Services.Platform;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed partial class PathItemViewModel(string path, Action<PathItemViewModel> remove)
{
    public string Path { get; } = path;

    [RelayCommand]
    private void Remove() => remove(this);
}

public sealed partial class SettingsViewModel : PageViewModel
{
    private readonly NovaCore _core;
    private bool _loading;

    public SettingsViewModel(NovaCore core)
    {
        _core = core;
        Load();
        core.RealTime.StateChanged += (_, _) => OnUi(() =>
        {
            _loading = true;
            RealTimeProtection = core.RealTime.IsRunning;
            _loading = false;
        });
    }

    public override string Title => "Ayarlar";

    private AppSettings S => _core.Settings.Current;

    [ObservableProperty] private bool _notificationsEnabled;
    [ObservableProperty] private bool _startWithSystem;
    [ObservableProperty] private bool _minimizeToTray;
    [ObservableProperty] private bool _realTimeProtection;
    [ObservableProperty] private bool _autoQuarantine;
    [ObservableProperty] private bool _useAmsi;
    [ObservableProperty] private bool _scanRunningProcesses;
    [ObservableProperty] private bool _monitorStartupChanges;
    [ObservableProperty] private bool _connectToSite;
    [ObservableProperty] private decimal _maxFileSizeMb;
    [ObservableProperty] private string _googleKey = "";
    [ObservableProperty] private string _virusTotalKey = "";
    [ObservableProperty] private string _hibpKey = "";
    [ObservableProperty] private bool _revealKeys;

    [ObservableProperty] private bool _scheduleEnabled;
    [ObservableProperty] private int _scheduleFrequencyIndex;
    [ObservableProperty] private int _scheduleDayIndex;
    [ObservableProperty] private TimeSpan? _scheduleTime = TimeSpan.FromHours(12);
    [ObservableProperty] private int _scheduleTypeIndex;
    [ObservableProperty] private bool _usbAutoScan;
    [ObservableProperty] private string _nextRunText = "";
    public bool IsWeekly => ScheduleFrequencyIndex == 1;

    public ObservableCollection<PathItemViewModel> Exclusions { get; } = [];
    public ObservableCollection<PathItemViewModel> WatchedFolders { get; } = [];
    public bool HasExclusions => Exclusions.Count > 0;
    public bool HasWatchedFolders => WatchedFolders.Count > 0;
    public int AllowedHashCount => S.AllowedHashes.Count;

    public bool IsWindows => OperatingSystem.IsWindows();
    public string UserId => "#" + S.InstallId;
    public string VersionText => $"v{typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3)} · {NovaCore.PlatformName} · .NET {Environment.Version}";
    public string DataFolder => AppPaths.Root;
    public char KeyMask => RevealKeys ? '\0' : '•';

    partial void OnRevealKeysChanged(bool value) => OnPropertyChanged(nameof(KeyMask));

    private void Load()
    {
        _loading = true;
        NotificationsEnabled = S.NotificationsEnabled;
        StartWithSystem = S.StartWithSystem;
        MinimizeToTray = S.MinimizeToTray;
        RealTimeProtection = _core.RealTime.IsRunning || S.RealTimeProtection;
        AutoQuarantine = S.AutoQuarantine;
        UseAmsi = S.UseSystemAntimalwareInterface;
        ScanRunningProcesses = S.ScanRunningProcesses;
        MonitorStartupChanges = S.MonitorStartupChanges;
        ConnectToSite = S.ConnectToSiteDuringUrlCheck;
        MaxFileSizeMb = S.MaxFileSizeMb;
        GoogleKey = S.GoogleSafeBrowsingApiKey;
        VirusTotalKey = S.VirusTotalApiKey;
        HibpKey = S.HibpApiKey;

        ScheduleEnabled = S.ScheduledScanEnabled;
        ScheduleFrequencyIndex = S.ScheduleFrequency == ScheduleFrequency.Weekly ? 1 : 0;
        ScheduleDayIndex = ((int)S.ScheduleDay + 6) % 7;
        ScheduleTime = TimeSpan.FromMinutes(S.ScheduleMinutes);
        ScheduleTypeIndex = S.ScheduledScanType == ScanType.Full ? 1 : 0;
        UsbAutoScan = S.UsbAutoScan;
        RefreshNextRun();

        Exclusions.Clear();
        foreach (var e in S.Exclusions) Exclusions.Add(new PathItemViewModel(e, RemoveExclusion));
        WatchedFolders.Clear();
        foreach (var w in S.ExtraWatchedFolders) WatchedFolders.Add(new PathItemViewModel(w, RemoveWatched));
        OnPropertyChanged(nameof(HasExclusions));
        OnPropertyChanged(nameof(HasWatchedFolders));
        OnPropertyChanged(nameof(AllowedHashCount));
        _loading = false;
    }

    public override void OnNavigatedTo() => Load();

    private void Save(Action<AppSettings> change)
    {
        if (_loading) return;
        _core.Settings.Update(change);
    }

    private void RefreshNextRun()
    {
        var next = ScanSchedule.NextRun(S, DateTime.Now);
        NextRunText = !S.ScheduledScanEnabled ? "Zamanlanmış tarama kapalı"
            : next is null ? ""
            : ScanSchedule.IsDue(S, DateTime.Now) ? "Bir sonraki tarama: birkaç dakika içinde (kaçırılan tarama)"
            : $"Bir sonraki tarama: {next:dddd, dd MMMM HH:mm}";
    }

    partial void OnScheduleEnabledChanged(bool value)
    {
        if (_loading) return;
        Save(s => { s.ScheduledScanEnabled = value; if (value) s.LastScheduledRun = DateTimeOffset.Now; });
        RefreshNextRun();
    }

    partial void OnScheduleFrequencyIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsWeekly));
        if (_loading) return;
        Save(s => { s.ScheduleFrequency = value == 1 ? ScheduleFrequency.Weekly : ScheduleFrequency.Daily; s.LastScheduledRun = DateTimeOffset.Now; });
        RefreshNextRun();
    }

    partial void OnScheduleDayIndexChanged(int value)
    {
        if (_loading || value < 0) return;
        Save(s => { s.ScheduleDay = (DayOfWeek)((value + 1) % 7); s.LastScheduledRun = DateTimeOffset.Now; });
        RefreshNextRun();
    }

    partial void OnScheduleTimeChanged(TimeSpan? value)
    {
        if (_loading || value is null) return;
        Save(s => { s.ScheduleMinutes = (int)value.Value.TotalMinutes; s.LastScheduledRun = DateTimeOffset.Now; });
        RefreshNextRun();
    }

    partial void OnScheduleTypeIndexChanged(int value) => Save(s => s.ScheduledScanType = value == 1 ? ScanType.Full : ScanType.Quick);
    partial void OnUsbAutoScanChanged(bool value) => Save(s => s.UsbAutoScan = value);

    partial void OnNotificationsEnabledChanged(bool value) => Save(s => s.NotificationsEnabled = value);
    partial void OnMinimizeToTrayChanged(bool value) => Save(s => s.MinimizeToTray = value);
    partial void OnAutoQuarantineChanged(bool value) => Save(s => s.AutoQuarantine = value);
    partial void OnUseAmsiChanged(bool value) => Save(s => s.UseSystemAntimalwareInterface = value);
    partial void OnScanRunningProcessesChanged(bool value) => Save(s => s.ScanRunningProcesses = value);
    partial void OnConnectToSiteChanged(bool value) => Save(s => s.ConnectToSiteDuringUrlCheck = value);
    partial void OnMaxFileSizeMbChanged(decimal value) => Save(s => s.MaxFileSizeMb = (int)Math.Clamp(value, 1, 4096));

    partial void OnMonitorStartupChangesChanged(bool value)
    {
        Save(s => s.MonitorStartupChanges = value);
        if (_loading || !_core.RealTime.IsRunning) return;
        _core.RealTime.Stop();
        _core.RealTime.Start();
    }

    partial void OnStartWithSystemChanged(bool value)
    {
        if (_loading) return;
        Save(s => s.StartWithSystem = value);
        var ok = AutoStartService.Apply(value);
        AppServices.Toasts.Show(ok ? "Başlangıç ayarı kaydedildi" : "Başlangıç ayarı uygulanamadı",
            value ? "Nova oturum açıldığında simge durumunda başlayacak." : "Nova artık otomatik başlamayacak.", ok ? Tone.Success : Tone.Danger, force: true);
    }

    partial void OnRealTimeProtectionChanged(bool value)
    {
        if (_loading) return;
        _core.RealTime.SetEnabled(value);
    }

    [RelayCommand]
    private void SaveKeys()
    {
        _core.Settings.Update(s =>
        {
            s.GoogleSafeBrowsingApiKey = GoogleKey.Trim();
            s.VirusTotalApiKey = VirusTotalKey.Trim();
            s.HibpApiKey = HibpKey.Trim();
        });
        AppServices.Toasts.Show("Servis anahtarları kaydedildi", "Anahtarlar yalnızca bu cihazda saklanır.", Tone.Success, force: true);
    }

    [RelayCommand]
    private async Task AddExclusion()
    {
        foreach (var p in await Pickers.PickFoldersAsync("Taramadan hariç tutulacak klasörü seçin"))
            if (!S.Exclusions.Contains(p))
            {
                _core.Settings.Update(s => s.Exclusions.Add(p));
                Exclusions.Add(new PathItemViewModel(p, RemoveExclusion));
            }
        OnPropertyChanged(nameof(HasExclusions));
    }

    private void RemoveExclusion(PathItemViewModel item)
    {
        _core.Settings.Update(s => s.Exclusions.Remove(item.Path));
        Exclusions.Remove(item);
        OnPropertyChanged(nameof(HasExclusions));
    }

    [RelayCommand]
    private async Task AddWatched()
    {
        foreach (var p in await Pickers.PickFoldersAsync("Gerçek zamanlı izlenecek klasörü seçin"))
            if (!S.ExtraWatchedFolders.Contains(p))
            {
                _core.Settings.Update(s => s.ExtraWatchedFolders.Add(p));
                WatchedFolders.Add(new PathItemViewModel(p, RemoveWatched));
            }
        OnPropertyChanged(nameof(HasWatchedFolders));
        RestartRealTime();
    }

    private void RemoveWatched(PathItemViewModel item)
    {
        _core.Settings.Update(s => s.ExtraWatchedFolders.Remove(item.Path));
        WatchedFolders.Remove(item);
        OnPropertyChanged(nameof(HasWatchedFolders));
        RestartRealTime();
    }

    private void RestartRealTime()
    {
        if (!_core.RealTime.IsRunning) return;
        _core.RealTime.Stop();
        _core.RealTime.Start();
    }

    [RelayCommand]
    private async Task ClearAllowed()
    {
        if (!await ConfirmDialogViewModel.ShowAsync("İzin listesi temizlensin mi?", $"{AllowedHashCount} dosya yeniden taranıp tehdit olarak işaretlenebilir.", "Temizle", true))
            return;
        _core.Settings.Update(s => s.AllowedHashes.Clear());
        OnPropertyChanged(nameof(AllowedHashCount));
    }

    [RelayCommand]
    private void OpenDataFolder() => ProcessRunner.Open(AppPaths.Root);

    [RelayCommand]
    private async Task CopyUserId()
    {
        await Pickers.CopyToClipboardAsync(UserId);
        AppServices.Toasts.Show("Kopyalandı", UserId, Tone.Success, force: true);
    }

    [RelayCommand]
    private void OpenLink(string url) => ProcessRunner.Open(url);
}
