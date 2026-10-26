using System.Collections.Concurrent;
using Nova.Core.Models;
using Nova.Core.Services.Privacy;
using Nova.Core.Services.Scanning;
using Nova.Core.Storage;

namespace Nova.Core.Services;

public sealed class ThreatBlockedEventArgs(ThreatDetection threat, bool quarantined) : EventArgs
{
    public ThreatDetection Threat { get; } = threat;
    public bool Quarantined { get; } = quarantined;
}

public sealed class RealTimeProtectionService : IDisposable
{
    private static readonly TimeSpan Settle = TimeSpan.FromMilliseconds(1200);
    private static readonly TimeSpan GiveUpLocked = TimeSpan.FromSeconds(60);

    private readonly NovaScanner _scanner;
    private readonly QuarantineService _quarantine;
    private readonly SettingsService _settings;
    private readonly EventLogService _events;
    private readonly ScanHistoryService _history;
    private readonly StartupAppsService _startup;

    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<string, (DateTime LastEvent, DateTime FirstEvent, bool RiskyOnly)> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly JsonStore<List<string>> _baselineStore = new("startup-baseline.json");
    private CancellationTokenSource? _cts;
    private ScanSession? _todaySession;
    private long _filesScanned;
    private int _threatsBlocked;

    public RealTimeProtectionService(NovaScanner scanner, QuarantineService quarantine, SettingsService settings,
        EventLogService events, ScanHistoryService history, StartupAppsService startup)
    {
        _scanner = scanner;
        _quarantine = quarantine;
        _settings = settings;
        _events = events;
        _history = history;
        _startup = startup;
    }

    public bool IsRunning => _cts is not null;
    public long FilesScanned => Interlocked.Read(ref _filesScanned);
    public int ThreatsBlocked => _threatsBlocked;
    public IReadOnlyList<string> WatchedFolders { get; private set; } = [];

    public event EventHandler<ThreatBlockedEventArgs>? ThreatBlocked;
    public event EventHandler? StateChanged;

    public void Start()
    {
        if (_cts is not null) return;
        _cts = new CancellationTokenSource();

        var folders = new List<(string Path, bool Recursive, bool RiskyOnly)>
        {
            (AppPaths.Downloads, true, false),
            (AppPaths.Desktop, true, false),
            (AppPaths.Documents, true, true),
            (Path.GetTempPath(), false, true)
        };
        if (OperatingSystem.IsWindows())
        {
            folders.Add((Environment.GetFolderPath(Environment.SpecialFolder.Startup), false, false));
            folders.Add((Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), false, true));
        }
        if (OperatingSystem.IsMacOS())
        {
            folders.Add((Path.Combine(AppPaths.Home, "Library", "LaunchAgents"), false, false));
            folders.Add(("/Users/Shared", true, true));
        }
        folders.AddRange(_settings.Current.ExtraWatchedFolders.Select(f => (f, true, false)));

        var watched = new List<string>();
        foreach (var (path, recursive, riskyOnly) in folders.DistinctBy(f => f.Path, StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) continue;
            try
            {
                var w = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = recursive,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024
                };
                w.Created += (_, e) => Enqueue(e.FullPath, riskyOnly);
                w.Changed += (_, e) => Enqueue(e.FullPath, riskyOnly);
                w.Renamed += (_, e) => Enqueue(e.FullPath, riskyOnly);
                w.Error += (_, _) => Restart();
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
                watched.Add(path);
            }
            catch (Exception) { /* folder not watchable (permissions / FS type) */ }
        }
        WatchedFolders = watched;

        var ct = _cts.Token;
        _ = Task.Run(() => ProcessLoopAsync(ct), ct);
        if (_settings.Current.MonitorStartupChanges)
            _ = Task.Run(() => StartupMonitorLoopAsync(ct), ct);

        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public void Stop()
    {
        var cts = Interlocked.Exchange(ref _cts, null);
        if (cts is null) return;
        cts.Cancel();
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
        _pending.Clear();
        WatchedFolders = [];
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public void SetEnabled(bool enabled)
    {
        if (enabled == IsRunning) return;
        _settings.Update(s => s.RealTimeProtection = enabled);
        if (enabled)
        {
            Start();
            _events.Add(EventCategory.RealTime, ThreatSeverity.Info, "Gerçek zamanlı koruma açıldı", "Yeni ve değişen dosyalar anında taranıyor.");
        }
        else
        {
            Stop();
            _events.Add(EventCategory.RealTime, ThreatSeverity.Medium, "Gerçek zamanlı koruma kapatıldı", "Cihazınız yeni tehditlere karşı korunmuyor.");
        }
    }

    private void Restart()
    {
        Stop();
        Start();
    }

    private void Enqueue(string path, bool riskyOnly)
    {
        if (_scanner.IsExcluded(path)) return;
        var now = DateTime.UtcNow;
        _pending.AddOrUpdate(path, _ => (now, now, riskyOnly), (_, v) => (now, v.FirstEvent, v.RiskyOnly));
    }

    private async Task ProcessLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(400, ct); }
            catch (OperationCanceledException) { return; }

            var now = DateTime.UtcNow;
            foreach (var (path, info) in _pending)
            {
                if (now - info.LastEvent < Settle) continue;
                if (!File.Exists(path)) { _pending.TryRemove(path, out _); continue; }
                if (info.RiskyOnly && !FileTypes.IsRisky(Path.GetExtension(path))) { _pending.TryRemove(path, out _); continue; }

                if (IsLocked(path) && now - info.FirstEvent < GiveUpLocked) continue;
                _pending.TryRemove(path, out _);

                try { await ScanAndHandleAsync(path, ct); }
                catch (OperationCanceledException) { return; }
                catch (Exception) { }
            }
        }
    }

    private Task ScanAndHandleAsync(string path, CancellationToken ct)
    {
        var hit = _scanner.ScanFile(path, ct);
        Interlocked.Increment(ref _filesScanned);
        if (hit is null) return Task.CompletedTask;

        var quarantined = false;
        if (_settings.Current.AutoQuarantine)
            quarantined = _quarantine.Quarantine(hit).Success;

        Interlocked.Increment(ref _threatsBlocked);
        RecordInTodaySession(hit);

        _events.Add(EventCategory.RealTime, hit.Severity,
            quarantined ? "Tehdit engellendi" : "Tehdit algılandı",
            quarantined
                ? $"{hit.FileName} ({hit.ThreatName}) karantinaya alındı."
                : $"{hit.FileName} ({hit.ThreatName}) — işlem yapmanız gerekiyor.");

        ThreatBlocked?.Invoke(this, new ThreatBlockedEventArgs(hit, quarantined));
        return Task.CompletedTask;
    }

    private void RecordInTodaySession(ThreatDetection hit)
    {
        var today = DateTimeOffset.Now.Date;
        if (_todaySession is null || _todaySession.StartedAt.Date != today)
        {
            _todaySession = _history.Sessions.FirstOrDefault(s => s.Type == ScanType.RealTime && s.StartedAt.Date == today)
                            ?? new ScanSession { Type = ScanType.RealTime, Status = ScanStatus.Completed, StartedAt = DateTimeOffset.Now, Targets = WatchedFolders.ToList() };
        }
        _todaySession.Threats.Add(hit);
        _todaySession.FilesScanned = Math.Max(_todaySession.FilesScanned, FilesScanned);
        _todaySession.FinishedAt = DateTimeOffset.Now;
        _history.Upsert(_todaySession);
    }

    private static bool IsLocked(string path)
    {
        if (!FileKind.IsRegularFile(path)) return false;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return false;
        }
        catch (IOException ex) when (!QuarantineService.IsVirusBlocked(ex)) { return true; }
        catch { return false; }
    }

    private async Task StartupMonitorLoopAsync(CancellationToken ct)
    {
        var baseline = new HashSet<string>(_baselineStore.Load(), StringComparer.OrdinalIgnoreCase);
        var firstRun = baseline.Count == 0;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var items = await _startup.GetItemsAsync(ct);
                var ids = items.Select(i => i.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (!firstRun)
                {
                    foreach (var item in items.Where(i => !baseline.Contains(i.Id)))
                    {
                        _events.Add(EventCategory.Privacy, ThreatSeverity.Medium, "Yeni başlangıç öğesi eklendi",
                            $"{item.Name} oturum açılışında otomatik çalışacak şekilde ayarlandı ({item.Location}).");
                        if (item.ExecutablePath is { } exe && File.Exists(exe))
                            await ScanAndHandleAsync(exe, ct);
                    }
                }
                firstRun = false;
                baseline = ids;
                _baselineStore.Save(ids.ToList());
            }
            catch (OperationCanceledException) { return; }
            catch (Exception) { }

            try { await Task.Delay(TimeSpan.FromSeconds(90), ct); }
            catch (OperationCanceledException) { return; }
        }
    }

    public void Dispose() => Stop();
}
