using Nova.Core.Models;

namespace Nova.Core.Services;

public static class ScanSchedule
{
    public static DateTime? LastDue(AppSettings s, DateTime now)
    {
        if (!s.ScheduledScanEnabled) return null;
        var time = TimeSpan.FromMinutes(Math.Clamp(s.ScheduleMinutes, 0, 1439));

        if (s.ScheduleFrequency == ScheduleFrequency.Daily)
        {
            var today = now.Date + time;
            return today <= now ? today : today.AddDays(-1);
        }

        var daysBack = ((int)now.DayOfWeek - (int)s.ScheduleDay + 7) % 7;
        var candidate = now.Date.AddDays(-daysBack) + time;
        return candidate <= now ? candidate : candidate.AddDays(-7);
    }

    public static bool IsDue(AppSettings s, DateTime now)
    {
        if (LastDue(s, now) is not { } due) return false;
        return s.LastScheduledRun?.LocalDateTime is { } last && last < due;
    }

    public static DateTime? NextRun(AppSettings s, DateTime now)
    {
        if (LastDue(s, now) is not { } due) return null;
        if (IsDue(s, now)) return now;
        return s.ScheduleFrequency == ScheduleFrequency.Daily ? due.AddDays(1) : due.AddDays(7);
    }
}

public sealed class AutomationService : IDisposable
{
    private readonly SettingsService _settings;
    private readonly EventLogService _events;
    private readonly object _gate = new();
    private Timer? _scheduleTimer;
    private Timer? _driveTimer;
    private HashSet<string> _knownDrives = new(StringComparer.OrdinalIgnoreCase);
    private int _checking;
    private int _polling;

    internal Func<HashSet<string>> DriveProvider { get; set; } = ListDrives;

    public AutomationService(SettingsService settings, EventLogService events)
    {
        _settings = settings;
        _events = events;
    }

    public Func<ScanType, Task<bool>>? ScheduledScanHandler { get; set; }

    public Func<string, Task>? NewDriveHandler { get; set; }

    internal void SnapshotDrives() => _knownDrives = DriveProvider();

    public void Start()
    {
        lock (_gate)
        {
            if (_scheduleTimer is not null) return;
            _knownDrives = DriveProvider();
            _scheduleTimer = new Timer(_ => _ = CheckScheduleAsync(), null, TimeSpan.FromSeconds(45), TimeSpan.FromSeconds(30));
            _driveTimer = new Timer(_ => PollDrives(), null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
        }
    }

    internal async Task CheckScheduleAsync()
    {
        if (Interlocked.Exchange(ref _checking, 1) == 1) return;
        try
        {
            var s = _settings.Current;
            if (!s.ScheduledScanEnabled) return;

            var now = DateTime.Now;
            if (s.LastScheduledRun is null)
            {
                _settings.Update(x => x.LastScheduledRun = DateTimeOffset.Now);
                return;
            }
            if (!ScanSchedule.IsDue(s, now) || ScheduledScanHandler is null) return;

            var type = s.ScheduledScanType is ScanType.Full ? ScanType.Full : ScanType.Quick;
            if (await ScheduledScanHandler(type))
            {
                _settings.Update(x => x.LastScheduledRun = DateTimeOffset.Now);
                _events.Add(EventCategory.Scan, ThreatSeverity.Info, "Zamanlanmış tarama başlatıldı", $"{type.ToTurkish()} planlandığı gibi başladı.");
            }
        }
        catch (Exception) { /* a failed tick must never stop the timer */ }
        finally { Volatile.Write(ref _checking, 0); }
    }

    internal void PollDrives()
    {
        if (Interlocked.Exchange(ref _polling, 1) == 1) return;
        try
        {
            var current = DriveProvider();
            var added = current.Where(d => !_knownDrives.Contains(d)).ToList();
            _knownDrives = current;

            if (added.Count == 0 || !_settings.Current.UsbAutoScan || NewDriveHandler is null) return;
            foreach (var drive in added)
            {
                _events.Add(EventCategory.Scan, ThreatSeverity.Info, "Yeni sürücü algılandı", $"{drive} otomatik taranıyor.");
                var path = drive;
                _ = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(2));
                    try { await NewDriveHandler(path); } catch (Exception) { }
                });
            }
        }
        catch (Exception) { }
        finally { Volatile.Write(ref _polling, 0); }
    }

    internal static HashSet<string> ListDrives()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                foreach (var d in DriveInfo.GetDrives())
                    if (d.DriveType is DriveType.Fixed or DriveType.Removable && d.IsReady)
                        set.Add(d.RootDirectory.FullName);
            }
            else if (OperatingSystem.IsMacOS() && Directory.Exists("/Volumes"))
            {
                foreach (var dir in new DirectoryInfo("/Volumes").EnumerateDirectories())
                    if ((dir.Attributes & FileAttributes.ReparsePoint) == 0)
                        set.Add(dir.FullName);
            }
        }
        catch (Exception) { }
        return set;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _scheduleTimer?.Dispose();
            _driveTimer?.Dispose();
            _scheduleTimer = _driveTimer = null;
        }
    }
}
