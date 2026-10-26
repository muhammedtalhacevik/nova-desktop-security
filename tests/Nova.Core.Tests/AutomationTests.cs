using Nova.Core.Models;
using Nova.Core.Services;

namespace Nova.Core.Tests;

public class AutomationTests
{
    private static HashSet<string> Drives(params string[] d) => new(d, StringComparer.OrdinalIgnoreCase);

    [Fact]
    public async Task New_drive_triggers_the_handler_once()
    {
        var core = TestEnv.Core;
        core.Settings.Update(s => s.UsbAutoScan = true);
        var current = Drives(@"C:\");
        var seen = new List<string>();
        using var svc = new AutomationService(core.Settings, core.Events)
        {
            DriveProvider = () => current,
            NewDriveHandler = path => { lock (seen) seen.Add(path); return Task.CompletedTask; }
        };
        svc.SnapshotDrives();

        svc.PollDrives();
        current = Drives(@"C:\", @"E:\");
        svc.PollDrives();
        svc.PollDrives();
        await Task.Delay(TimeSpan.FromSeconds(3.5));

        Assert.Equal([@"E:\"], seen);
    }

    [Fact]
    public async Task Drives_present_at_start_are_not_scanned()
    {
        var core = TestEnv.Core;
        core.Settings.Update(s => s.UsbAutoScan = true);
        var calls = 0;
        using var svc = new AutomationService(core.Settings, core.Events)
        {
            DriveProvider = () => Drives(@"C:\", @"D:\"),
            NewDriveHandler = _ => { Interlocked.Increment(ref calls); return Task.CompletedTask; }
        };
        svc.SnapshotDrives();
        svc.PollDrives();
        await Task.Delay(TimeSpan.FromSeconds(3));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task Usb_auto_scan_can_be_switched_off()
    {
        var core = TestEnv.Core;
        core.Settings.Update(s => s.UsbAutoScan = false);
        var calls = 0;
        var current = Drives(@"C:\");
        using var svc = new AutomationService(core.Settings, core.Events)
        {
            DriveProvider = () => current,
            NewDriveHandler = _ => { Interlocked.Increment(ref calls); return Task.CompletedTask; }
        };
        svc.SnapshotDrives();
        current = Drives(@"C:\", @"F:\");
        svc.PollDrives();
        await Task.Delay(TimeSpan.FromSeconds(3));
        core.Settings.Update(s => s.UsbAutoScan = true);
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task Due_schedule_runs_and_records_the_run()
    {
        var core = TestEnv.Core;
        var scheduled = DateTime.Now.AddHours(-1);
        core.Settings.Update(s =>
        {
            s.ScheduledScanEnabled = true;
            s.ScheduleFrequency = ScheduleFrequency.Daily;
            s.ScheduleMinutes = scheduled.Hour * 60 + scheduled.Minute;
            s.ScheduledScanType = ScanType.Full;
            s.LastScheduledRun = DateTimeOffset.Now.AddDays(-2);
        });
        var started = new List<ScanType>();
        using var svc = new AutomationService(core.Settings, core.Events)
        {
            ScheduledScanHandler = type => { started.Add(type); return Task.FromResult(true); }
        };

        await svc.CheckScheduleAsync();
        await svc.CheckScheduleAsync();

        Assert.Equal([ScanType.Full], started);
        Assert.True(core.Settings.Current.LastScheduledRun > DateTimeOffset.Now.AddMinutes(-1));
        core.Settings.Update(s => s.ScheduledScanEnabled = false);
    }

    [Fact]
    public async Task Schedule_is_retried_when_a_scan_is_already_running()
    {
        var core = TestEnv.Core;
        var scheduled = DateTime.Now.AddHours(-1);
        var oldRun = DateTimeOffset.Now.AddDays(-2);
        core.Settings.Update(s =>
        {
            s.ScheduledScanEnabled = true;
            s.ScheduleFrequency = ScheduleFrequency.Daily;
            s.ScheduleMinutes = scheduled.Hour * 60 + scheduled.Minute;
            s.LastScheduledRun = oldRun;
        });
        var busy = true;
        var attempts = 0;
        using var svc = new AutomationService(core.Settings, core.Events)
        {
            ScheduledScanHandler = _ => { attempts++; return Task.FromResult(!busy); }
        };

        await svc.CheckScheduleAsync();
        Assert.Equal(oldRun, core.Settings.Current.LastScheduledRun);

        busy = false;
        await svc.CheckScheduleAsync();
        Assert.Equal(2, attempts);
        Assert.True(core.Settings.Current.LastScheduledRun > oldRun);
        core.Settings.Update(s => s.ScheduledScanEnabled = false);
    }

    [Fact]
    public async Task Enabling_a_schedule_never_triggers_an_immediate_scan()
    {
        var core = TestEnv.Core;
        core.Settings.Update(s => { s.ScheduledScanEnabled = true; s.LastScheduledRun = null; });
        var calls = 0;
        using var svc = new AutomationService(core.Settings, core.Events)
        {
            ScheduledScanHandler = _ => { calls++; return Task.FromResult(true); }
        };
        await svc.CheckScheduleAsync();
        Assert.Equal(0, calls);
        Assert.NotNull(core.Settings.Current.LastScheduledRun);
        core.Settings.Update(s => s.ScheduledScanEnabled = false);
    }
}
