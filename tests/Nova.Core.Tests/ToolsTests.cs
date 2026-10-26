using Nova.Core.Models;
using Nova.Core.Services;
using Nova.Core.Services.WindowsTools;

namespace Nova.Core.Tests;

public class ScheduleTests
{
    private static AppSettings Daily(int hour, DateTimeOffset? last) => new()
    {
        ScheduledScanEnabled = true,
        ScheduleFrequency = ScheduleFrequency.Daily,
        ScheduleMinutes = hour * 60,
        LastScheduledRun = last
    };

    [Fact]
    public void Disabled_schedule_is_never_due()
    {
        var s = new AppSettings { ScheduledScanEnabled = false, LastScheduledRun = DateTimeOffset.Now.AddDays(-9) };
        Assert.False(ScanSchedule.IsDue(s, DateTime.Now));
        Assert.Null(ScanSchedule.NextRun(s, DateTime.Now));
    }

    [Fact]
    public void Daily_is_due_after_the_scheduled_time_when_not_yet_run_today()
    {
        var now = new DateTime(2026, 10, 20, 14, 0, 0);
        var s = Daily(12, new DateTimeOffset(new DateTime(2026, 10, 19, 12, 5, 0)));
        Assert.True(ScanSchedule.IsDue(s, now));
    }

    [Fact]
    public void Daily_is_not_due_after_todays_run()
    {
        var now = new DateTime(2026, 10, 20, 14, 0, 0);
        var s = Daily(12, new DateTimeOffset(new DateTime(2026, 10, 20, 12, 1, 0)));
        Assert.False(ScanSchedule.IsDue(s, now));
        Assert.Equal(new DateTime(2026, 10, 21, 12, 0, 0), ScanSchedule.NextRun(s, now));
    }

    [Fact]
    public void Daily_is_not_due_before_the_scheduled_time()
    {
        var now = new DateTime(2026, 10, 20, 9, 0, 0);
        var s = Daily(12, new DateTimeOffset(new DateTime(2026, 10, 19, 12, 2, 0)));
        Assert.False(ScanSchedule.IsDue(s, now));
    }

    [Fact]
    public void Missed_run_is_caught_up_when_the_pc_was_off()
    {
        var now = new DateTime(2026, 10, 25, 8, 0, 0);
        var s = Daily(12, new DateTimeOffset(new DateTime(2026, 10, 20, 12, 0, 0)));
        Assert.True(ScanSchedule.IsDue(s, now));
    }

    [Fact]
    public void Weekly_runs_on_the_chosen_day()
    {
        var s = new AppSettings
        {
            ScheduledScanEnabled = true,
            ScheduleFrequency = ScheduleFrequency.Weekly,
            ScheduleDay = DayOfWeek.Monday,
            ScheduleMinutes = 10 * 60,
            LastScheduledRun = new DateTimeOffset(new DateTime(2026, 10, 12, 10, 1, 0))
        };

        Assert.False(ScanSchedule.IsDue(s, new DateTime(2026, 10, 19, 9, 0, 0)));
        Assert.True(ScanSchedule.IsDue(s, new DateTime(2026, 10, 19, 10, 30, 0)));
        Assert.False(ScanSchedule.IsDue(s, new DateTime(2026, 10, 15, 12, 0, 0)));
    }

    [Fact]
    public void Weekly_next_run_is_seven_days_after_the_last_due_time()
    {
        var s = new AppSettings
        {
            ScheduledScanEnabled = true,
            ScheduleFrequency = ScheduleFrequency.Weekly,
            ScheduleDay = DayOfWeek.Wednesday,
            ScheduleMinutes = 18 * 60,
            LastScheduledRun = new DateTimeOffset(new DateTime(2026, 10, 14, 18, 1, 0))
        };
        var now = new DateTime(2026, 10, 16, 9, 0, 0);
        Assert.False(ScanSchedule.IsDue(s, now));
        Assert.Equal(new DateTime(2026, 10, 21, 18, 0, 0), ScanSchedule.NextRun(s, now));
    }
}

public class UpdaterParseTests
{
    private const string English = """
        -\|/
        Name                         Id                       Version     Available    Source
        ------------------------------------------------------------------------------------
        Git                          Git.Git                  2.45.1      2.46.0       winget
        7-Zip 24.07 (x64)            7zip.7zip                24.07       24.08        winget
        Python Launcher              Python.Launcher          < 3.14.7    3.14.7       winget
        3 upgrades available.
        1 package(s) have version numbers that cannot be determined.
        """;

    private const string Turkish = """
        Ad                           Kimlik                   Sürüm       Kullanılabilir Kaynak
        ----------------------------------------------------------------------------------------
        Windows Terminal             Microsoft.WindowsTerminal 1.24.1      1.25.2         winget
        Zoom Workplace (64-bit)      Zoom.Zoom                6.2.49      7.2.48         winget
        2 yükseltme mevcut.
        """;

    [Fact]
    public void Parses_english_table()
    {
        var list = SoftwareUpdaterService.ParseTable(English);
        Assert.Equal(3, list.Count);
        Assert.Equal(new AppUpdate("Git", "Git.Git", "2.45.1", "2.46.0", "winget"), list[0]);
        Assert.Equal("7zip.7zip", list[1].Id);
        Assert.Equal("7-Zip 24.07 (x64)", list[1].Name);
        Assert.Equal("< 3.14.7", list[2].CurrentVersion);
    }

    [Fact]
    public void Parses_localised_headers()
    {
        var list = SoftwareUpdaterService.ParseTable(Turkish);
        Assert.Equal(2, list.Count);
        Assert.Equal("Zoom.Zoom", list[1].Id);
        Assert.Equal("7.2.48", list[1].AvailableVersion);
    }

    [Fact]
    public void Returns_empty_when_nothing_to_update()
    {
        Assert.Empty(SoftwareUpdaterService.ParseTable("No installed package found matching input criteria."));
        Assert.Empty(SoftwareUpdaterService.ParseTable(""));
    }
}

public class CleanerTests
{
    private static (CleanerService Service, CleanerCategory Category, string Root) Setup()
    {
        var root = Path.Combine(TestEnv.NewSampleDir(), "cache");
        Directory.CreateDirectory(root);
        var category = new CleanerCategory
        {
            Id = "test",
            Title = "Test",
            Description = "",
            MinAge = TimeSpan.FromHours(24),
            ResolveRoots = () => [root]
        };
        return (new CleanerService([category]), category, root);
    }

    private static void Write(string path, int bytes, DateTime when)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, new byte[bytes]);
        File.SetLastWriteTime(path, when);
        File.SetCreationTime(path, when);
    }

    [Fact]
    public async Task Scan_counts_only_files_older_than_the_minimum_age()
    {
        var (svc, cat, root) = Setup();
        Write(Path.Combine(root, "old.tmp"), 1000, DateTime.Now.AddDays(-3));
        Write(Path.Combine(root, "sub", "old2.tmp"), 500, DateTime.Now.AddDays(-5));
        Write(Path.Combine(root, "fresh.tmp"), 9999, DateTime.Now);

        var scan = await svc.ScanAsync(cat);

        Assert.Equal(1500, scan.Bytes);
        Assert.Equal(2, scan.Files);
    }

    [Fact]
    public async Task Clean_removes_old_files_keeps_fresh_ones_and_prunes_empty_folders()
    {
        var (svc, cat, root) = Setup();
        var old = Path.Combine(root, "sub", "old.tmp");
        var fresh = Path.Combine(root, "fresh.tmp");
        Write(old, 2048, DateTime.Now.AddDays(-2));
        Write(fresh, 100, DateTime.Now);

        var result = await svc.CleanAsync(cat);

        Assert.Equal(2048, result.FreedBytes);
        Assert.Equal(1, result.Deleted);
        Assert.False(File.Exists(old));
        Assert.False(Directory.Exists(Path.Combine(root, "sub")));
        Assert.True(File.Exists(fresh));
        Assert.True(Directory.Exists(root));
    }

    [Fact]
    public async Task Locked_files_are_skipped_not_fatal()
    {
        var (svc, cat, root) = Setup();
        var locked = Path.Combine(root, "locked.tmp");
        var free = Path.Combine(root, "free.tmp");
        Write(locked, 10, DateTime.Now.AddDays(-2));
        Write(free, 10, DateTime.Now.AddDays(-2));

        using (new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var result = await svc.CleanAsync(cat);
            Assert.Equal(1, result.Deleted);
            Assert.Equal(1, result.Skipped);
        }
        Assert.True(File.Exists(locked));
        Assert.False(File.Exists(free));
    }

    [Fact]
    public async Task Missing_folder_is_ignored()
    {
        var svc = new CleanerService([new CleanerCategory { Id = "x", Title = "x", Description = "", ResolveRoots = () => [@"C:\definitely\not\here"] }]);
        var scan = await svc.ScanAsync(svc.Categories[0]);
        Assert.Equal(0, scan.Bytes);
    }

    [Fact]
    public void Default_categories_never_include_user_documents()
    {
        var all = new CleanerService().Categories.SelectMany(c => c.ResolveRoots()).Select(r => r.ToLowerInvariant()).ToList();
        var forbidden = new[] { "documents", "desktop", "downloads", "pictures", "\\cookies", "login data", "history" };
        foreach (var root in all)
            Assert.DoesNotContain(forbidden, f => root.EndsWith(f) || root.Contains("\\" + f + "\\"));
    }
}

[Trait("Category", "Live")]
public class WindowsToolsLiveTests
{
    [Fact]
    public async Task Security_audit_returns_all_checks_with_scores()
    {
        if (!OperatingSystem.IsWindows()) return;
        var report = await TestEnv.Core.Audit.RunAsync();
        Assert.True(report.Checks.Count >= 8);
        Assert.InRange(report.Score, 0, 100);
        Assert.All(report.Checks, c => Assert.False(string.IsNullOrWhiteSpace(c.Detail)));
    }

    [Fact]
    public async Task Winget_check_runs_and_parses()
    {
        if (!OperatingSystem.IsWindows()) return;
        var result = await TestEnv.Core.Updater.CheckAsync();
        Assert.True(result.WingetAvailable);
        Assert.Null(result.Error);
        Assert.All(result.Updates, u => Assert.False(string.IsNullOrEmpty(u.Id)));
    }

    [Fact]
    public async Task Cleaner_scan_of_real_categories_does_not_throw()
    {
        if (!OperatingSystem.IsWindows()) return;
        foreach (var c in TestEnv.Core.Cleaner.Categories)
        {
            var scan = await TestEnv.Core.Cleaner.ScanAsync(c);
            Assert.True(scan.Bytes >= 0);
        }
    }
}

public class UpdaterProgressTests
{
    private static List<UpdateProgress> Run(params string[] lines)
    {
        var seen = new List<UpdateProgress>();
        var tracker = new SoftwareUpdaterService.ProgressTracker(new SyncProgress<UpdateProgress>(seen.Add));
        foreach (var l in lines) tracker.OnLine(l);
        return seen;
    }

    private sealed class SyncProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value) => handler(value);
    }

    [Fact]
    public void Download_percentage_is_reported_then_install_phase_has_no_percentage()
    {
        var seen = Run(
            "Found Git [Git.Git] Version 2.46.0",
            "Downloading https://example.com/git.exe",
            "  ██████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒  26%",
            "  ██████████████████████████████  100%",
            "Successfully verified installer hash",
            "Starting package install...");

        Assert.Equal(26, seen.First(p => p.Percent is not null).Percent);
        Assert.Equal(100, seen.Last(p => p.Percent is not null).Percent);
        Assert.Equal("Kuruluyor", seen[^1].Phase);
        Assert.Null(seen[^1].Percent);
    }

    [Fact]
    public void Turkish_output_is_understood()
    {
        var seen = Run("İndiriliyor https://example.com/x.exe", "  ███▒▒▒▒▒  42%", "Paket yüklemesi başlatılıyor...", "Başarıyla yüklendi");
        Assert.Contains(seen, p => p.Percent == 42 && p.Phase == "İndiriliyor");
        Assert.Equal("Tamamlanıyor", seen[^1].Phase);
    }

    [Fact]
    public void Percent_signs_after_install_started_are_ignored()
    {
        var seen = Run("Starting package install...", "Disk usage 80%");
        Assert.All(seen, p => Assert.Null(p.Percent));
    }

    [Fact]
    public void Ansi_escape_codes_are_stripped()
    {
        var seen = Run("\u001b[2K\u001b[1GDownloading", "\u001b[2K  ████  58%\u001b[0m");
        Assert.Equal(58, seen[^1].Percent);
    }

    [Fact]
    public async Task Streaming_runner_splits_carriage_return_progress_lines()
    {
        if (!OperatingSystem.IsWindows()) return;
        var lines = new List<string>();
        var res = await Nova.Core.Services.Platform.ProcessRunner.RunStreamingAsync("powershell",
            ["-NoProfile", "-Command", "[Console]::Out.Write(\"10%`r50%`r100%`nend`n\")"],
            l => { lock (lines) lines.Add(l); }, TimeSpan.FromSeconds(30));
        Assert.True(res.Ok);
        Assert.Equal(["10%", "50%", "100%", "end"], lines);
    }
}

[Trait("Category", "Live")]
public class AppIconLiveTests
{
    [Fact]
    public void Most_installed_programs_resolve_to_a_png_icon()
    {
        if (!OperatingSystem.IsWindows()) return;
        var icons = TestEnv.Core.Icons;
        var names = new[] { "7-Zip", "Google Chrome", "Python Launcher", "Git" };
        var found = names.Select(icons.GetIconPng).Where(b => b is not null).ToList();
        Assert.All(found, b => Assert.Equal(0x89, b![0]));
        Assert.Null(icons.GetIconPng("Definitely Not An Installed Program 123"));
    }

    [Fact]
    public async Task Icons_are_found_for_most_pending_updates()
    {
        if (!OperatingSystem.IsWindows()) return;
        var check = await TestEnv.Core.Updater.CheckAsync();
        if (check.Updates.Count < 5) return;
        var withIcon = check.Updates.Count(u => TestEnv.Core.Icons.GetIconPng(u.Name) is not null);
        Console.WriteLine($"ICON-RATIO {withIcon}/{check.Updates.Count}"); foreach (var u in check.Updates.Where(u => TestEnv.Core.Icons.GetIconPng(u.Name) is null)) Console.WriteLine("NOICON " + u.Name + " | " + u.Id);
        Assert.True(withIcon * 100 / check.Updates.Count >= 55, $"only {withIcon}/{check.Updates.Count} icons resolved");
    }

    [Fact]
    public async Task Startup_items_with_an_existing_program_get_an_icon()
    {
        if (!OperatingSystem.IsWindows()) return;
        var items = (await TestEnv.Core.Startup.GetItemsAsync()).Where(i => i.FileExists && i.ExecutablePath is not null).ToList();
        if (items.Count < 3) return;
        var withIcon = items.Count(i => TestEnv.Core.Icons.GetIconPngForFile(i.ExecutablePath) is not null);
        Console.WriteLine($"STARTUP-ICONS {withIcon}/{items.Count}");
        Assert.True(withIcon * 100 / items.Count >= 80, $"only {withIcon}/{items.Count}");
    }
}