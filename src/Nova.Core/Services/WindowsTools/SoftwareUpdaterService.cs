using System.Text.RegularExpressions;
using Nova.Core.Services.Platform;

namespace Nova.Core.Services.WindowsTools;

public sealed record AppUpdate(string Name, string Id, string CurrentVersion, string AvailableVersion, string Source);

public sealed record UpdateCheck(bool WingetAvailable, IReadOnlyList<AppUpdate> Updates, string? Error);

public sealed record UpdateOutcome(bool Success, string Message);

public sealed record UpdateProgress(double? Percent, string Phase);

public sealed class SoftwareUpdaterService
{
    private static readonly Regex SafeId = new(@"^[A-Za-z0-9][A-Za-z0-9._\-+]{0,127}$", RegexOptions.Compiled);
    private static readonly string[] CommonArgs = ["--accept-source-agreements", "--disable-interactivity"];

    public async Task<UpdateCheck> CheckAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) return new(false, [], "Bu özellik yalnızca Windows'ta kullanılabilir.");

        var version = await ProcessRunner.RunAsync("winget", ["--version"], TimeSpan.FromSeconds(15), ct);
        if (!version.Ok)
            return new(false, [], "Windows Paket Yöneticisi (winget) bulunamadı. Microsoft Store'dan \"Uygulama Yükleyicisi\"ni (App Installer) yükleyin.");

        var res = await ProcessRunner.RunAsync("winget", ["upgrade", .. CommonArgs], TimeSpan.FromSeconds(120), ct);
        if (res.ExitCode != 0 && res.StdOut.Trim().Length == 0)
            return new(true, [], "Güncelleme listesi alınamadı: " + (res.StdErr.Trim().Length > 0 ? res.StdErr.Trim() : $"çıkış kodu {res.ExitCode}"));

        return new(true, ParseTable(res.StdOut), null);
    }

    public async Task<UpdateOutcome> UpdateAsync(AppUpdate app, IProgress<UpdateProgress>? progress = null, CancellationToken ct = default)
    {
        if (!SafeId.IsMatch(app.Id)) return new(false, "Geçersiz paket kimliği.");

        var tracker = new ProgressTracker(progress);
        progress?.Report(new UpdateProgress(null, "Hazırlanıyor"));
        var res = await ProcessRunner.RunStreamingAsync("winget",
            ["upgrade", "--id", app.Id, "--exact", "--silent", "--accept-package-agreements", .. CommonArgs],
            tracker.OnLine, TimeSpan.FromMinutes(20), ct);

        if (res.Ok) return new(true, $"{app.Name} güncellendi.");

        var last = Clean(res.StdOut).Concat(Clean(res.StdErr)).LastOrDefault(l => l.Length > 3) ?? $"çıkış kodu {res.ExitCode}";
        return new(false, last.Length > 160 ? last[..160] + "…" : last);
    }

    private static readonly Regex AnsiEscapes = new(@"\x1B\[[0-9;?]*[A-Za-z]", RegexOptions.Compiled);
    private static readonly Regex Percent = new(@"(\d{1,3})\s?%", RegexOptions.Compiled);
    private static readonly Regex DownloadPhase = new(@"Downloading|İndiriliyor|Indiriliyor", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex InstallPhase = new(@"Starting package install|Installing|Yükleniyor|Paket yüklemesi başlatılıyor|Kuruluyor|Yükleme", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex DonePhase = new(@"Successfully installed|Başarıyla yüklendi", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    internal sealed class ProgressTracker(IProgress<UpdateProgress>? progress)
    {
        private string _phase = "Hazırlanıyor";
        private double? _last;
        private bool _installing;

        public void OnLine(string raw)
        {
            if (progress is null) return;
            var line = AnsiEscapes.Replace(raw, "").Trim();
            if (line.Length == 0) return;

            if (DonePhase.IsMatch(line)) { _installing = true; _phase = "Tamamlanıyor"; _last = null; }
            else if (InstallPhase.IsMatch(line)) { _installing = true; _phase = "Kuruluyor"; _last = null; }
            else if (DownloadPhase.IsMatch(line) && !_installing) _phase = "İndiriliyor";

            if (!_installing && Percent.Match(line) is { Success: true } m && int.TryParse(m.Groups[1].Value, out var pct) && pct is >= 0 and <= 100)
            {
                _phase = "İndiriliyor";
                _last = pct;
            }
            progress.Report(new UpdateProgress(_last, _phase));
        }
    }

    private static IEnumerable<string> Clean(string output) =>
        output.Replace("\r\n", "\n").Split('\n')
            .Select(l => l.Contains('\r') ? l[(l.LastIndexOf('\r') + 1)..] : l)
            .Select(l => l.TrimEnd())
            .Where(l => l.Length > 0);

    internal static List<AppUpdate> ParseTable(string output)
    {
        var lines = output.Replace("\r\n", "\n").Split('\n')
            .Select(l => l.Contains('\r') ? l[(l.LastIndexOf('\r') + 1)..] : l)
            .Select(l => l.TrimEnd())
            .ToList();

        var sep = lines.FindIndex(l => l.Length >= 10 && l.All(c => c == '-'));
        if (sep < 1) return [];

        var header = lines[sep - 1];
        var starts = Regex.Matches(header, @"\S+").Select(m => m.Index).ToList();
        if (starts.Count < 4) return [];

        var result = new List<AppUpdate>();
        foreach (var line in lines.Skip(sep + 1))
        {
            if (line.Length == 0) break;
            if (line.Length <= starts[2]) continue;

            string Col(int i)
            {
                var from = Math.Min(starts[i], line.Length);
                var to = i + 1 < starts.Count ? Math.Min(starts[i + 1], line.Length) : line.Length;
                return line[from..to].Trim();
            }

            var name = Col(0);
            var id = Col(1);
            if (name.Length == 0 || !SafeId.IsMatch(id)) continue;

            result.Add(new AppUpdate(name, id, Col(2), Col(3), starts.Count > 4 ? Col(4) : ""));
        }
        return result;
    }
}
