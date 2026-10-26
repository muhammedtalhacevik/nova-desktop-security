using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Nova.Core.Services.WindowsTools;

public sealed class CleanerCategory
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public bool DefaultSelected { get; init; } = true;
    public bool NeedsAdmin { get; init; }
    public bool IsRecycleBin { get; init; }

    public TimeSpan MinAge { get; init; } = TimeSpan.Zero;

    public Func<IReadOnlyList<string>> ResolveRoots { get; init; } = () => [];
}

public sealed record CleanScan(long Bytes, long Files, bool MayBeIncomplete);

public sealed record CleanOutcome(long FreedBytes, long Deleted, long Skipped);

public sealed class CleanerService
{
    private readonly IReadOnlyList<CleanerCategory> _categories;

    public CleanerService(IEnumerable<CleanerCategory>? categories = null)
    {
        _categories = (categories ?? DefaultCategories()).ToList();
    }

    public IReadOnlyList<CleanerCategory> Categories => _categories;

    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public Task<CleanScan> ScanAsync(CleanerCategory category, CancellationToken ct = default) => Task.Run(() =>
    {
        if (category.IsRecycleBin) return QueryRecycleBin();

        long bytes = 0, files = 0;
        var incomplete = false;
        foreach (var root in category.ResolveRoots())
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in EnumerateFiles(root, category.MinAge, ct))
                {
                    try { bytes += file.Length; files++; }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { incomplete = true; }
        }
        return new CleanScan(bytes, files, incomplete || (category.NeedsAdmin && !IsElevated()));
    }, ct);

    public Task<CleanOutcome> CleanAsync(CleanerCategory category, CancellationToken ct = default) => Task.Run(() =>
    {
        if (category.IsRecycleBin) return EmptyRecycleBin();

        long freed = 0, deleted = 0, skipped = 0;
        foreach (var root in category.ResolveRoots())
        {
            if (!Directory.Exists(root)) continue;
            var rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

            foreach (var file in EnumerateFiles(root, category.MinAge, ct).ToList())
            {
                ct.ThrowIfCancellationRequested();
                if (!file.FullName.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)) { skipped++; continue; }
                try
                {
                    var size = file.Length;
                    file.Attributes = FileAttributes.Normal;
                    file.Delete();
                    freed += size;
                    deleted++;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    skipped++;
                }
            }
            RemoveEmptyDirectories(root, rootFull);
        }
        return new CleanOutcome(freed, deleted, skipped);
    }, ct);

    internal static IEnumerable<FileInfo> EnumerateFiles(string root, TimeSpan minAge, CancellationToken ct)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false
        };
        var cutoff = DateTime.UtcNow - minAge;
        var appData = AppPaths.Root;

        foreach (var file in new DirectoryInfo(root).EnumerateFiles("*", options))
        {
            ct.ThrowIfCancellationRequested();
            if (file.FullName.StartsWith(appData, StringComparison.OrdinalIgnoreCase)) continue;
            if (minAge > TimeSpan.Zero)
            {
                DateTime newest;
                try { newest = file.LastWriteTimeUtc > file.CreationTimeUtc ? file.LastWriteTimeUtc : file.CreationTimeUtc; }
                catch (IOException) { continue; }
                if (newest > cutoff) continue;
            }
            yield return file;
        }
    }

    private static void RemoveEmptyDirectories(string root, string rootFull)
    {
        try
        {
            var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
            foreach (var dir in new DirectoryInfo(root).EnumerateDirectories("*", options).OrderByDescending(d => d.FullName.Length))
            {
                if (!dir.FullName.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    if (!dir.EnumerateFileSystemInfos().Any()) dir.Delete();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SHQUERYRBINFO
    {
        public uint cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHQueryRecycleBinW(string? rootPath, ref SHQUERYRBINFO info);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBinW(IntPtr hwnd, string? rootPath, uint flags);

    private const uint NoConfirmation = 0x1, NoProgressUi = 0x2, NoSound = 0x4;

    private static CleanScan QueryRecycleBin()
    {
        if (!OperatingSystem.IsWindows()) return new(0, 0, false);
        var info = new SHQUERYRBINFO { cbSize = (uint)Marshal.SizeOf<SHQUERYRBINFO>() };
        return SHQueryRecycleBinW(null, ref info) == 0 ? new CleanScan(info.i64Size, info.i64NumItems, false) : new CleanScan(0, 0, true);
    }

    private static CleanOutcome EmptyRecycleBin()
    {
        if (!OperatingSystem.IsWindows()) return new(0, 0, 0);
        var before = QueryRecycleBin();
        var hr = SHEmptyRecycleBinW(IntPtr.Zero, null, NoConfirmation | NoProgressUi | NoSound);
        return hr == 0 ? new CleanOutcome(before.Bytes, before.Files, 0) : new CleanOutcome(0, 0, before.Files);
    }

    private static string Env(Environment.SpecialFolder f) => Environment.GetFolderPath(f);

    private static IEnumerable<CleanerCategory> DefaultCategories()
    {
        var local = Env(Environment.SpecialFolder.LocalApplicationData);
        var windows = Env(Environment.SpecialFolder.Windows);
        var programData = Env(Environment.SpecialFolder.CommonApplicationData);

        yield return new CleanerCategory
        {
            Id = "user-temp",
            Title = "Geçici dosyalar",
            Description = "Uygulamaların bıraktığı geçici dosyalar (son 24 saatte değişenler korunur).",
            MinAge = TimeSpan.FromHours(24),
            ResolveRoots = () => [Path.GetTempPath()]
        };

        yield return new CleanerCategory
        {
            Id = "browser-cache",
            Title = "Tarayıcı önbellekleri",
            Description = "Chrome, Edge, Brave, Opera ve Firefox önbellekleri. Çerezler, parolalar ve geçmiş silinmez.",
            ResolveRoots = () => BrowserCacheRoots(local)
        };

        yield return new CleanerCategory
        {
            Id = "crash-reports",
            Title = "Hata raporları ve çökme dökümleri",
            Description = "Windows hata raporlama ve uygulama çökme kayıtları.",
            ResolveRoots = () =>
            [
                Path.Combine(local, "CrashDumps"),
                Path.Combine(local, "Microsoft", "Windows", "WER", "ReportArchive"),
                Path.Combine(local, "Microsoft", "Windows", "WER", "ReportQueue"),
                Path.Combine(programData, "Microsoft", "Windows", "WER", "ReportArchive"),
                Path.Combine(programData, "Microsoft", "Windows", "WER", "ReportQueue")
            ]
        };

        yield return new CleanerCategory
        {
            Id = "windows-update",
            Title = "Windows güncelleme artıkları",
            Description = "İndirilmiş ve yüklenmiş güncelleme paketleri ile Teslim Optimizasyonu önbelleği.",
            NeedsAdmin = true,
            ResolveRoots = () =>
            [
                Path.Combine(windows, "SoftwareDistribution", "Download"),
                Path.Combine(windows, "ServiceProfiles", "NetworkService", "AppData", "Local", "Microsoft", "Windows", "DeliveryOptimization", "Cache")
            ]
        };

        yield return new CleanerCategory
        {
            Id = "windows-temp",
            Title = "Windows geçici dosyaları",
            Description = "Sistem geçici klasörü (son 24 saatte değişenler korunur).",
            NeedsAdmin = true,
            MinAge = TimeSpan.FromHours(24),
            ResolveRoots = () => [Path.Combine(windows, "Temp")]
        };

        yield return new CleanerCategory
        {
            Id = "recycle-bin",
            Title = "Geri dönüşüm kutusu",
            Description = "Kutudaki tüm dosyalar kalıcı olarak silinir. Varsayılan olarak seçili gelmez.",
            DefaultSelected = false,
            IsRecycleBin = true
        };
    }

    private static IReadOnlyList<string> BrowserCacheRoots(string local)
    {
        var roots = new List<string>();
        var chromium = new[]
        {
            Path.Combine(local, "Google", "Chrome", "User Data"),
            Path.Combine(local, "Microsoft", "Edge", "User Data"),
            Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"),
            Path.Combine(Env(Environment.SpecialFolder.ApplicationData), "Opera Software", "Opera Stable")
        };

        foreach (var userData in chromium.Where(Directory.Exists))
        {
            var profiles = Directory.EnumerateDirectories(userData)
                .Where(d => Path.GetFileName(d) is "Default" or "Opera Stable" || Path.GetFileName(d).StartsWith("Profile ", StringComparison.Ordinal))
                .Append(userData);
            foreach (var profile in profiles)
                foreach (var sub in new[] { "Cache", "Code Cache", "GPUCache" })
                    roots.Add(Path.Combine(profile, sub));
        }

        var firefox = Path.Combine(local, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(firefox))
            roots.AddRange(Directory.EnumerateDirectories(firefox).Select(p => Path.Combine(p, "cache2")));

        return roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
