using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Nova.Core.Services.WindowsTools;

public sealed class AppIconService
{
    private sealed record Entry(string? DisplayIcon, string? InstallLocation, string? UninstallString);

    private static readonly string[] UninstallPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ];

    private Dictionary<string, Entry>? _index;
    private readonly object _gate = new();

    public byte[]? GetIconPng(string appName)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(appName)) return null;
        try
        {
            var index = Index();
            var entry = Find(index, appName);
            var path = entry is null ? null : ResolveExecutable(entry, appName);
            path ??= SearchProgramFolders(appName);
            return path is null ? null : ToPng(path);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly Dictionary<string, byte[]?> _fileCache = new(StringComparer.OrdinalIgnoreCase);

    public byte[]? GetIconPngForFile(string? path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path)) return null;
        lock (_gate)
            if (_fileCache.TryGetValue(path, out var cached)) return cached;

        byte[]? png = null;
        try
        {
            if (File.Exists(path) && Path.GetExtension(path).ToLowerInvariant() is ".exe" or ".ico" or ".dll" or ".scr")
                png = ToPng(path);
        }
        catch (Exception) { /* cosmetic only */ }

        lock (_gate) _fileCache[path] = png;
        return png;
    }

    private Dictionary<string, Entry> Index()
    {
        lock (_gate) return _index ??= BuildIndex();
    }

    [SupportedOSPlatform("windows")]
    private static Dictionary<string, Entry> BuildIndex()
    {
        var map = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            foreach (var path in UninstallPaths)
            {
                using var key = baseKey.OpenSubKey(path);
                if (key is null) continue;
                foreach (var name in key.GetSubKeyNames())
                {
                    try
                    {
                        using var sub = key.OpenSubKey(name);
                        if (sub?.GetValue("DisplayName") is not string display || display.Length == 0) continue;
                        map.TryAdd(display, new Entry(sub.GetValue("DisplayIcon") as string, sub.GetValue("InstallLocation") as string, sub.GetValue("UninstallString") as string));
                    }
                    catch (Exception) { }
                }
            }
        }
        return map;
    }

    private static Entry? Find(Dictionary<string, Entry> index, string name)
    {
        if (index.TryGetValue(name, out var exact)) return exact;
        var trimmed = name.TrimEnd('…', '.').Trim();
        foreach (var (key, value) in index)
            if (key.StartsWith(trimmed, StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith(key, StringComparison.OrdinalIgnoreCase))
                return value;
        return null;
    }

    private static string? ResolveExecutable(Entry entry, string appName)
    {
        if (!string.IsNullOrWhiteSpace(entry.DisplayIcon))
        {
            var raw = entry.DisplayIcon!.Trim();
            var comma = raw.LastIndexOf(',');
            if (comma > 3 && int.TryParse(raw[(comma + 1)..].Trim(), out _)) raw = raw[..comma];
            raw = Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"'));
            if (File.Exists(raw) && Path.GetExtension(raw).ToLowerInvariant() is ".exe" or ".ico" or ".dll") return raw;
        }

        foreach (var dir in CandidateFolders(entry))
        {
            var exes = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly)
                .Where(f => !Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase)
                            && !Path.GetFileName(f).Contains("update", StringComparison.OrdinalIgnoreCase)
                            && !Path.GetFileName(f).Contains("crash", StringComparison.OrdinalIgnoreCase)
                            && !Path.GetFileName(f).Contains("setup", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var firstWord = appName.Split(' ', '-', '(')[0];
            var best = exes.FirstOrDefault(f => Path.GetFileNameWithoutExtension(f).StartsWith(firstWord, StringComparison.OrdinalIgnoreCase)) ?? exes.FirstOrDefault();
            if (best is not null) return best;
        }
        return null;
    }

    private static string? SearchProgramFolders(string appName)
    {
        var word = appName.Split(' ', '-', '(', '.', ',')[0];
        if (word.Length < 3) return null;

        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs")
        };
        var options = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 3, AttributesToSkip = FileAttributes.ReparsePoint };

        foreach (var root in roots.Where(Directory.Exists))
        {
            foreach (var dir in Directory.EnumerateDirectories(root).Where(d => Path.GetFileName(d).StartsWith(word, StringComparison.OrdinalIgnoreCase)))
            {
                var exe = Directory.EnumerateFiles(dir, "*.exe", options)
                    .Where(f => !Path.GetFileName(f).Contains("unins", StringComparison.OrdinalIgnoreCase)
                                && !Path.GetFileName(f).Contains("update", StringComparison.OrdinalIgnoreCase)
                                && !Path.GetFileName(f).Contains("crash", StringComparison.OrdinalIgnoreCase)
                                && !Path.GetFileName(f).Contains("setup", StringComparison.OrdinalIgnoreCase)
                                && !Path.GetFileName(f).Contains("helper", StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(f => Path.GetFileNameWithoutExtension(f).StartsWith(word, StringComparison.OrdinalIgnoreCase))
                    .ThenBy(f => f.Length)
                    .FirstOrDefault();
                if (exe is not null) return exe;
            }
        }
        return null;
    }

    private static IEnumerable<string> CandidateFolders(Entry entry)
    {
        var location = entry.InstallLocation?.Trim().Trim('"');
        if (!string.IsNullOrEmpty(location) && Directory.Exists(location)) yield return location;

        var uninstall = entry.UninstallString?.Trim();
        if (string.IsNullOrEmpty(uninstall)) yield break;
        var path = uninstall.StartsWith('"') ? uninstall[1..Math.Max(1, uninstall.IndexOf('"', 1))] : uninstall.Split(' ', 2)[0];
        if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && Path.GetDirectoryName(path) is { Length: > 0 } dir && Directory.Exists(dir)
            && !dir.Contains("Windows\\Installer", StringComparison.OrdinalIgnoreCase)
            && !dir.Contains("InstallShield Installation Information", StringComparison.OrdinalIgnoreCase)
            && !dir.Equals(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase))
            yield return dir;
    }

    [SupportedOSPlatform("windows")]
    private static byte[]? ToPng(string path)
    {
        using var icon = Path.GetExtension(path).Equals(".ico", StringComparison.OrdinalIgnoreCase)
            ? new Icon(path, 64, 64)
            : Icon.ExtractAssociatedIcon(path);
        if (icon is null) return null;
        using var bitmap = icon.ToBitmap();
        using var ms = new MemoryStream();
        bitmap.Save(ms, ImageFormat.Png);
        return ms.ToArray();
    }
}
