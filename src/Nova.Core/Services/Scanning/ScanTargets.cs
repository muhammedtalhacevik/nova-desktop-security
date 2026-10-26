using System.Diagnostics;
using Nova.Core.Models;

namespace Nova.Core.Services.Scanning;

public sealed record ScanRoot(string Path, int MaxDepth, bool RiskyOnly);

public static class ScanTargets
{
    private const FileAttributes CloudPlaceholder = FileAttributes.Offline | (FileAttributes)0x00040000 | (FileAttributes)0x00400000;

    public static IReadOnlyList<ScanRoot> Quick()
    {
        var home = AppPaths.Home;
        var list = new List<ScanRoot>
        {
            new(AppPaths.Downloads, 4, false),
            new(AppPaths.Desktop, 3, false),
            new(AppPaths.Documents, 2, true),
            new(Path.GetTempPath(), 3, true)
        };

        if (OperatingSystem.IsWindows())
        {
            list.Add(new(Environment.GetFolderPath(Environment.SpecialFolder.Startup), 2, false));
            list.Add(new(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), 2, false));
            list.Add(new(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 2, true));
            list.Add(new(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 1, true));
            list.Add(new(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 1, true));
            list.Add(new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Tasks"), 2, false));
            list.Add(new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), 2, true));
            list.Add(new(@"C:\Users\Public", 3, true));
        }
        else if (OperatingSystem.IsMacOS())
        {
            list.Add(new(Path.Combine(home, "Library", "LaunchAgents"), 1, false));
            list.Add(new("/Library/LaunchAgents", 1, false));
            list.Add(new("/Library/LaunchDaemons", 1, false));
            list.Add(new(Path.Combine(home, "Library", "Application Support"), 1, true));
            list.Add(new("/Users/Shared", 3, true));
            list.Add(new("/private/tmp", 2, true));
        }
        else
        {
            list.Add(new(Path.Combine(home, ".config", "autostart"), 1, false));
            list.Add(new("/tmp", 2, true));
        }

        return list.Where(r => !string.IsNullOrEmpty(r.Path)).DistinctBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static IReadOnlyList<ScanRoot> Full()
    {
        if (OperatingSystem.IsWindows())
        {
            return DriveInfo.GetDrives()
                .Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable && SafeReady(d))
                .Select(d => new ScanRoot(d.RootDirectory.FullName, int.MaxValue, false))
                .ToList();
        }
        return [new ScanRoot("/", int.MaxValue, false)];
    }

    public static IReadOnlyList<ScanRoot> Custom(IEnumerable<string> paths) =>
        paths.Select(p => new ScanRoot(p, int.MaxValue, false)).ToList();

    public static IEnumerable<string> RunningProcessImages()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            string? path = null;
            try { path = p.MainModule?.FileName; }
            catch { /* access denied for protected / other-user processes */ }
            finally { p.Dispose(); }
            if (path is not null && seen.Add(path) && File.Exists(path))
                yield return path;
        }
    }

    private static bool SafeReady(DriveInfo d)
    {
        try { return d.IsReady; } catch { return false; }
    }

    private static readonly string[] WindowsSkip =
    [
        @"\Windows\WinSxS", @"\Windows\servicing", @"\Windows\SoftwareDistribution\Download", @"\System Volume Information",
        @"\Windows\Installer\$PatchCache$", @"\$WinREAgent"
    ];

    private static readonly string[] UnixSkip =
    [
        "/System", "/dev", "/proc", "/sys", "/Volumes", "/private/var/vm", "/private/var/db/uuidtext", "/cores", "/net", "/home/.snapshots",
        "/Library/Developer/CoreSimulator", "/private/var/folders"
    ];

    public static IEnumerable<string> Enumerate(ScanRoot root, Func<string, bool> isExcluded, CancellationToken ct)
    {
        if (File.Exists(root.Path))
        {
            if (!isExcluded(root.Path)) yield return root.Path;
            yield break;
        }
        if (!Directory.Exists(root.Path)) yield break;

        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false
        };

        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((root.Path, 0));
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();
            if (ShouldSkipDirectory(dir) || isExcluded(dir)) continue;

            IEnumerable<FileSystemInfo> entries;
            try { entries = new DirectoryInfo(dir).EnumerateFileSystemInfos("*", options); }
            catch { continue; }

            using var e = entries.GetEnumerator();
            while (true)
            {
                FileSystemInfo entry;
                try
                {
                    if (!e.MoveNext()) break;
                    entry = e.Current;
                }
                catch { break; }

                if (entry is DirectoryInfo sub)
                {
                    var bonus = sub.Name.EndsWith(".app", StringComparison.OrdinalIgnoreCase) ? 3 : 0;
                    if (depth + 1 <= root.MaxDepth + bonus) stack.Push((sub.FullName, depth + 1));
                    continue;
                }

                FileAttributes attrs;
                try { attrs = entry.Attributes; } catch { continue; }
                if ((attrs & CloudPlaceholder) != 0) continue;
                if (root.RiskyOnly && !FileTypes.IsRisky(entry.Extension)) continue;
                if (isExcluded(entry.FullName)) continue;
                yield return entry.FullName;
            }
        }
    }

    private static bool ShouldSkipDirectory(string dir)
    {
        if (dir.StartsWith(AppPaths.Root, StringComparison.OrdinalIgnoreCase)) return true;
        if (OperatingSystem.IsWindows())
        {
            var noDrive = dir.Length > 2 && dir[1] == ':' ? dir[2..] : dir;
            return WindowsSkip.Any(s => noDrive.StartsWith(s, StringComparison.OrdinalIgnoreCase));
        }
        return UnixSkip.Any(s => dir.Equals(s, StringComparison.Ordinal) || dir.StartsWith(s + "/", StringComparison.Ordinal));
    }

    public static string Describe(ScanType type) => type switch
    {
        ScanType.Quick => "İndirilenler, masaüstü, geçici klasörler, başlangıç konumları ve çalışan işlemler",
        ScanType.Full => "Tüm yerel diskler ve çalışan işlemler",
        _ => "Seçilen klasör ve dosyalar"
    };
}
