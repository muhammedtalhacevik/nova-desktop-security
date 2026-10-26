using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Nova.Core.Models;
using Nova.Core.Services.Platform;

namespace Nova.Core.Services.Privacy;

public sealed record ToggleOutcome(bool Success, string Message);

public sealed class StartupAppsService
{
    private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOncePath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string Run32Path = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string ApprovedPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\";

    public Task<List<StartupItem>> GetItemsAsync(CancellationToken ct = default)
    {
        if (OperatingSystem.IsWindows()) return Task.Run(GetWindowsItems, ct);
        if (OperatingSystem.IsMacOS()) return GetMacItemsAsync(ct);
        return Task.FromResult(new List<StartupItem>());
    }

    public Task<ToggleOutcome> SetEnabledAsync(StartupItem item, bool enabled, CancellationToken ct = default)
    {
        if (OperatingSystem.IsWindows()) return Task.FromResult(SetWindowsEnabled(item, enabled));
        if (OperatingSystem.IsMacOS()) return SetMacEnabledAsync(item, enabled, ct);
        return Task.FromResult(new ToggleOutcome(false, "Bu platformda desteklenmiyor."));
    }

    [SupportedOSPlatform("windows")]
    private static List<StartupItem> GetWindowsItems()
    {
        var items = new List<StartupItem>();
        using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

        ReadRunKey(items, hkcu, RunPath, "Kullanıcı kayıt defteri (Run)", "HKCU", "Run", false);
        ReadRunKey(items, hkcu, RunOncePath, "Kullanıcı kayıt defteri (RunOnce)", "HKCU", null, false);
        ReadRunKey(items, hklm, RunPath, "Sistem kayıt defteri (Run)", "HKLM", "Run", true);
        ReadRunKey(items, hklm, Run32Path, "Sistem kayıt defteri (32-bit)", "HKLM", "Run32", true);

        ReadStartupFolder(items, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Başlangıç klasörü (kullanıcı)", "HKCU", false);
        ReadStartupFolder(items, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Başlangıç klasörü (tüm kullanıcılar)", "HKLM", true);

        foreach (var item in items) Enrich(item);
        return items.OrderBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    [SupportedOSPlatform("windows")]
    private static void ReadRunKey(List<StartupItem> items, RegistryKey hive, string path, string location, string hiveName, string? approvedSub, bool admin)
    {
        try
        {
            using var key = hive.OpenSubKey(path);
            if (key is null) return;
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is not string command || command.Length == 0) continue;
                items.Add(new StartupItem
                {
                    Id = $"{hiveName}\\{path}\\{name}",
                    Name = name,
                    Command = command,
                    ExecutablePath = ExtractExecutable(command),
                    Location = location,
                    Enabled = approvedSub is null || IsApproved(hive, approvedSub, name),
                    CanToggle = approvedSub is not null,
                    RequiresAdmin = admin,
                    SourceKey = $"{hiveName}|{approvedSub}",
                    SourceValue = name
                });
            }
        }
        catch (Exception) { }
    }

    [SupportedOSPlatform("windows")]
    private static void ReadStartupFolder(List<StartupItem> items, string folder, string location, string hiveName, bool admin)
    {
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
        using var hive = RegistryKey.OpenBaseKey(hiveName == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var file in Directory.EnumerateFiles(folder))
        {
            var fileName = Path.GetFileName(file);
            if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            string? target = file;
            var command = file;
            if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                var (t, args) = ShellLink.Read(file);
                target = t;
                command = $"{t} {args}".Trim();
                if (command.Length == 0) command = file;
            }
            items.Add(new StartupItem
            {
                Id = $"{hiveName}\\StartupFolder\\{fileName}",
                Name = Path.GetFileNameWithoutExtension(file),
                Command = command,
                ExecutablePath = target,
                Location = location,
                Enabled = IsApproved(hive, "StartupFolder", fileName),
                CanToggle = true,
                RequiresAdmin = admin,
                SourceKey = $"{hiveName}|StartupFolder",
                SourceValue = fileName
            });
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsApproved(RegistryKey hive, string sub, string name)
    {
        try
        {
            using var key = hive.OpenSubKey(ApprovedPath + sub);
            return key?.GetValue(name) is not byte[] { Length: > 0 } data || (data[0] & 1) == 0;
        }
        catch { return true; }
    }

    [SupportedOSPlatform("windows")]
    private static ToggleOutcome SetWindowsEnabled(StartupItem item, bool enabled)
    {
        if (!item.CanToggle || item.SourceKey is null || item.SourceValue is null)
            return new(false, "Bu öğe Nova tarafından değiştirilemez.");
        var parts = item.SourceKey.Split('|');
        try
        {
            using var hive = RegistryKey.OpenBaseKey(parts[0] == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hive.CreateSubKey(ApprovedPath + parts[1], true);
            var data = new byte[12];
            data[0] = enabled ? (byte)0x02 : (byte)0x03;
            if (!enabled) BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 4);
            key.SetValue(item.SourceValue, data, RegistryValueKind.Binary);
            item.Enabled = enabled;
            return new(true, enabled ? $"{item.Name} başlangıçta çalışacak." : $"{item.Name} artık başlangıçta çalışmayacak.");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new(false, "Bu öğeyi değiştirmek için Nova'yı yönetici olarak çalıştırın.");
        }
        catch (Exception ex)
        {
            return new(false, ex.Message);
        }
    }

    internal static string? ExtractExecutable(string command)
    {
        var cmd = Environment.ExpandEnvironmentVariables(command.Trim());
        string? path;
        if (cmd.StartsWith('"'))
        {
            var end = cmd.IndexOf('"', 1);
            path = end > 1 ? cmd[1..end] : cmd.Trim('"');
        }
        else
        {
            var m = Regex.Match(cmd, @"^(.+?\.(exe|com|bat|cmd|vbs|js|ps1|scr|dll))(\s|,|$)", RegexOptions.IgnoreCase);
            path = m.Success ? m.Groups[1].Value : cmd.Split(' ')[0];
        }

        var file = Path.GetFileName(path).ToLowerInvariant();
        if (file is "rundll32.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "regsvr32.exe")
        {
            var rest = cmd[(cmd.IndexOf(Path.GetFileName(path), StringComparison.OrdinalIgnoreCase) + Path.GetFileName(path).Length)..].Trim().Trim('"');
            var m = Regex.Match(rest, @"^(?:/\w+\s+)*""?([^""]+?\.(dll|vbs|js|hta|ocx|cpl))", RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value;
        }

        if (!Path.IsPathRooted(path) && OperatingSystem.IsWindows())
        {
            var sys = Path.Combine(Environment.SystemDirectory, path);
            if (File.Exists(sys)) return sys;
        }
        return path;
    }

    private static void Enrich(StartupItem item)
    {
        var exe = item.ExecutablePath;
        if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
        {
            item.FileExists = false;
            item.Warnings.Add("Hedef dosya bulunamadı (kalıntı kayıt).");
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(exe);
                item.Publisher = string.IsNullOrWhiteSpace(vi.CompanyName) ? null : vi.CompanyName.Trim();
            }
            catch { }
            item.IsSigned = WinTrust.Verify(exe, out var signer);
            if (signer is not null) item.Publisher = signer;
        }

        if (item.IsSigned == false) item.Warnings.Add("Dijital imza yok — yayıncı doğrulanamıyor.");
        var lower = exe.ToLowerInvariant();
        if (lower.Contains(@"\temp\") || lower.Contains("/tmp/") || lower.Contains(@"\appdata\local\temp"))
            item.Warnings.Add("Geçici klasörden çalışıyor — zararlı yazılımlarda sık görülür.");
        if (Regex.IsMatch(item.Command, @"-(enc|encodedcommand)\s|FromBase64String|-w(indowstyle)?\s+hidden", RegexOptions.IgnoreCase))
            item.Warnings.Add("Gizlenmiş / kodlanmış komut satırı içeriyor.");
        if (Regex.IsMatch(Path.GetFileNameWithoutExtension(exe), @"^[a-z0-9]{12,}$", RegexOptions.IgnoreCase) && !Regex.IsMatch(Path.GetFileNameWithoutExtension(exe), "[aeiou]{1}.*[aeiou]", RegexOptions.IgnoreCase))
            item.Warnings.Add("Rastgele görünen dosya adı.");
    }

    [DllImport("libc")]
    private static extern uint getuid();

    private static async Task<List<StartupItem>> GetMacItemsAsync(CancellationToken ct)
    {
        var uid = getuid();
        var disabledUser = await LaunchctlDisabledAsync($"gui/{uid}", ct);
        var disabledSystem = await LaunchctlDisabledAsync("system", ct);

        var items = new List<StartupItem>();
        var sources = new[]
        {
            (Path.Combine(AppPaths.Home, "Library", "LaunchAgents"), "Kullanıcı Launch Agent", false, disabledUser),
            ("/Library/LaunchAgents", "Sistem Launch Agent", true, disabledUser),
            ("/Library/LaunchDaemons", "Sistem Launch Daemon (root)", true, disabledSystem)
        };

        foreach (var (dir, location, admin, disabled) in sources)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var plist in Directory.EnumerateFiles(dir, "*.plist"))
            {
                ct.ThrowIfCancellationRequested();
                var res = await ProcessRunner.RunAsync("/usr/bin/plutil", ["-convert", "json", "-o", "-", plist], TimeSpan.FromSeconds(5), ct);
                if (!res.Ok) continue;
                try
                {
                    using var doc = JsonDocument.Parse(res.StdOut);
                    var r = doc.RootElement;
                    var label = r.TryGetProperty("Label", out var l) ? l.GetString() ?? Path.GetFileNameWithoutExtension(plist) : Path.GetFileNameWithoutExtension(plist);
                    string? program = r.TryGetProperty("Program", out var p) ? p.GetString() : null;
                    var args = r.TryGetProperty("ProgramArguments", out var pa) && pa.ValueKind == JsonValueKind.Array
                        ? pa.EnumerateArray().Select(a => a.GetString() ?? "").ToList()
                        : [];
                    program ??= args.FirstOrDefault();
                    var plistDisabled = r.TryGetProperty("Disabled", out var d) && d.ValueKind == JsonValueKind.True;
                    var runAtLoad = r.TryGetProperty("RunAtLoad", out var ral) && ral.ValueKind == JsonValueKind.True
                                    || r.TryGetProperty("KeepAlive", out var ka) && ka.ValueKind != JsonValueKind.False;

                    var item = new StartupItem
                    {
                        Id = $"launchd:{plist}",
                        Name = FriendlyLabel(label),
                        Command = args.Count > 0 ? string.Join(' ', args) : program ?? "",
                        ExecutablePath = program,
                        Location = location + (runAtLoad ? "" : " (isteğe bağlı)"),
                        Enabled = !plistDisabled && !(disabled.TryGetValue(label, out var dis) && dis),
                        CanToggle = !admin,
                        RequiresAdmin = admin,
                        SourceKey = plist,
                        SourceValue = label
                    };
                    await EnrichMacAsync(item, ct);
                    items.Add(item);
                }
                catch (JsonException) { }
            }
        }
        return items.OrderBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    public static async Task<List<StartupItem>> GetMacLoginItemsAsync(CancellationToken ct)
    {
        var list = new List<StartupItem>();
        if (!OperatingSystem.IsMacOS()) return list;
        var res = await ProcessRunner.RunAsync("/usr/bin/osascript",
            ["-e", "tell application \"System Events\" to get the {name, path} of every login item"], TimeSpan.FromSeconds(20), ct);
        if (!res.Ok) return list;
        var parts = res.StdOut.Trim().Split(", ");
        var half = parts.Length / 2;
        for (var i = 0; i < half; i++)
        {
            var item = new StartupItem
            {
                Id = $"loginitem:{parts[i]}",
                Name = parts[i],
                Command = parts[half + i],
                ExecutablePath = parts[half + i],
                Location = "Oturum açma öğesi",
                CanToggle = false
            };
            await EnrichMacAsync(item, ct);
            list.Add(item);
        }
        return list;
    }

    private static async Task<Dictionary<string, bool>> LaunchctlDisabledAsync(string domain, CancellationToken ct)
    {
        var map = new Dictionary<string, bool>(StringComparer.Ordinal);
        var res = await ProcessRunner.RunAsync("/bin/launchctl", ["print-disabled", domain], TimeSpan.FromSeconds(5), ct);
        foreach (Match m in Regex.Matches(res.StdOut, @"""([^""]+)""\s*=>\s*(\w+)"))
            map[m.Groups[1].Value] = m.Groups[2].Value is "disabled" or "true";
        return map;
    }

    private static async Task EnrichMacAsync(StartupItem item, CancellationToken ct)
    {
        var exe = item.ExecutablePath;
        if (string.IsNullOrEmpty(exe) || !(File.Exists(exe) || Directory.Exists(exe)))
        {
            item.FileExists = false;
            item.Warnings.Add("Hedef program bulunamadı (kalıntı kayıt).");
            return;
        }
        var res = await ProcessRunner.RunAsync("/usr/bin/codesign", ["-dv", "--verbose=2", exe], TimeSpan.FromSeconds(8), ct);
        var text = res.StdErr + res.StdOut;
        if (text.Contains("not signed", StringComparison.OrdinalIgnoreCase))
        {
            item.IsSigned = false;
            item.Warnings.Add("Kod imzası yok — geliştirici doğrulanamıyor.");
        }
        else if (Regex.Match(text, @"Authority=(.+)") is { Success: true } a)
        {
            item.IsSigned = true;
            item.Publisher = Regex.Replace(a.Groups[1].Value.Trim(), @"^(Developer ID Application|Apple Development|Mac Developer):\s*", "");
        }
        if (exe.StartsWith("/tmp/", StringComparison.Ordinal) || exe.StartsWith("/private/tmp/", StringComparison.Ordinal) || exe.Contains("/.", StringComparison.Ordinal))
            item.Warnings.Add("Geçici veya gizli bir konumdan çalışıyor.");
        if (Regex.IsMatch(item.Command, @"(curl|wget)\s.+\|\s*(ba|z)?sh|base64\s+(-d|--decode)", RegexOptions.IgnoreCase))
            item.Warnings.Add("İnternetten kod indirip çalıştıran komut içeriyor.");
    }

    private static async Task<ToggleOutcome> SetMacEnabledAsync(StartupItem item, bool enabled, CancellationToken ct)
    {
        if (!item.CanToggle || item.SourceValue is null || item.SourceKey is null)
            return new(false, "Sistem öğelerini değiştirmek için yönetici yetkisi gerekir.");
        var uid = getuid();
        var target = $"gui/{uid}/{item.SourceValue}";
        var res = await ProcessRunner.RunAsync("/bin/launchctl", [enabled ? "enable" : "disable", target], TimeSpan.FromSeconds(8), ct);
        if (!res.Ok) return new(false, res.StdErr.Trim().Length > 0 ? res.StdErr.Trim() : "launchctl işlemi başarısız.");
        if (enabled) await ProcessRunner.RunAsync("/bin/launchctl", ["bootstrap", $"gui/{uid}", item.SourceKey], TimeSpan.FromSeconds(8), ct);
        else await ProcessRunner.RunAsync("/bin/launchctl", ["bootout", $"gui/{uid}", item.SourceKey], TimeSpan.FromSeconds(8), ct);
        item.Enabled = enabled;
        return new(true, enabled ? $"{item.Name} etkinleştirildi." : $"{item.Name} devre dışı bırakıldı.");
    }

    private static string FriendlyLabel(string label)
    {
        var parts = label.Split('.');
        return parts.Length > 2 && parts[0] is "com" or "org" or "net" or "io" ? string.Join(' ', parts[1..]) : label;
    }
}
