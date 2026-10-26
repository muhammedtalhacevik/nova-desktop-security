using System.Runtime.Versioning;
using Microsoft.Win32;
using Nova.Core.Models;
using Nova.Core.Services.Platform;

namespace Nova.Core.Services.Privacy;

public sealed class PermissionsService
{
    private const string ConsentStore = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\";

    private static readonly (string Key, string Title, string Icon, string Uri)[] WindowsCapabilities =
    [
        ("webcam", "Kamera", "Webcam", "ms-settings:privacy-webcam"),
        ("microphone", "Mikrofon", "Microphone", "ms-settings:privacy-microphone"),
        ("location", "Konum", "MapMarker", "ms-settings:privacy-location"),
        ("graphicsCaptureProgrammatic", "Ekran yakalama", "MonitorScreenshot", "ms-settings:privacy-graphicscaptureprogrammatic"),
        ("contacts", "Kişiler", "Contacts", "ms-settings:privacy-contacts"),
        ("appointments", "Takvim", "Calendar", "ms-settings:privacy-calendar"),
        ("email", "E-posta", "Email", "ms-settings:privacy-email"),
        ("documentsLibrary", "Belgeler", "FileDocument", "ms-settings:privacy-documents"),
        ("picturesLibrary", "Resimler", "Image", "ms-settings:privacy-pictures"),
        ("broadFileSystemAccess", "Dosya sistemi", "Harddisk", "ms-settings:privacy-broadfilesystemaccess"),
        ("userNotificationListener", "Bildirimler", "Bell", "ms-settings:privacy-notifications")
    ];

    private static readonly (string Service, string Title, string Icon, string Pane)[] MacServices =
    [
        ("kTCCServiceCamera", "Kamera", "Webcam", "Privacy_Camera"),
        ("kTCCServiceMicrophone", "Mikrofon", "Microphone", "Privacy_Microphone"),
        ("kTCCServiceScreenCapture", "Ekran kaydı", "MonitorScreenshot", "Privacy_ScreenCapture"),
        ("kTCCServiceAccessibility", "Erişilebilirlik (bilgisayarı denetleme)", "Human", "Privacy_Accessibility"),
        ("kTCCServiceListenEvent", "Giriş izleme (klavye)", "Keyboard", "Privacy_ListenEvent"),
        ("kTCCServiceSystemPolicyAllFiles", "Tam disk erişimi", "Harddisk", "Privacy_AllFiles"),
        ("kTCCServiceAddressBook", "Kişiler", "Contacts", "Privacy_Contacts"),
        ("kTCCServiceCalendar", "Takvim", "Calendar", "Privacy_Calendars"),
        ("kTCCServicePhotos", "Fotoğraflar", "Image", "Privacy_Photos"),
        ("kTCCServiceSystemPolicyDocumentsFolder", "Belgeler klasörü", "FileDocument", "Privacy_FilesAndFolders"),
        ("kTCCServiceSystemPolicyDownloadsFolder", "İndirilenler klasörü", "Download", "Privacy_FilesAndFolders"),
        ("kTCCServiceSystemPolicyDesktopFolder", "Masaüstü klasörü", "Monitor", "Privacy_FilesAndFolders"),
        ("kTCCServiceAppleEvents", "Otomasyon", "Robot", "Privacy_Automation")
    ];

    public Task<PermissionReport> GetReportAsync(CancellationToken ct = default)
    {
        if (OperatingSystem.IsWindows()) return Task.Run(GetWindows, ct);
        if (OperatingSystem.IsMacOS()) return GetMacAsync(ct);
        return Task.FromResult(new PermissionReport { Limited = true, Note = "Bu platform için izin raporu bulunmuyor." });
    }

    public static void OpenSettings(PermissionGroup group)
    {
        if (group.SettingsUri is { } uri) ProcessRunner.Open(uri);
    }

    [SupportedOSPlatform("windows")]
    private static PermissionReport GetWindows()
    {
        var report = new PermissionReport();
        using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
        foreach (var (key, title, icon, uri) in WindowsCapabilities)
        {
            using var cap = hkcu.OpenSubKey(ConsentStore + key);
            if (cap is null) continue;

            var group = new PermissionGroup
            {
                Key = key,
                Title = title,
                Icon = icon,
                SettingsUri = uri,
                GloballyAllowed = cap.GetValue("Value") is string v ? v.Equals("Allow", StringComparison.OrdinalIgnoreCase) : null
            };

            foreach (var sub in cap.GetSubKeyNames())
            {
                if (sub.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                {
                    using var np = cap.OpenSubKey(sub);
                    if (np is null) continue;
                    foreach (var exeKey in np.GetSubKeyNames())
                    {
                        using var app = np.OpenSubKey(exeKey);
                        if (app is null) continue;
                        var path = exeKey.Replace('#', '\\');
                        group.Apps.Add(ReadApp(app, Path.GetFileNameWithoutExtension(path), path));
                    }
                }
                else
                {
                    using var app = cap.OpenSubKey(sub);
                    if (app is null) continue;
                    group.Apps.Add(ReadApp(app, PackagedName(sub), null));
                }
            }

            group.Apps = group.Apps
                .OrderByDescending(a => a.InUse)
                .ThenByDescending(a => a.LastUsed ?? DateTimeOffset.MinValue)
                .ToList();
            report.Groups.Add(group);
        }
        return report;
    }

    [SupportedOSPlatform("windows")]
    private static PermissionApp ReadApp(RegistryKey key, string name, string? path)
    {
        var start = key.GetValue("LastUsedTimeStart") is long s ? s : 0;
        var stop = key.GetValue("LastUsedTimeStop") is long e ? e : 0;
        DateTimeOffset? last = null;
        try
        {
            var ft = Math.Max(start, stop);
            if (ft > 0) last = DateTimeOffset.FromFileTime(ft);
        }
        catch (ArgumentOutOfRangeException) { }

        return new PermissionApp
        {
            AppName = name,
            AppPath = path,
            Allowed = key.GetValue("Value") is not string v || v.Equals("Allow", StringComparison.OrdinalIgnoreCase),
            LastUsed = last,
            InUse = start > 0 && stop == 0
        };
    }

    private static string PackagedName(string family)
    {
        var name = family.Split('_')[0];
        var dot = name.LastIndexOf('.');
        return dot >= 0 && dot < name.Length - 1 ? name[(dot + 1)..] : name;
    }

    private static async Task<PermissionReport> GetMacAsync(CancellationToken ct)
    {
        var report = new PermissionReport();
        var dbs = new[]
        {
            Path.Combine(AppPaths.Home, "Library", "Application Support", "com.apple.TCC", "TCC.db"),
            "/Library/Application Support/com.apple.TCC/TCC.db"
        };

        var rows = new List<(string Service, string Client, int Auth, long Modified)>();
        var anyReadable = false;
        foreach (var db in dbs)
        {
            var res = await ProcessRunner.RunAsync("/usr/bin/sqlite3",
                ["-readonly", "-separator", "\t", db, "SELECT service, client, auth_value, last_modified FROM access;"], TimeSpan.FromSeconds(8), ct);
            if (!res.Ok) continue;
            anyReadable = true;
            foreach (var line in res.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var c = line.Split('\t');
                if (c.Length >= 4 && int.TryParse(c[2], out var auth) && long.TryParse(c[3], out var mod))
                    rows.Add((c[0], c[1], auth, mod));
            }
        }

        foreach (var (service, title, icon, pane) in MacServices)
        {
            var group = new PermissionGroup
            {
                Key = service,
                Title = title,
                Icon = icon,
                SettingsUri = $"x-apple.systempreferences:com.apple.preference.security?{pane}"
            };
            foreach (var r in rows.Where(r => r.Service == service).DistinctBy(r => r.Client))
            {
                group.Apps.Add(new PermissionApp
                {
                    AppName = FriendlyClient(r.Client),
                    AppPath = r.Client,
                    Allowed = r.Auth is 2 or 3,
                    LastUsed = r.Modified > 0 ? DateTimeOffset.FromUnixTimeSeconds(r.Modified) : null
                });
            }
            group.Apps = group.Apps.OrderByDescending(a => a.Allowed).ThenBy(a => a.AppName).ToList();
            report.Groups.Add(group);
        }

        if (!anyReadable)
        {
            report.Limited = true;
            report.Note = "macOS izin veritabanını (TCC) okumak için Nova'ya Tam Disk Erişimi verin: Sistem Ayarları › Gizlilik ve Güvenlik › Tam Disk Erişimi. " +
                          "O zamana kadar her izni Sistem Ayarları'nda açabilirsiniz.";
        }
        return report;
    }

    private static string FriendlyClient(string client)
    {
        if (client.StartsWith('/')) return Path.GetFileName(client.TrimEnd('/'));
        var parts = client.Split('.');
        return parts.Length >= 3 ? parts[^1] : client;
    }
}
