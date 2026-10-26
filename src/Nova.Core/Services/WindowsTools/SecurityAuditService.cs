using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;
using Nova.Core.Services.Platform;

namespace Nova.Core.Services.WindowsTools;

public enum AuditState
{
    Pass,
    Warning,
    Fail,
    Info
}

public sealed record AuditCheck(string Id, string Title, AuditState State, string Detail, string? Advice, string? FixTarget, int Weight);

public sealed class SecurityAuditReport
{
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.Now;
    public List<AuditCheck> Checks { get; init; } = [];

    public int FailCount => Checks.Count(c => c.State == AuditState.Fail);
    public int WarningCount => Checks.Count(c => c.State == AuditState.Warning);

    public int Score
    {
        get
        {
            var scored = Checks.Where(c => c.State != AuditState.Info).ToList();
            var total = scored.Sum(c => c.Weight);
            if (total == 0) return 100;
            var earned = scored.Sum(c => c.State switch { AuditState.Pass => c.Weight, AuditState.Warning => c.Weight / 2.0, _ => 0 });
            return (int)Math.Round(earned * 100 / total);
        }
    }
}

public sealed class SecurityAuditService
{
    private const string PowerShell = "powershell.exe";

    public SecurityAuditReport? LastReport { get; private set; }

    public async Task<SecurityAuditReport> RunAsync(CancellationToken ct = default)
    {
        var report = new SecurityAuditReport();
        if (!OperatingSystem.IsWindows()) return report;

        var av = AntivirusAsync(ct);
        var bitlocker = BitLockerAsync(ct);

        report.Checks.Add(await av);
        report.Checks.Add(Firewall());
        report.Checks.Add(SmartScreen());
        report.Checks.Add(Uac());
        report.Checks.Add(await bitlocker);
        report.Checks.Add(WindowsUpdate());
        report.Checks.Add(RemoteDesktop());
        report.Checks.Add(SecureBoot());
        report.Checks.Add(AutoLogon());

        LastReport = report;
        return report;
    }

    private static async Task<AuditCheck> AntivirusAsync(CancellationToken ct)
    {
        const string script =
            "$p=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,productState);" +
            "$d=$null; try{$d=Get-MpComputerStatus -ErrorAction Stop | Select-Object RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected}catch{};" +
            "[pscustomobject]@{products=$p;defender=$d} | ConvertTo-Json -Compress -Depth 4";
        var res = await ProcessRunner.RunAsync(PowerShell, ["-NoProfile", "-NonInteractive", "-Command", script], TimeSpan.FromSeconds(30), ct);

        const string title = "Antivirüs ve gerçek zamanlı koruma";
        const string fix = "windowsdefender://threat/";
        try
        {
            using var doc = JsonDocument.Parse(res.StdOut);
            var root = doc.RootElement;
            var active = new List<string>();
            if (root.TryGetProperty("products", out var products))
            {
                var items = products.ValueKind == JsonValueKind.Array ? products.EnumerateArray().ToList() : [products];
                foreach (var p in items)
                {
                    if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty("productState", out var st)) continue;
                    var state = (st.GetInt64() >> 8) & 0xFF;
                    if (state is 0x10 or 0x11 && p.TryGetProperty("displayName", out var n) && n.GetString() is { } name)
                        active.Add(name);
                }
            }

            JsonElement? defender = root.TryGetProperty("defender", out var d) && d.ValueKind == JsonValueKind.Object ? d : null;
            if (active.Count == 0)
                return new("antivirus", title, AuditState.Fail, "Gerçek zamanlı koruması açık bir antivirüs bulunamadı.",
                    "Windows Güvenliği'nden gerçek zamanlı korumayı açın.", fix, 25);

            var defenderOn = defender is { } def && def.TryGetProperty("RealTimeProtectionEnabled", out var rt) && rt.ValueKind == JsonValueKind.True;
            if (defenderOn && defender!.Value.TryGetProperty("AntivirusSignatureAge", out var age) && age.TryGetInt32(out var days) && days is > 7 and < 60000)
                return new("antivirus", title, AuditState.Warning, $"Microsoft Defender açık ama virüs tanımları {days} gündür güncellenmemiş.",
                    "Windows Güvenliği › Virüs ve tehdit koruması › Güncellemeleri denetle.", fix, 25);

            return new("antivirus", title, AuditState.Pass, "Etkin: " + string.Join(", ", active.Distinct()), null, null, 25);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            return new("antivirus", title, AuditState.Info, "Antivirüs durumu okunamadı.", null, fix, 25);
        }
    }

    [SupportedOSPlatform("windows")]
    private static object? Reg(string path, string name, RegistryHive hive = RegistryHive.LocalMachine)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(path);
            return key?.GetValue(name);
        }
        catch (Exception) { return null; }
    }

    [SupportedOSPlatform("windows")]
    private static AuditCheck Firewall()
    {
        const string title = "Windows Güvenlik Duvarı";
        const string fix = "windowsdefender://network/";
        const string baseKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
        var profiles = new (string Key, string Name)[] { ("DomainProfile", "Etki alanı"), ("StandardProfile", "Özel"), ("PublicProfile", "Genel") };

        var off = new List<string>();
        var known = 0;
        foreach (var (key, name) in profiles)
        {
            if (Reg(baseKey + key, "EnableFirewall") is not int v) continue;
            known++;
            if (v == 0) off.Add(name);
        }
        if (known == 0) return new("firewall", title, AuditState.Info, "Güvenlik duvarı durumu okunamadı.", null, fix, 15);
        if (off.Count > 0)
            return new("firewall", title, off.Contains("Genel") ? AuditState.Fail : AuditState.Warning,
                $"Kapalı profil: {string.Join(", ", off)}.", "Güvenlik duvarını tüm ağ profillerinde açın.", fix, 15);
        return new("firewall", title, AuditState.Pass, "Tüm ağ profillerinde açık.", null, null, 15);
    }

    [SupportedOSPlatform("windows")]
    private static AuditCheck SmartScreen()
    {
        const string title = "SmartScreen (tehlikeli uygulama ve dosya uyarısı)";
        const string fix = "windowsdefender://appbrowser/";
        var policy = Reg(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen");
        var setting = Reg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled") as string;

        if (policy is 0 || string.Equals(setting, "Off", StringComparison.OrdinalIgnoreCase))
            return new("smartscreen", title, AuditState.Warning, "SmartScreen kapalı; tanınmayan indirmeler için uyarı verilmiyor.",
                "Windows Güvenliği › Uygulama ve tarayıcı denetimi › İtibar tabanlı koruma.", fix, 10);
        return new("smartscreen", title, AuditState.Pass, "Açık.", null, null, 10);
    }

    [SupportedOSPlatform("windows")]
    private static AuditCheck Uac()
    {
        const string title = "Kullanıcı Hesabı Denetimi (UAC)";
        const string fix = "UserAccountControlSettings.exe";
        const string key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

        if (Reg(key, "EnableLUA") is 0)
            return new("uac", title, AuditState.Fail, "UAC tamamen kapalı; programlar sormadan yönetici yetkisi alabilir.", "UAC'yi açıp bilgisayarı yeniden başlatın.", fix, 15);
        if (Reg(key, "ConsentPromptBehaviorAdmin") is 0)
            return new("uac", title, AuditState.Warning, "UAC 'hiçbir zaman bildirme' düzeyinde.", "Kaydırıcıyı en az 'Yalnızca uygulamalar değişiklik yapmaya çalıştığında' düzeyine alın.", fix, 15);
        return new("uac", title, AuditState.Pass, "Açık.", null, null, 15);
    }

    [SupportedOSPlatform("windows")]
    private static AuditCheck RemoteDesktop()
    {
        const string title = "Uzak Masaüstü (RDP)";
        const string fix = "ms-settings:remotedesktop";
        if (Reg(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") is not 0)
            return new("rdp", title, AuditState.Pass, "Kapalı; dışarıdan masaüstü bağlantısı kabul edilmiyor.", null, null, 10);

        var nla = Reg(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
        return nla is 0
            ? new("rdp", title, AuditState.Fail, "RDP açık ve ağ düzeyinde kimlik doğrulama (NLA) kapalı.", "Kullanmıyorsanız kapatın; kullanıyorsanız NLA'yı zorunlu kılın.", fix, 10)
            : new("rdp", title, AuditState.Warning, "RDP açık. Saldırganların sık denediği bir giriş noktasıdır.", "Kullanmıyorsanız kapatın; internete doğrudan açmayın.", fix, 10);
    }

    [SupportedOSPlatform("windows")]
    private static AuditCheck SecureBoot()
    {
        const string title = "Güvenli Önyükleme (Secure Boot)";
        return Reg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") switch
        {
            1 => new("secureboot", title, AuditState.Pass, "Açık.", null, null, 8),
            0 => new("secureboot", title, AuditState.Warning, "Kapalı; önyükleme sırasında zararlı yazılım yüklenmesine karşı koruma yok.", "BIOS/UEFI ayarlarından açılır.", null, 8),
            _ => new("secureboot", title, AuditState.Info, "Bu cihazda desteklenmiyor veya okunamadı.", null, null, 8)
        };
    }

    [SupportedOSPlatform("windows")]
    private static AuditCheck AutoLogon()
    {
        const string title = "Otomatik oturum açma";
        return Reg(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon") as string == "1"
            ? new("autologon", title, AuditState.Warning, "Bilgisayar parola sorulmadan oturum açıyor.", "Cihaz çalınırsa verilerinize doğrudan erişilebilir.", "netplwiz.exe", 5)
            : new("autologon", title, AuditState.Pass, "Kapalı.", null, null, 5);
    }

    [SupportedOSPlatform("windows")]
    private static AuditCheck WindowsUpdate()
    {
        const string title = "Windows güncellemeleri";
        const string fix = "ms-settings:windowsupdate";

        if (Environment.OSVersion.Version.Build < 22000)
            return new("update", title, AuditState.Warning, "Windows 10 kullanıyorsunuz; ücretsiz güvenlik güncellemeleri sona erdi.", "Windows 11'e geçin veya genişletilmiş güvenlik güncellemesi (ESU) alın.", fix, 20);

        using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var reboot = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
        {
            if (reboot is not null)
                return new("update", title, AuditState.Warning, "Yüklenen güncellemelerin tamamlanması için yeniden başlatma bekleniyor.", "Bilgisayarı yeniden başlatın.", fix, 20);
        }

        var last = Reg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install", "LastSuccessTime") as string;
        if (DateTime.TryParse(last, out var when))
        {
            var days = (int)(DateTime.Now - when.ToLocalTime()).TotalDays;
            return days > 60
                ? new("update", title, AuditState.Warning, $"Son güncelleme {days} gün önce yüklenmiş.", "Windows Update'ten güncellemeleri denetleyin.", fix, 20)
                : new("update", title, AuditState.Pass, $"Güncel (son güncelleme {Math.Max(days, 0)} gün önce).", null, null, 20);
        }
        return new("update", title, AuditState.Info, "Son güncelleme zamanı okunamadı. Windows Update'ten elle denetleyin.", null, fix, 20);
    }

    private static async Task<AuditCheck> BitLockerAsync(CancellationToken ct)
    {
        const string title = "Disk şifreleme (BitLocker)";
        const string fix = "shell:::{D9EF8727-CAC2-4e60-809E-86F80A666C91}";
        const string script = "(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')";
        var res = await ProcessRunner.RunAsync(PowerShell, ["-NoProfile", "-NonInteractive", "-Command", script], TimeSpan.FromSeconds(20), ct);

        return res.StdOut.Trim() switch
        {
            "1" => new("bitlocker", title, AuditState.Pass, "Sistem sürücüsü şifreli.", null, null, 12),
            "2" => new("bitlocker", title, AuditState.Warning, "Sistem sürücüsü şifrelenmemiş; cihaz çalınırsa dosyalar okunabilir.", "Windows sürümünüz destekliyorsa BitLocker'ı açın.", fix, 12),
            _ => new("bitlocker", title, AuditState.Info, "Durum belirlenemedi (Windows sürümünüz BitLocker'ı desteklemiyor olabilir).", null, fix, 12)
        };
    }
}
