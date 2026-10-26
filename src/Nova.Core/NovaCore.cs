using Nova.Core.Models;
using Nova.Core.Services;
using Nova.Core.Services.Breach;
using Nova.Core.Services.Network;
using Nova.Core.Services.Platform;
using Nova.Core.Services.Privacy;
using Nova.Core.Services.Scanning;
using Nova.Core.Services.Web;
using Nova.Core.Services.WindowsTools;

namespace Nova.Core;

public sealed record ProtectionIssue(string Title, string Detail, ThreatSeverity Severity, string ActionKey);

public sealed record ProtectionStatus(ProtectionLevel Level, string Headline, string Summary, IReadOnlyList<ProtectionIssue> Issues);

public sealed class NovaCore : IDisposable
{
    public NovaCore()
    {
        Settings = new SettingsService();
        Events = new EventLogService();
        History = new ScanHistoryService();
        Quarantine = new QuarantineService(Settings, Events);
        Signatures = new SignatureDatabase();
        Amsi = new AmsiEngine();
        Scanner = new NovaScanner(Settings, History, Quarantine, Events,
            [new SignatureEngine(Signatures), new HeuristicEngine(), Amsi]);
        Startup = new StartupAppsService();
        Permissions = new PermissionsService();
        RealTime = new RealTimeProtectionService(Scanner, Quarantine, Settings, Events, History, Startup);
        Web = new WebSafetyService(Settings, Events);
        Network = new NetworkSecurityService(Events);
        Breach = new BreachCheckService(Settings, Events);
        Automation = new AutomationService(Settings, Events);
        Audit = new SecurityAuditService();
        Cleaner = new CleanerService();
        Updater = new SoftwareUpdaterService();
        Icons = new AppIconService();
    }

    public SettingsService Settings { get; }
    public EventLogService Events { get; }
    public ScanHistoryService History { get; }
    public QuarantineService Quarantine { get; }
    public SignatureDatabase Signatures { get; }
    public AmsiEngine Amsi { get; }
    public NovaScanner Scanner { get; }
    public StartupAppsService Startup { get; }
    public PermissionsService Permissions { get; }
    public RealTimeProtectionService RealTime { get; }
    public WebSafetyService Web { get; }
    public NetworkSecurityService Network { get; }
    public BreachCheckService Breach { get; }
    public AutomationService Automation { get; }
    public SecurityAuditService Audit { get; }
    public CleanerService Cleaner { get; }
    public SoftwareUpdaterService Updater { get; }
    public AppIconService Icons { get; }

    public static bool HasWindowsTools => OperatingSystem.IsWindows();

    public static string PlatformName =>
        OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsMacOS() ? "macOS" : "Linux";

    public void Start()
    {
        if (Settings.Current.RealTimeProtection) RealTime.Start();
        if (Events.Events.Count == 0)
            Events.Add(EventCategory.System, ThreatSeverity.Info, "Nova Desktop Security kuruldu", "Koruma etkin. İlk hızlı taramanızı başlatmanızı öneririz.");
        AutoStartService.Apply(Settings.Current.StartWithSystem);
        Automation.Start();
        if (HasWindowsTools) _ = Task.Run(async () => { await Task.Delay(TimeSpan.FromSeconds(8)); try { await Audit.RunAsync(); } catch (Exception) { } });
    }

    public async Task<int> UpdateSignaturesAsync(CancellationToken ct)
    {
        var added = await Signatures.UpdateFromFeedAsync(NovaHttp.Shared, ct);
        Settings.Update(s => s.SignaturesUpdatedAt = DateTimeOffset.Now);
        Events.Add(EventCategory.System, ThreatSeverity.Info, "Virüs imzaları güncellendi",
            $"{added:N0} yeni imza eklendi. Toplam {Signatures.HashCount:N0} imza.");
        return added;
    }

    public ProtectionStatus GetStatus()
    {
        var issues = new List<ProtectionIssue>();
        var s = Settings.Current;

        var unresolved = History.UnresolvedThreats;
        if (unresolved.Count > 0)
            issues.Add(new($"{unresolved.Count} tehdit işlem bekliyor", "Tespit edilen dosyalar hâlâ diskte. Karantinaya alın veya silin.", ThreatSeverity.Critical, "threats"));

        if (!RealTime.IsRunning)
            issues.Add(new("Gerçek zamanlı koruma kapalı", "Yeni indirilen dosyalar otomatik olarak taranmıyor.", ThreatSeverity.High, "realtime"));

        var last = new[] { s.LastQuickScanAt, s.LastFullScanAt }.Max();
        if (last is null)
            issues.Add(new("Henüz tarama yapılmadı", "Cihazınızı ilk kez taramak için hızlı tarama başlatın.", ThreatSeverity.Medium, "scan"));
        else if (DateTimeOffset.Now - last > TimeSpan.FromDays(7))
            issues.Add(new("Son tarama 7 günden eski", $"Son tarama: {last:dd.MM.yyyy}. Düzenli tarama önerilir.", ThreatSeverity.Medium, "scan"));

        if (s.SignaturesUpdatedAt is null || DateTimeOffset.Now - s.SignaturesUpdatedAt > TimeSpan.FromDays(3))
            issues.Add(new("Virüs imzaları güncel değil", "En yeni tehdit imzalarını indirmek için güncelleyin.", ThreatSeverity.Low, "signatures"));

        if (Audit.LastReport is { FailCount: > 0 } audit)
            issues.Add(new($"{audit.FailCount} güvenlik ayarı zayıf", "Güvenlik denetimi, Windows'ta düzeltilmesi gereken ayarlar buldu.", ThreatSeverity.High, "audit"));

        if (Network.LastReport is { } net && net.Checks.Any(c => c.State == CheckState.Fail))
            issues.Add(new("Ağ güvenliği riski", "Son ağ analizinde kritik bulgu var.", ThreatSeverity.High, "network"));

        var level = issues.Any(i => i.Severity >= ThreatSeverity.Critical) || issues.Count(i => i.Severity >= ThreatSeverity.High) >= 2
            ? ProtectionLevel.AtRisk
            : issues.Any(i => i.Severity >= ThreatSeverity.Medium) || issues.Any(i => i.Severity == ThreatSeverity.High)
                ? ProtectionLevel.Attention
                : ProtectionLevel.Protected;

        return level switch
        {
            ProtectionLevel.AtRisk => new(level, "Risk altındasınız", "Cihazınızda acil işlem gerektiren sorunlar var.", issues),
            ProtectionLevel.Attention => new(level, "Dikkat gerekiyor", "Korumanızı tamamlamak için birkaç öneri var.", issues),
            _ => new(level, "Korunuyorsunuz", "Nova cihazınızı ve verilerinizi izliyor.", issues)
        };
    }

    public void Dispose()
    {
        RealTime.Dispose();
        Automation.Dispose();
        Amsi.Dispose();
    }
}
