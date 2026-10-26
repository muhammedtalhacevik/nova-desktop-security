namespace Nova.Core.Models;

public sealed class QuarantineItem
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string OriginalPath { get; set; } = "";
    public string StoredFileName { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public ThreatSeverity Severity { get; set; }
    public string? Sha256 { get; set; }
    public long Size { get; set; }
    public DateTimeOffset QuarantinedAt { get; set; } = DateTimeOffset.Now;

    public string FileName => Path.GetFileName(OriginalPath);
}

public sealed class SecurityEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.Now;
    public EventCategory Category { get; set; }
    public ThreatSeverity Severity { get; set; }
    public string Title { get; set; } = "";
    public string Message { get; set; } = "";
    public bool IsRead { get; set; }
}

public sealed class AppSettings
{
    public bool RealTimeProtection { get; set; } = true;
    public bool AutoQuarantine { get; set; } = true;
    public bool NotificationsEnabled { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public bool StartWithSystem { get; set; }
    public bool UseSystemAntimalwareInterface { get; set; } = true;
    public bool ScanRunningProcesses { get; set; } = true;
    public bool ConnectToSiteDuringUrlCheck { get; set; } = true;
    public bool MonitorStartupChanges { get; set; } = true;
    public int MaxFileSizeMb { get; set; } = 150;
    public List<string> Exclusions { get; set; } = [];
    public List<string> AllowedHashes { get; set; } = [];
    public List<string> ExtraWatchedFolders { get; set; } = [];

    public bool ScheduledScanEnabled { get; set; }
    public ScheduleFrequency ScheduleFrequency { get; set; } = ScheduleFrequency.Daily;
    public DayOfWeek ScheduleDay { get; set; } = DayOfWeek.Monday;
    public int ScheduleMinutes { get; set; } = 12 * 60;
    public ScanType ScheduledScanType { get; set; } = ScanType.Quick;
    public DateTimeOffset? LastScheduledRun { get; set; }
    public bool UsbAutoScan { get; set; } = true;

    public string GoogleSafeBrowsingApiKey { get; set; } = "";
    public string VirusTotalApiKey { get; set; } = "";
    public string HibpApiKey { get; set; } = "";

    public DateTimeOffset? SignaturesUpdatedAt { get; set; }
    public DateTimeOffset? LastQuickScanAt { get; set; }
    public DateTimeOffset? LastFullScanAt { get; set; }
    public string InstallId { get; set; } = Convert.ToHexString(Guid.NewGuid().ToByteArray())[..8];
}
