namespace Nova.Core.Models;

public sealed class ThreatDetection
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string FilePath { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public string Engine { get; set; } = "";
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.High;
    public string Description { get; set; } = "";
    public string? Sha256 { get; set; }
    public long FileSize { get; set; }
    public DateTimeOffset DetectedAt { get; set; } = DateTimeOffset.Now;
    public ThreatAction Action { get; set; } = ThreatAction.None;
    public Guid? QuarantineId { get; set; }

    public string FileName => Path.GetFileName(FilePath);
}

public sealed class ScanSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public ScanType Type { get; set; }
    public ScanStatus Status { get; set; } = ScanStatus.Running;
    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset? FinishedAt { get; set; }
    public List<string> Targets { get; set; } = [];
    public long FilesScanned { get; set; }
    public long FilesSkipped { get; set; }
    public long BytesScanned { get; set; }
    public List<ThreatDetection> Threats { get; set; } = [];
    public string? Error { get; set; }

    public TimeSpan Duration => (FinishedAt ?? DateTimeOffset.Now) - StartedAt;
    public int ThreatCount => Threats.Count;
    public int UnresolvedThreatCount => Threats.Count(t => t.Action is ThreatAction.None or ThreatAction.Failed);
}

public sealed record ScanProgress(
    long FilesScanned,
    long FilesDiscovered,
    bool EnumerationComplete,
    int ThreatsFound,
    string CurrentFile,
    TimeSpan Elapsed,
    long BytesScanned)
{
    public double Percent => EnumerationComplete && FilesDiscovered > 0
        ? Math.Min(100.0, FilesScanned * 100.0 / FilesDiscovered)
        : 0;
}
