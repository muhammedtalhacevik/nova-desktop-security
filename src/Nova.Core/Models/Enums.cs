namespace Nova.Core.Models;

public enum ThreatSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum ScanType
{
    Quick,
    Full,
    Custom,
    RealTime
}

public enum ScanStatus
{
    Running,
    Completed,
    Cancelled,
    Failed
}

public enum ThreatAction
{
    None,
    Quarantined,
    Allowed,
    Deleted,
    Failed
}

public enum EventCategory
{
    System,
    Scan,
    RealTime,
    Web,
    Network,
    Breach,
    Privacy,
    Quarantine
}

public enum ScheduleFrequency
{
    Daily,
    Weekly
}

public enum ProtectionLevel
{
    Protected,
    Attention,
    AtRisk
}

public static class SeverityText
{
    public static string ToTurkish(this ThreatSeverity s) => s switch
    {
        ThreatSeverity.Critical => "Kritik",
        ThreatSeverity.High => "Yüksek",
        ThreatSeverity.Medium => "Orta",
        ThreatSeverity.Low => "Düşük",
        _ => "Bilgi"
    };

    public static string ToTurkish(this ScanType t) => t switch
    {
        ScanType.Quick => "Hızlı Tarama",
        ScanType.Full => "Tam Tarama",
        ScanType.Custom => "Özel Tarama",
        ScanType.RealTime => "Gerçek Zamanlı",
        _ => t.ToString()
    };

    public static string ToTurkish(this ScanStatus s) => s switch
    {
        ScanStatus.Running => "Sürüyor",
        ScanStatus.Completed => "Tamamlandı",
        ScanStatus.Cancelled => "İptal edildi",
        ScanStatus.Failed => "Başarısız",
        _ => s.ToString()
    };

    public static string ToTurkish(this ThreatAction a) => a switch
    {
        ThreatAction.Quarantined => "Karantinada",
        ThreatAction.Allowed => "İzin verildi",
        ThreatAction.Deleted => "Silindi",
        ThreatAction.Failed => "İşlem başarısız",
        _ => "İşlem bekliyor"
    };

    public static string ToTurkish(this EventCategory c) => c switch
    {
        EventCategory.Scan => "Tarama",
        EventCategory.RealTime => "Gerçek Zamanlı Koruma",
        EventCategory.Web => "Web Güvenliği",
        EventCategory.Network => "Ağ Güvenliği",
        EventCategory.Breach => "Veri İhlali",
        EventCategory.Privacy => "Gizlilik",
        EventCategory.Quarantine => "Karantina",
        _ => "Sistem"
    };
}
