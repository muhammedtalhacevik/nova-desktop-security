namespace Nova.Core.Models;

public enum UrlVerdict
{
    Safe,
    Suspicious,
    Dangerous,
    Unknown
}

public sealed record RiskSignal(string Title, string Detail, ThreatSeverity Severity);

public sealed record IntelResult(string Provider, bool Checked, bool Flagged, string Summary, int Malicious = 0, int Suspicious = 0);

public sealed class UrlCheckResult
{
    public string InputUrl { get; set; } = "";
    public string NormalizedUrl { get; set; } = "";
    public string Host { get; set; } = "";
    public string RegistrableDomain { get; set; } = "";
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.Now;
    public UrlVerdict Verdict { get; set; } = UrlVerdict.Unknown;
    public int RiskScore { get; set; }
    public List<RiskSignal> Signals { get; set; } = [];
    public List<IntelResult> Intel { get; set; } = [];
    public List<string> RedirectChain { get; set; } = [];
    public string? FinalUrl { get; set; }
    public int? HttpStatus { get; set; }
    public List<string> ResolvedIps { get; set; } = [];
    public bool? CertificateValid { get; set; }
    public string? CertificateIssuer { get; set; }
    public string? CertificateSubject { get; set; }
    public DateTimeOffset? CertificateExpires { get; set; }
    public DateTimeOffset? DomainRegisteredAt { get; set; }
    public string? Registrar { get; set; }
    public string? Error { get; set; }
}

public enum CheckState
{
    Pass,
    Warning,
    Fail,
    Info,
    Unavailable
}

public sealed record NetworkCheck(string Title, string Result, CheckState State, string? Advice = null);

public sealed class WifiInfo
{
    public string? Ssid { get; set; }
    public string? Bssid { get; set; }
    public string? Authentication { get; set; }
    public string? Cipher { get; set; }
    public int? SignalPercent { get; set; }
    public string? PhyType { get; set; }
    public int? Channel { get; set; }
    public bool SecurityEnabled { get; set; } = true;
    public bool IsOpen { get; set; }
    public bool IsWeak { get; set; }
    public string? Note { get; set; }
}

public sealed class NetworkAdapterInfo
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Type { get; set; } = "";
    public bool IsWireless { get; set; }
    public string Mac { get; set; } = "";
    public List<string> IPv4 { get; set; } = [];
    public List<string> IPv6 { get; set; } = [];
    public string? SubnetMask { get; set; }
    public List<string> Gateways { get; set; } = [];
    public List<string> DnsServers { get; set; } = [];
    public long SpeedMbps { get; set; }
}

public sealed class NetworkReport
{
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.Now;
    public NetworkAdapterInfo? Primary { get; set; }
    public List<NetworkAdapterInfo> Adapters { get; set; } = [];
    public WifiInfo? Wifi { get; set; }
    public string? PublicIp { get; set; }
    public string? Isp { get; set; }
    public string? Location { get; set; }
    public bool? FirewallEnabled { get; set; }
    public bool VpnActive { get; set; }
    public List<NetworkCheck> Checks { get; set; } = [];
    public int RiskCount => Checks.Count(c => c.State is CheckState.Fail or CheckState.Warning);
}

public sealed class BreachInfo
{
    public string Name { get; set; } = "";
    public string? Domain { get; set; }
    public DateTimeOffset? BreachDate { get; set; }
    public long? Records { get; set; }
    public List<string> DataClasses { get; set; } = [];
    public string? Description { get; set; }
    public bool Verified { get; set; }
    public string? PasswordRisk { get; set; }
}

public sealed class BreachCheckResult
{
    public string Email { get; set; } = "";
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.Now;
    public string Provider { get; set; } = "";
    public List<BreachInfo> Breaches { get; set; } = [];
    public string? Error { get; set; }
    public bool Found => Breaches.Count > 0;
}

public sealed class StartupItem
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public string? ExecutablePath { get; set; }
    public string Location { get; set; } = "";
    public string? Publisher { get; set; }
    public bool? IsSigned { get; set; }
    public bool Enabled { get; set; } = true;
    public bool CanToggle { get; set; }
    public bool RequiresAdmin { get; set; }
    public bool FileExists { get; set; } = true;
    public List<string> Warnings { get; set; } = [];

    public string? SourceKey { get; set; }
    public string? SourceValue { get; set; }
}

public sealed class PermissionApp
{
    public string AppName { get; set; } = "";
    public string? AppPath { get; set; }
    public bool Allowed { get; set; }
    public DateTimeOffset? LastUsed { get; set; }
    public bool InUse { get; set; }
}

public sealed class PermissionGroup
{
    public string Key { get; set; } = "";
    public string Title { get; set; } = "";
    public string Icon { get; set; } = "";
    public bool? GloballyAllowed { get; set; }
    public string? SettingsUri { get; set; }
    public List<PermissionApp> Apps { get; set; } = [];
}

public sealed class PermissionReport
{
    public List<PermissionGroup> Groups { get; set; } = [];
    public string? Note { get; set; }
    public bool Limited { get; set; }
}
