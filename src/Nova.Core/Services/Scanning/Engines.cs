using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Nova.Core.Models;

namespace Nova.Core.Services.Scanning;

public interface IScanEngine
{
    string Name { get; }
    bool IsAvailable { get; }

    bool WantsFullContent(string extension);

    ThreatDetection? Scan(FileSample sample);
}

public sealed class SignatureEngine(SignatureDatabase db) : IScanEngine
{
    public string Name => "Nova İmza Motoru";
    public bool IsAvailable => true;
    public bool WantsFullContent(string extension) => false;

    public ThreatDetection? Scan(FileSample sample)
    {
        var name = db.MatchSha256(sample.Sha256) ?? db.MatchMd5(sample.Md5);
        if (name is not null)
            return Detection(sample, name, "Dosya özeti bilinen bir zararlı yazılım imzasıyla eşleşti.");

        foreach (var p in db.Patterns)
        {
            var window = sample.Head.AsSpan(0, Math.Min(sample.Head.Length, p.SearchWindow));
            if (window.IndexOf(p.Bytes) >= 0)
                return Detection(sample, p.Name, "Dosya içeriği bilinen bir zararlı içerik imzası barındırıyor.");
        }
        return null;
    }

    private ThreatDetection Detection(FileSample s, string threat, string description) => new()
    {
        FilePath = s.Path,
        ThreatName = threat,
        Engine = Name,
        Severity = threat.StartsWith("EICAR", StringComparison.OrdinalIgnoreCase) || threat.StartsWith("AMSI-Test", StringComparison.OrdinalIgnoreCase)
            ? ThreatSeverity.Medium
            : ThreatSeverity.Critical,
        Description = description,
        Sha256 = s.Sha256,
        FileSize = s.Size
    };
}

public sealed class HeuristicEngine : IScanEngine
{
    private sealed record Rule(string Name, int Score, Regex Pattern);

    private const int ReportThreshold = 4;
    private const int HighThreshold = 6;

    private static readonly RegexOptions Opt = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    private static readonly Rule[] ScriptRules =
    [
        new("Heur.Script.EncodedPowerShell", 3, new Regex(@"powershell(\.exe)?[^\r\n]{0,80}\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}", Opt)),
        new("Heur.Script.Base64Exec", 4, new Regex(@"FromBase64String[\s\S]{0,400}(IEX|Invoke-Expression|\.Invoke\(|Reflection\.Assembly\]::Load)", Opt)),
        new("Heur.Script.DownloadExec", 3, new Regex(@"(DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|iwr\s|Net\.WebClient|Start-BitsTransfer)[\s\S]{0,300}(IEX|Invoke-Expression|Start-Process|\.Invoke\()", Opt)),
        new("Heur.Script.PipeToShell", 4, new Regex(@"(curl|wget)\s[^\r\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b", Opt)),
        new("Heur.Script.Base64Shell", 4, new Regex(@"base64\s+(-d|--decode|-D)[^\r\n]{0,80}\|\s*(ba|z)?sh\b", Opt)),
        new("Heur.Script.HiddenWindow", 1, new Regex(@"-(w|windowstyle)\s+(hidden|1)\b", Opt)),
        new("Heur.Script.ExecutionPolicyBypass", 1, new Regex(@"-(ep|executionpolicy)\s+bypass", Opt)),
        new("Heur.Script.DefenderTamper", 5, new Regex(@"(Set-MpPreference\s+[^\r\n]{0,60}-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection)|Add-MpPreference\s+[^\r\n]{0,20}-Exclusion(Path|Process|Extension))", Opt)),
        new("Heur.Ransom.ShadowCopyDelete", 6, new Regex(@"(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog|bcdedit[^\r\n]{0,40}recoveryenabled\s+no)", Opt)),
        new("Heur.Script.CertutilDownload", 3, new Regex(@"certutil(\.exe)?\s+[^\r\n]{0,40}(-urlcache|-decode|-decodehex)", Opt)),
        new("Heur.Script.BitsadminTransfer", 2, new Regex(@"bitsadmin(\.exe)?\s+/transfer", Opt)),
        new("Heur.Script.MshtaRemote", 3, new Regex(@"mshta(\.exe)?\s+[""']?(https?:|vbscript:|javascript:)", Opt)),
        new("Heur.Script.WScriptShellRun", 2, new Regex(@"WScript\.Shell[\s\S]{0,300}\.(Run|Exec)\s*\(", Opt)),
        new("Heur.Script.RemoteUrl", 1, new Regex(@"https?://(\d{1,3}\.){3}\d{1,3}[:/]", Opt)),
        new("Heur.Script.RunKeyPersistence", 2, new Regex(@"(reg(\.exe)?\s+add\s+[^\r\n]{0,40}\\CurrentVersion\\Run|New-ItemProperty[^\r\n]{0,80}\\CurrentVersion\\Run)", Opt)),
        new("Heur.Script.QuarantineStrip", 2, new Regex(@"xattr\s+(-[a-z]*\s+)*-d\s+com\.apple\.quarantine", Opt)),
        new("Heur.Script.OsascriptShell", 2, new Regex(@"osascript[^\r\n]{0,80}do shell script", Opt)),
        new("Heur.Script.LaunchAgentPersist", 2, new Regex(@"Library/Launch(Agents|Daemons)/[^\r\n]{0,80}\.plist[\s\S]{0,300}launchctl\s+(load|bootstrap)", Opt)),
        new("Heur.Script.ChmodExecTmp", 2, new Regex(@"chmod\s+\+?[0-7x]+\s+/(tmp|private/tmp|var/tmp)/", Opt)),
        new("Heur.Script.AmsiBypass", 6, new Regex(@"(AmsiUtils|amsiInitFailed|AmsiScanBuffer)", Opt)),
    ];

    private static readonly Regex LnkPayload = new(@"(powershell|cmd(\.exe)?\s*/c|mshta|wscript|cscript|rundll32)[\s\S]{0,400}(https?:|-enc|FromBase64)", Opt);

    public string Name => "Nova Sezgisel Analiz";
    public bool IsAvailable => true;
    public bool WantsFullContent(string extension) => false;

    public ThreatDetection? Scan(FileSample s)
    {
        var name = s.FileName;

        if (name.Contains('‮'))
            return Hit(s, "Heur.FileName.RTLO", ThreatSeverity.High, "Dosya adı, gerçek uzantısını gizlemek için sağdan-sola karakteri içeriyor.");

        var outer = s.Extension;
        if (FileTypes.Executable.Contains(outer) || outer is ".bat" or ".cmd" or ".vbs" or ".js" or ".hta" or ".lnk" or ".ps1" or ".scr" or ".com" or ".pif")
        {
            var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(name).TrimEnd());
            if (inner.Length > 1 && FileTypes.Decoy.Contains(inner))
                return Hit(s, "Heur.FileName.DoubleExtension", ThreatSeverity.High,
                    $"Dosya '{inner}' gibi görünüyor ancak gerçekte '{outer}' çalıştırılabilir dosyası.");
            if (Regex.IsMatch(name, @"\s{6,}\.\w+$"))
                return Hit(s, "Heur.FileName.PaddedExtension", ThreatSeverity.High, "Dosya adı, uzantıyı gizlemek için çok sayıda boşluk içeriyor.");
        }

        if (FileTypes.Decoy.Contains(outer) && outer is not (".zip" or ".rar") && LooksExecutable(s.Head))
            return Hit(s, "Heur.Masquerade.Executable", ThreatSeverity.High,
                $"Dosya '{outer}' uzantısına sahip ancak içeriği çalıştırılabilir program (PE/Mach-O/ELF).");

        if (outer == ".lnk" && s.Head.Length > 0)
        {
            var text = Encoding.Unicode.GetString(s.Head) + Encoding.ASCII.GetString(s.Head);
            if (LnkPayload.IsMatch(text))
                return Hit(s, "Heur.Shortcut.Dropper", ThreatSeverity.High, "Kısayol, uzaktan kod indirip çalıştıran bir komut içeriyor.");
        }

        if (FileTypes.Script.Contains(outer) || (outer.Length == 0 && s.Head.Length > 2 && s.Head[0] == '#' && s.Head[1] == '!'))
        {
            var text = DecodeText(s.Head);
            var score = 0;
            Rule? strongest = null;
            foreach (var rule in ScriptRules)
            {
                if (!rule.Pattern.IsMatch(text)) continue;
                score += rule.Score;
                if (strongest is null || rule.Score > strongest.Score) strongest = rule;
            }
            if (score >= ReportThreshold && strongest is not null)
                return Hit(s, strongest.Name, score >= HighThreshold ? ThreatSeverity.High : ThreatSeverity.Medium,
                    $"Betik, zararlı yazılımlarda sık görülen davranış kalıpları içeriyor (risk puanı {score}).");
        }

        return null;
    }

    internal static bool LooksExecutable(ReadOnlySpan<byte> head)
    {
        if (head.Length < 64) return false;
        if (head[0] == 'M' && head[1] == 'Z')
        {
            var lfanew = BitConverter.ToInt32(head.Slice(0x3C, 4));
            return lfanew > 0 && lfanew + 4 <= head.Length && head[lfanew] == 'P' && head[lfanew + 1] == 'E' && head[lfanew + 2] == 0 && head[lfanew + 3] == 0;
        }
        var magic = BitConverter.ToUInt32(head[..4]);
        return magic is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE or 0xBEBAFECA
               || (head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F');
    }

    private static string DecodeText(byte[] head)
    {
        if (head.Length >= 2 && head[0] == 0xFF && head[1] == 0xFE) return Encoding.Unicode.GetString(head, 2, head.Length - 2);
        if (head.Length >= 2 && head[0] == 0xFE && head[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(head, 2, head.Length - 2);
        return Encoding.UTF8.GetString(head).Replace("^", "").Replace("`", "");
    }

    private ThreatDetection Hit(FileSample s, string threat, ThreatSeverity severity, string description) => new()
    {
        FilePath = s.Path,
        ThreatName = threat,
        Engine = Name,
        Severity = severity,
        Description = description,
        Sha256 = s.Sha256,
        FileSize = s.Size
    };
}

public sealed class AmsiEngine : IScanEngine, IDisposable
{
    private const int AmsiResultDetected = 32768;
    private readonly object _gate = new();
    private IntPtr _context;
    private bool _initTried;

    public string Name => "Windows AMSI (sistem antivirüs motoru)";

    public bool IsAvailable
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            EnsureInit();
            return _context != IntPtr.Zero;
        }
    }

    public bool WantsFullContent(string extension) => FileTypes.IsRisky(extension);

    public ThreatDetection? Scan(FileSample s)
    {
        if (!OperatingSystem.IsWindows() || !FileTypes.IsRisky(s.Extension) || !s.FullyRead || s.Size == 0) return null;
        EnsureInit();
        if (_context == IntPtr.Zero) return null;

        int result;
        int hr;
        lock (_gate)
            hr = AmsiScanBuffer(_context, s.Head, (uint)s.Head.Length, s.Path, IntPtr.Zero, out result);

        if (hr != 0 || result < AmsiResultDetected) return null;
        return new ThreatDetection
        {
            FilePath = s.Path,
            ThreatName = "AMSI.Detected.Malware",
            Engine = Name,
            Severity = ThreatSeverity.High,
            Description = "Sistemin kötü amaçlı yazılım motoru bu içeriği zararlı olarak sınıflandırdı.",
            Sha256 = s.Sha256,
            FileSize = s.Size
        };
    }

    private void EnsureInit()
    {
        if (_initTried) return;
        lock (_gate)
        {
            if (_initTried) return;
            _initTried = true;
            try
            {
                if (AmsiInitialize("NovaDesktopSecurity", out var ctx) == 0) _context = ctx;
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_context != IntPtr.Zero)
            {
                try { AmsiUninitialize(_context); } catch { }
                _context = IntPtr.Zero;
            }
        }
    }

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
}
