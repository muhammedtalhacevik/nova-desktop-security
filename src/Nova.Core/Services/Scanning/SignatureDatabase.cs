using System.Text;

namespace Nova.Core.Services.Scanning;

public sealed record BytePattern(string Name, byte[] Bytes, int SearchWindow);

public sealed class SignatureDatabase
{
    private const string FeedFile = "malwarebazaar.sig";
    private const string FeedCsvUrl = "https://bazaar.abuse.ch/export/csv/recent/";
    private const string FeedTxtUrl = "https://bazaar.abuse.ch/export/txt/sha256/recent/";

    private Dictionary<string, string> _sha256 = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string> _md5 = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<BytePattern> _patterns = [];
    private readonly object _gate = new();

    public SignatureDatabase()
    {
        _patterns.AddRange(BuiltInPatterns());
        Reload();
    }

    public int HashCount { get { lock (_gate) return _sha256.Count + _md5.Count; } }
    public int PatternCount => _patterns.Count;
    public IReadOnlyList<BytePattern> Patterns => _patterns;

    public string? MatchSha256(string? hash)
    {
        if (hash is null) return null;
        lock (_gate) return _sha256.GetValueOrDefault(hash);
    }

    public string? MatchMd5(string? hash)
    {
        if (hash is null) return null;
        lock (_gate) return _md5.GetValueOrDefault(hash);
    }

    public void Reload()
    {
        var sha = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var md5 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        using (var s = typeof(SignatureDatabase).Assembly.GetManifestResourceStream("Nova.Core.builtin-signatures.txt"))
        {
            if (s is not null)
            {
                using var reader = new StreamReader(s);
                ParseInto(reader, sha, md5);
            }
        }

        foreach (var file in Directory.EnumerateFiles(AppPaths.Signatures, "*.sig"))
        {
            try
            {
                using var reader = new StreamReader(file);
                ParseInto(reader, sha, md5);
            }
            catch (IOException) { }
        }

        lock (_gate)
        {
            _sha256 = sha;
            _md5 = md5;
        }
    }

    public void AddCustom(string sha256, string name)
    {
        var path = Path.Combine(AppPaths.Signatures, "custom.sig");
        File.AppendAllText(path, $"sha256:{sha256.ToLowerInvariant()}:{name}{Environment.NewLine}");
        lock (_gate) _sha256[sha256] = name;
    }

    internal static void ParseInto(TextReader reader, Dictionary<string, string> sha, Dictionary<string, string> md5)
    {
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            line = line.Trim();
            if (line.Length == 0 || line[0] == '#') continue;

            var parts = line.Split(':', 3);
            if (parts.Length >= 2 && parts[0].Equals("sha256", StringComparison.OrdinalIgnoreCase) && IsHex(parts[1], 64))
                sha[parts[1]] = parts.Length == 3 && parts[2].Length > 0 ? parts[2] : "Malware.Generic";
            else if (parts.Length >= 2 && parts[0].Equals("md5", StringComparison.OrdinalIgnoreCase) && IsHex(parts[1], 32))
                md5[parts[1]] = parts.Length == 3 && parts[2].Length > 0 ? parts[2] : "Malware.Generic";
            else if (IsHex(line, 64))
                sha[line] = "Malware.Generic";
        }
    }

    private static bool IsHex(string s, int len) => s.Length == len && s.All(Uri.IsHexDigit);

    public async Task<int> UpdateFromFeedAsync(HttpClient http, CancellationToken ct)
    {
        var feedPath = Path.Combine(AppPaths.Signatures, FeedFile);
        var existing = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(feedPath))
        {
            using var r = new StreamReader(feedPath);
            ParseInto(r, existing, new Dictionary<string, string>());
        }
        var before = existing.Count;

        string body;
        var csv = true;
        try
        {
            body = await http.GetStringAsync(FeedCsvUrl, ct);
        }
        catch (HttpRequestException)
        {
            csv = false;
            body = await http.GetStringAsync(FeedTxtUrl, ct);
        }

        using (var reader = new StringReader(body))
        {
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                if (line.Length == 0 || line[0] == '#') continue;
                if (csv)
                {
                    var cols = SplitCsv(line);
                    if (cols.Count < 9 || !IsHex(cols[1], 64)) continue;
                    var family = cols[8] is { Length: > 0 } f && f != "n/a" ? f : "Generic";
                    var type = cols[6] is { Length: > 0 } t && t != "unknown" ? t : "file";
                    existing[cols[1]] = $"Malware.{Sanitize(type)}.{Sanitize(family)}";
                }
                else if (IsHex(line.Trim(), 64))
                {
                    existing.TryAdd(line.Trim(), "Malware.Generic");
                }
            }
        }

        var sb = new StringBuilder();
        sb.AppendLine($"# MalwareBazaar feed (abuse.ch) - updated {DateTimeOffset.Now:O}");
        foreach (var (hash, name) in existing)
            sb.Append("sha256:").Append(hash.ToLowerInvariant()).Append(':').AppendLine(name);
        await File.WriteAllTextAsync(feedPath + ".tmp", sb.ToString(), ct);
        File.Move(feedPath + ".tmp", feedPath, true);

        Reload();
        return existing.Count - before;
    }

    private static string Sanitize(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-');
        return sb.ToString().Trim('-');
    }

    internal static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else quoted = !quoted;
            }
            else if (c == ',' && !quoted)
            {
                result.Add(sb.ToString().Trim());
                sb.Clear();
            }
            else sb.Append(c);
        }
        result.Add(sb.ToString().Trim());
        return result;
    }

    private static IEnumerable<BytePattern> BuiltInPatterns()
    {
        static byte[] R(string reversed) => Encoding.ASCII.GetBytes(new string(reversed.Reverse().ToArray()));

        yield return new BytePattern("EICAR-Test-File",
            R("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X"), 256);
        yield return new BytePattern("AMSI-Test-Sample",
            R("6831c4841ca0-0478-9334-b168-ec3c27e7 :elpmaS tseT ISMA"), 1024);
    }
}
