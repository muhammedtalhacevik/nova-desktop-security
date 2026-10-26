using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Nova.Core.Models;
using Nova.Core.Storage;

namespace Nova.Core.Services.Web;

public sealed class WebSafetyService
{
    private const string OpenPhishFeed = "https://openphish.com/feed.txt";
    private static readonly TimeSpan FeedMaxAge = TimeSpan.FromHours(6);

    private readonly SettingsService _settings;
    private readonly EventLogService _events;
    private readonly JsonStore<List<UrlCheckResult>> _historyStore = new("url-history.json");
    private readonly List<UrlCheckResult> _history;
    private readonly SemaphoreSlim _feedLock = new(1, 1);
    private HashSet<string>? _phishUrls;
    private HashSet<string>? _phishHosts;
    private DateTime _feedLoadedAt;

    public WebSafetyService(SettingsService settings, EventLogService events)
    {
        _settings = settings;
        _events = events;
        _history = _historyStore.Load();
    }

    public IReadOnlyList<UrlCheckResult> History
    {
        get { lock (_history) return _history.OrderByDescending(h => h.CheckedAt).ToList(); }
    }

    public void ClearHistory()
    {
        lock (_history)
        {
            _history.Clear();
            _historyStore.Save(_history);
        }
    }

    public async Task<UrlCheckResult> CheckAsync(string input, CancellationToken ct)
    {
        var result = new UrlCheckResult { InputUrl = input.Trim() };
        if (!UrlAnalyzer.TryNormalize(input, out var n, out var error) || n is null)
        {
            result.Error = error;
            result.Verdict = UrlVerdict.Unknown;
            return result;
        }

        result.NormalizedUrl = n.Uri.AbsoluteUri;
        result.Host = n.AsciiHost;
        result.RegistrableDomain = n.RegistrableDomain;
        result.Signals.AddRange(UrlAnalyzer.Analyze(n));

        var dnsTask = ResolveAsync(n, result, ct);
        var probeTask = _settings.Current.ConnectToSiteDuringUrlCheck ? ProbeAsync(n.Uri, result, ct) : Task.CompletedTask;
        var rdapTask = n.IsIpLiteral ? Task.CompletedTask : RdapAsync(n.RegistrableDomain, result, ct);

        await Task.WhenAll(dnsTask, probeTask, rdapTask);

        var urlsToCheck = new List<string> { n.Uri.AbsoluteUri };
        if (result.FinalUrl is { } final && UrlAnalyzer.TryNormalize(final, out var fn, out _) && fn is not null
            && !fn.RegistrableDomain.Equals(n.RegistrableDomain, StringComparison.OrdinalIgnoreCase))
        {
            urlsToCheck.Add(fn.Uri.AbsoluteUri);
            foreach (var s in UrlAnalyzer.Analyze(fn).Where(s => s.Severity >= ThreatSeverity.Low))
                result.Signals.Add(s with { Title = "Yönlendirme hedefi: " + s.Title });
        }

        var intelRaw = await Task.WhenAll(
            SafeBrowsingAsync(urlsToCheck, ct),
            VirusTotalAsync(n.Uri.AbsoluteUri, ct),
            OpenPhishAsync(urlsToCheck, ct));
        var intel = intelRaw.OfType<IntelResult>().ToArray();
        result.Intel.AddRange(intel);
        foreach (var vt in intel.Where(i => i.Checked && !i.Flagged && (i.Malicious > 0 || i.Suspicious > 0)))
            result.Signals.Add(new($"{vt.Provider}: {vt.Malicious} motor zararlı, {vt.Suspicious} motor şüpheli buldu",
                "Tek bir motorun tespiti yanlış alarm olabilir; yine de adresi açmadan önce dikkatli olun.",
                vt.Malicious > 0 ? ThreatSeverity.Medium : ThreatSeverity.Low));

        if (result.ResolvedIps.Count == 0 && result.HttpStatus is null)
            result.Signals.Add(new("Alan adı çözümlenemedi", "Bu alan adı için DNS kaydı bulunamadı; site kapatılmış veya hiç var olmamış olabilir.", ThreatSeverity.Medium));

        if (result.DomainRegisteredAt is { } reg)
        {
            var age = DateTimeOffset.UtcNow - reg;
            if (age.TotalDays < 30)
                result.Signals.Add(new("Çok yeni alan adı", $"Alan adı {Math.Max(0, (int)age.TotalDays)} gün önce kaydedilmiş. Oltalama siteleri genellikle yeni kayıtlıdır.", ThreatSeverity.High));
            else if (age.TotalDays < 180)
                result.Signals.Add(new("Yeni alan adı", $"Alan adı {(int)age.TotalDays} gün önce kaydedilmiş.", ThreatSeverity.Low));
        }

        if (result.CertificateValid == false)
            result.Signals.Add(new("Geçersiz SSL sertifikası", "Sitenin güvenlik sertifikası doğrulanamadı; bağlantı taklit ediliyor olabilir.", ThreatSeverity.High));
        else if (result.CertificateExpires is { } exp && exp < DateTimeOffset.Now.AddDays(7) && exp > DateTimeOffset.Now)
            result.Signals.Add(new("Sertifika süresi doluyor", $"Sertifika {exp:dd.MM.yyyy} tarihinde sona eriyor.", ThreatSeverity.Low));

        var flagged = result.Intel.Any(i => i.Flagged);
        result.RiskScore = flagged ? Math.Max(90, UrlAnalyzer.Score(result.Signals)) : UrlAnalyzer.Score(result.Signals);
        result.Verdict = flagged || result.RiskScore >= 60 ? UrlVerdict.Dangerous
            : result.RiskScore >= 25 ? UrlVerdict.Suspicious
            : UrlVerdict.Safe;

        lock (_history)
        {
            _history.RemoveAll(h => h.NormalizedUrl == result.NormalizedUrl);
            _history.Add(result);
            if (_history.Count > 50) _history.RemoveAt(0);
            _historyStore.Save(_history);
        }

        if (result.Verdict != UrlVerdict.Safe)
            _events.Add(EventCategory.Web,
                result.Verdict == UrlVerdict.Dangerous ? ThreatSeverity.High : ThreatSeverity.Medium,
                result.Verdict == UrlVerdict.Dangerous ? "Tehlikeli web sitesi tespit edildi" : "Şüpheli web sitesi",
                $"{result.Host} — risk puanı {result.RiskScore}/100");

        return result;
    }

    private static async Task ResolveAsync(UrlAnalyzer.Normalized n, UrlCheckResult result, CancellationToken ct)
    {
        try
        {
            var addresses = n.IsIpLiteral
                ? [IPAddress.Parse(n.AsciiHost.Trim('[', ']'))]
                : await Dns.GetHostAddressesAsync(n.AsciiHost, ct).WaitAsync(TimeSpan.FromSeconds(6), ct);
            lock (result.ResolvedIps)
                result.ResolvedIps.AddRange(addresses.Select(a => a.ToString()).Distinct().Take(6));
        }
        catch (Exception) { }
    }

    private async Task ProbeAsync(Uri start, UrlCheckResult result, CancellationToken ct)
    {
        X509Certificate2? cert = null;
        SslPolicyErrors certErrors = SslPolicyErrors.None;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(8),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, c, _, errors) =>
                {
                    if (c is not null && cert is null)
                    {
                        cert = new X509Certificate2(c);
                        certErrors = errors;
                    }
                    return true;
                }
            }
        };
        using var http = NovaHttp.Create(TimeSpan.FromSeconds(12), handler);

        var url = start;
        result.RedirectChain.Add(url.AbsoluteUri);
        try
        {
            for (var hop = 0; hop < 8; hop++)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
                using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                result.HttpStatus = (int)resp.StatusCode;

                if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
                {
                    url = loc.IsAbsoluteUri ? loc : new Uri(url, loc);
                    if (url.Scheme != Uri.UriSchemeHttp && url.Scheme != Uri.UriSchemeHttps) break;
                    result.RedirectChain.Add(url.AbsoluteUri);
                    continue;
                }
                break;
            }
            result.FinalUrl = url.AbsoluteUri;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            if (ct.IsCancellationRequested) throw;
            result.Signals.Add(new("Siteye bağlanılamadı", Short(ex), ThreatSeverity.Info));
        }

        if (start.Scheme == Uri.UriSchemeHttp && result.FinalUrl?.StartsWith("https://", StringComparison.OrdinalIgnoreCase) == true)
            result.Signals.RemoveAll(s => s.Title.StartsWith("Şifrelenmemiş", StringComparison.Ordinal));

        if (cert is not null)
        {
            result.CertificateValid = certErrors == SslPolicyErrors.None;
            result.CertificateIssuer = cert.GetNameInfo(X509NameType.SimpleName, true);
            result.CertificateSubject = cert.GetNameInfo(X509NameType.DnsName, false);
            result.CertificateExpires = cert.NotAfter;
            cert.Dispose();
        }

        if (result.RedirectChain.Count > 3)
            result.Signals.Add(new("Çok sayıda yönlendirme", $"Bağlantı {result.RedirectChain.Count - 1} kez yönlendiriliyor.", ThreatSeverity.Low));
    }

    private static async Task RdapAsync(string domain, UrlCheckResult result, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            using var resp = await NovaHttp.Shared.GetAsync($"https://rdap.org/domain/{Uri.EscapeDataString(domain)}", cts.Token);
            if (!resp.IsSuccessStatusCode) return;
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(cts.Token));
            var root = doc.RootElement;
            if (root.TryGetProperty("events", out var events))
            {
                foreach (var ev in events.EnumerateArray())
                {
                    if (ev.TryGetProperty("eventAction", out var a) && a.GetString() == "registration"
                        && ev.TryGetProperty("eventDate", out var d) && DateTimeOffset.TryParse(d.GetString(), out var date))
                        result.DomainRegisteredAt = date;
                }
            }
            if (root.TryGetProperty("entities", out var entities))
            {
                foreach (var e in entities.EnumerateArray())
                {
                    if (!e.TryGetProperty("roles", out var roles) || !roles.EnumerateArray().Any(r => r.GetString() == "registrar")) continue;
                    if (e.TryGetProperty("vcardArray", out var vcard) && vcard.GetArrayLength() > 1)
                        foreach (var field in vcard[1].EnumerateArray())
                            if (field.GetArrayLength() >= 4 && field[0].GetString() == "fn")
                                result.Registrar = field[3].GetString();
                }
            }
        }
        catch (Exception) { /* RDAP is best-effort; not every TLD offers it */ }
    }

    private async Task<IntelResult?> SafeBrowsingAsync(IReadOnlyList<string> urls, CancellationToken ct)
    {
        const string provider = "Google Safe Browsing";
        var key = _settings.Current.GoogleSafeBrowsingApiKey.Trim();
        if (key.Length == 0) return null;

        var body = new
        {
            client = new { clientId = "nova-desktop-security", clientVersion = "1.0.0" },
            threatInfo = new
            {
                threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION" },
                platformTypes = new[] { "ANY_PLATFORM" },
                threatEntryTypes = new[] { "URL" },
                threatEntries = urls.Select(u => new { url = u }).ToArray()
            }
        };
        try
        {
            using var resp = await NovaHttp.Shared.PostAsJsonAsync($"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={Uri.EscapeDataString(key)}", body, ct);
            var text = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode) return new(provider, false, false, $"Servis hatası ({(int)resp.StatusCode})");
            using var doc = JsonDocument.Parse(text.Length == 0 ? "{}" : text);
            if (doc.RootElement.TryGetProperty("matches", out var matches) && matches.GetArrayLength() > 0)
            {
                var types = matches.EnumerateArray()
                    .Select(m => m.TryGetProperty("threatType", out var t) ? TranslateThreatType(t.GetString()) : "Tehdit")
                    .Distinct();
                return new(provider, true, true, "Listede: " + string.Join(", ", types));
            }
            return new(provider, true, false, "Bilinen tehdit listelerinde bulunmadı");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            if (ct.IsCancellationRequested) throw;
            return new(provider, false, false, "Servise ulaşılamadı");
        }
    }

    private async Task<IntelResult> VirusTotalAsync(string url, CancellationToken ct)
    {
        const string provider = "VirusTotal";
        var key = _settings.Current.VirusTotalApiKey.Trim();
        if (key.Length == 0) key = BuiltInKeys.VirusTotal;
        if (key.Length == 0) return null;

        var id = Convert.ToBase64String(Encoding.UTF8.GetBytes(url)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        try
        {
            using var resp = await VtGetAsync($"https://www.virustotal.com/api/v3/urls/{id}", key, ct);
            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
                return new(provider, false, false, "Hız sınırına ulaşıldı (dakikada 4 sorgu); biraz sonra tekrar deneyin");
            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
                return new(provider, false, false, "API anahtarı geçersiz");

            if (resp.StatusCode == HttpStatusCode.NotFound)
                return await VtSubmitAndWaitAsync(url, key, ct);
            if (!resp.IsSuccessStatusCode) return new(provider, false, false, $"Servis hatası ({(int)resp.StatusCode})");

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
            return VtResult(stats);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            if (ct.IsCancellationRequested) throw;
            return new(provider, false, false, "Servise ulaşılamadı");
        }
    }

    private static async Task<HttpResponseMessage> VtGetAsync(string url, string key, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Add("x-apikey", key);
        return await NovaHttp.Shared.SendAsync(req, ct);
    }

    private static async Task<IntelResult> VtSubmitAndWaitAsync(string url, string key, CancellationToken ct)
    {
        const string provider = "VirusTotal";
        using var submit = new HttpRequestMessage(HttpMethod.Post, "https://www.virustotal.com/api/v3/urls")
        {
            Content = new FormUrlEncodedContent([new KeyValuePair<string, string>("url", url)])
        };
        submit.Headers.Add("x-apikey", key);
        using var submitted = await NovaHttp.Shared.SendAsync(submit, ct);
        if (submitted.StatusCode == HttpStatusCode.TooManyRequests)
            return new(provider, false, false, "Hız sınırına ulaşıldı (dakikada 4 sorgu); biraz sonra tekrar deneyin");
        if (!submitted.IsSuccessStatusCode) return new(provider, false, false, $"Servis hatası ({(int)submitted.StatusCode})");

        using var sub = JsonDocument.Parse(await submitted.Content.ReadAsStringAsync(ct));
        var analysisId = sub.RootElement.GetProperty("data").GetProperty("id").GetString();

        for (var attempt = 0; attempt < 5; attempt++)
        {
            await Task.Delay(TimeSpan.FromSeconds(3), ct);
            using var poll = await VtGetAsync($"https://www.virustotal.com/api/v3/analyses/{analysisId}", key, ct);
            if (!poll.IsSuccessStatusCode) continue;
            using var doc = JsonDocument.Parse(await poll.Content.ReadAsStringAsync(ct));
            var attrs = doc.RootElement.GetProperty("data").GetProperty("attributes");
            if (attrs.TryGetProperty("status", out var status) && status.GetString() == "completed")
                return VtResult(attrs.GetProperty("stats"));
        }
        return new(provider, true, false, "Adres analiz için gönderildi; sonuç birkaç dakika içinde hazır olur");
    }

    private static IntelResult VtResult(JsonElement stats)
    {
        int Get(string p) => stats.TryGetProperty(p, out var v) && v.TryGetInt32(out var n) ? n : 0;
        var malicious = Get("malicious");
        var suspicious = Get("suspicious");
        var total = malicious + suspicious + Get("harmless") + Get("undetected");
        var flagged = malicious >= 2 || malicious + suspicious >= 3;
        return new("VirusTotal", true, flagged, $"{malicious} zararlı, {suspicious} şüpheli / {total} motor", malicious, suspicious);
    }

    private async Task<IntelResult> OpenPhishAsync(IReadOnlyList<string> urls, CancellationToken ct)
    {
        const string provider = "OpenPhish oltalama akışı";
        try
        {
            await EnsureFeedAsync(ct);
            if (_phishUrls is null || _phishHosts is null) return new(provider, false, false, "Akış indirilemedi");

            foreach (var u in urls)
            {
                var trimmed = u.TrimEnd('/');
                var host = new Uri(u).Host;
                if (_phishUrls.Contains(trimmed) || _phishUrls.Any(p => trimmed.StartsWith(p, StringComparison.OrdinalIgnoreCase) && p.Length > 20))
                    return new(provider, true, true, "Bu adres aktif oltalama listesinde");
                if (_phishHosts.Contains(host) && !UrlAnalyzer.IsShortener(UrlAnalyzer.RegistrableDomain(host)))
                    return new(provider, true, true, "Bu alan adında aktif oltalama sayfası raporlandı");
            }
            return new(provider, true, false, $"{_phishUrls.Count:N0} aktif oltalama adresi arasında bulunmadı");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            if (ct.IsCancellationRequested) throw;
            return new(provider, false, false, "Akışa ulaşılamadı");
        }
    }

    private async Task EnsureFeedAsync(CancellationToken ct)
    {
        if (_phishUrls is not null && DateTime.UtcNow - _feedLoadedAt < FeedMaxAge) return;
        await _feedLock.WaitAsync(ct);
        try
        {
            if (_phishUrls is not null && DateTime.UtcNow - _feedLoadedAt < FeedMaxAge) return;
            var cache = Path.Combine(AppPaths.Cache, "openphish.txt");
            string text;
            if (File.Exists(cache) && DateTime.UtcNow - File.GetLastWriteTimeUtc(cache) < FeedMaxAge)
                text = await File.ReadAllTextAsync(cache, ct);
            else
            {
                try
                {
                    text = await NovaHttp.Shared.GetStringAsync(OpenPhishFeed, ct);
                    await File.WriteAllTextAsync(cache, text, ct);
                }
                catch when (File.Exists(cache))
                {
                    text = await File.ReadAllTextAsync(cache, ct);
                }
            }

            var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                urls.Add(line.TrimEnd('/'));
                if (Uri.TryCreate(line, UriKind.Absolute, out var u)) hosts.Add(u.Host);
            }
            _phishUrls = urls;
            _phishHosts = hosts;
            _feedLoadedAt = DateTime.UtcNow;
        }
        finally
        {
            _feedLock.Release();
        }
    }

    private static string TranslateThreatType(string? t) => t switch
    {
        "MALWARE" => "Zararlı yazılım",
        "SOCIAL_ENGINEERING" => "Oltalama / sosyal mühendislik",
        "UNWANTED_SOFTWARE" => "İstenmeyen yazılım",
        "POTENTIALLY_HARMFUL_APPLICATION" => "Potansiyel zararlı uygulama",
        _ => t ?? "Tehdit"
    };

    private static string Short(Exception ex)
    {
        var msg = ex.InnerException?.Message ?? ex.Message;
        return msg.Length > 140 ? msg[..140] + "…" : msg;
    }
}
