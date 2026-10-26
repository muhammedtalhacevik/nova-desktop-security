using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Nova.Core.Models;

namespace Nova.Core.Services.Web;

public static class UrlAnalyzer
{
    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = true };

    private static readonly HashSet<string> MultiPartSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "bel.tr", "k12.tr", "gen.tr", "web.tr", "av.tr", "biz.tr", "info.tr", "tsk.tr", "pol.tr",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "com.br", "co.in", "co.nz", "co.za", "com.mx",
        "com.ar", "com.cn", "com.hk", "com.sg", "co.kr", "com.ua", "com.pl", "co.il", "com.de", "github.io", "herokuapp.com", "azurewebsites.net",
        "web.app", "firebaseapp.com", "pages.dev", "netlify.app", "vercel.app", "blogspot.com", "appspot.com", "cloudfront.net", "ngrok.io", "ngrok-free.app"
    };

    private static readonly HashSet<string> AbusedHosting = new(StringComparer.OrdinalIgnoreCase)
    {
        "ngrok.io", "ngrok-free.app", "trycloudflare.com", "000webhostapp.com", "weebly.com", "wixsite.com", "glitch.me", "repl.co",
        "firebaseapp.com", "web.app", "pages.dev", "netlify.app", "vercel.app", "github.io", "duckdns.org", "serveo.net", "workers.dev"
    };

    private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work", "rest", "fit", "loan", "men",
        "date", "racing", "download", "stream", "review", "party", "cam", "icu", "buzz", "monster", "cyou", "sbs", "quest", "bond"
    };

    private static readonly HashSet<string> Shorteners = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "ow.ly", "buff.ly", "shorturl.at", "tiny.cc", "t.ly",
        "rebrand.ly", "s.id", "v.gd", "lnkd.in", "bl.ink", "short.io", "qr.ae"
    };

    private static readonly Dictionary<string, string[]> Brands = new(StringComparer.OrdinalIgnoreCase)
    {
        ["paypal"] = ["paypal.com", "paypal.me"],
        ["apple"] = ["apple.com", "icloud.com", "apple.news"],
        ["icloud"] = ["icloud.com", "apple.com"],
        ["microsoft"] = ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "msn.com", "azure.com", "bing.com", "windows.com", "xbox.com"],
        ["office365"] = ["office.com", "microsoft.com", "microsoftonline.com"],
        ["outlook"] = ["outlook.com", "live.com", "office.com", "microsoft.com"],
        ["google"] = ["google.com", "google.com.tr", "gmail.com", "youtube.com", "googleusercontent.com", "gstatic.com", "goo.gl", "googleapis.com"],
        ["gmail"] = ["gmail.com", "google.com"],
        ["facebook"] = ["facebook.com", "fb.com", "fb.me", "meta.com"],
        ["instagram"] = ["instagram.com"],
        ["whatsapp"] = ["whatsapp.com", "whatsapp.net", "wa.me"],
        ["netflix"] = ["netflix.com"],
        ["amazon"] = ["amazon.com", "amazon.com.tr", "amazon.de", "amazon.co.uk", "aws.amazon.com", "amazonaws.com"],
        ["binance"] = ["binance.com", "binance.tr"],
        ["steam"] = ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
        ["garanti"] = ["garantibbva.com.tr", "garanti.com.tr"],
        ["ziraat"] = ["ziraatbank.com.tr", "ziraat.com.tr"],
        ["isbank"] = ["isbank.com.tr"],
        ["akbank"] = ["akbank.com"],
        ["yapikredi"] = ["yapikredi.com.tr"],
        ["halkbank"] = ["halkbank.com.tr"],
        ["vakifbank"] = ["vakifbank.com.tr"],
        ["denizbank"] = ["denizbank.com"],
        ["enpara"] = ["enpara.com"],
        ["papara"] = ["papara.com"],
        ["edevlet"] = ["turkiye.gov.tr"],
        ["turkiye"] = ["turkiye.gov.tr", "turkiye.com.tr"],
        ["hepsiburada"] = ["hepsiburada.com"],
        ["trendyol"] = ["trendyol.com"],
        ["sahibinden"] = ["sahibinden.com"],
        ["turkcell"] = ["turkcell.com.tr"],
        ["vodafone"] = ["vodafone.com.tr", "vodafone.com"],
        ["yurtici"] = ["yurticikargo.com"],
        ["aras"] = ["araskargo.com.tr"],
        ["linkedin"] = ["linkedin.com", "lnkd.in"],
        ["dropbox"] = ["dropbox.com"],
        ["docusign"] = ["docusign.com", "docusign.net"]
    };

    private static readonly Regex LureWords = new(@"(login|signin|sign-in|verify|verification|account|update|secure|banking|wallet|password|giris|dogrula|hesap|sifre|guncelle|odeme|kargo|iade)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public sealed record Normalized(Uri Uri, string Host, string AsciiHost, string RegistrableDomain, bool IsIpLiteral);

    public static bool TryNormalize(string input, out Normalized? result, out string error)
    {
        result = null;
        error = "";
        var text = (input ?? "").Trim();
        if (text.Length == 0) { error = "Lütfen bir bağlantı girin."; return false; }
        if (text.Length > 4096) { error = "Bağlantı çok uzun."; return false; }
        if (text.Any(char.IsWhiteSpace)) { error = "Bağlantı boşluk içeremez."; return false; }

        if (!Regex.IsMatch(text, @"^[a-zA-Z][a-zA-Z0-9+.-]*://"))
            text = "https://" + text;

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)) { error = "Geçerli bir web adresi değil."; return false; }
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            error = $"Yalnızca http ve https bağlantıları kontrol edilebilir ({uri.Scheme}:// desteklenmiyor).";
            return false;
        }

        var host = uri.Host.TrimEnd('.');
        if (host.Length == 0) { error = "Bağlantıda alan adı bulunamadı."; return false; }

        var isIp = IPAddress.TryParse(host.Trim('[', ']'), out _);
        string ascii;
        if (isIp) ascii = host;
        else
        {
            try { ascii = Idn.GetAscii(host).ToLowerInvariant(); }
            catch (ArgumentException) { error = "Alan adı geçersiz karakterler içeriyor."; return false; }
            if (!ascii.Contains('.')) { error = "Alan adı bir uzantı içermiyor (ör. .com)."; return false; }
            if (ascii.Split('.').Any(l => l.Length is 0 or > 63)) { error = "Alan adı biçimi geçersiz."; return false; }
        }

        result = new Normalized(uri, host, ascii, isIp ? ascii : RegistrableDomain(ascii), isIp);
        return true;
    }

    public static string RegistrableDomain(string asciiHost)
    {
        var labels = asciiHost.ToLowerInvariant().Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length <= 2) return string.Join('.', labels);
        var lastTwo = labels[^2] + "." + labels[^1];
        var lastThree = labels.Length >= 3 ? labels[^3] + "." + lastTwo : lastTwo;
        if (MultiPartSuffixes.Contains(lastThree) && labels.Length >= 4) return labels[^4] + "." + lastThree;
        if (MultiPartSuffixes.Contains(lastTwo)) return lastThree;
        return lastTwo;
    }

    public static bool IsShortener(string registrable) => Shorteners.Contains(registrable);

    public static List<RiskSignal> Analyze(Normalized n)
    {
        var signals = new List<RiskSignal>();
        var uri = n.Uri;
        var full = uri.OriginalString;

        if (uri.Scheme == Uri.UriSchemeHttp)
            signals.Add(new("Şifrelenmemiş bağlantı (HTTP)", "Bu sitede girdiğiniz bilgiler ağdaki başkaları tarafından okunabilir.", ThreatSeverity.Medium));

        if (n.IsIpLiteral)
            signals.Add(new("Alan adı yerine IP adresi", "Meşru siteler nadiren doğrudan IP adresiyle paylaşılır; oltalama bağlantılarında yaygındır.", ThreatSeverity.High));

        if (!string.IsNullOrEmpty(uri.UserInfo) || full.Contains('@') && full.IndexOf('@') < full.IndexOf(uri.Host, StringComparison.OrdinalIgnoreCase))
            signals.Add(new("Bağlantıda '@' karakteri", "'@' işaretinden önceki kısım tarayıcı tarafından yok sayılır ve gerçek hedefi gizlemek için kullanılır.", ThreatSeverity.High));

        if (n.AsciiHost.Split('.').Any(l => l.StartsWith("xn--", StringComparison.Ordinal)))
            signals.Add(new("Uluslararası karakterli alan adı (Punycode)", $"Gerçek adres: {n.AsciiHost}. Benzer görünen harflerle bilinen bir siteyi taklit edebilir.", ThreatSeverity.Medium));

        if (!uri.IsDefaultPort)
            signals.Add(new("Standart olmayan bağlantı noktası", $"Bağlantı {uri.Port} numaralı portu kullanıyor.", ThreatSeverity.Low));

        var labelCount = n.AsciiHost.Split('.').Length;
        if (!n.IsIpLiteral && labelCount >= 5)
            signals.Add(new("Çok sayıda alt alan adı", "Uzun alt alan adı zincirleri gerçek alan adını gizlemek için kullanılabilir.", ThreatSeverity.Low));

        if (full.Length > 160)
            signals.Add(new("Çok uzun bağlantı", $"{full.Length} karakter; gerçek hedefi gizlemek için kullanılabilir.", ThreatSeverity.Low));

        var tld = n.AsciiHost.Split('.')[^1];
        if (!n.IsIpLiteral && SuspiciousTlds.Contains(tld))
            signals.Add(new($"Riskli alan adı uzantısı (.{tld})", "Bu uzantı kötüye kullanım raporlarında sık görülür.", ThreatSeverity.Low));

        if (IsShortener(n.RegistrableDomain))
            signals.Add(new("Bağlantı kısaltıcı", "Kısaltılmış bağlantılar gerçek hedefi gizler; Nova yönlendirmeyi takip ederek son adresi kontrol eder.", ThreatSeverity.Info));

        if (AbusedHosting.Contains(n.RegistrableDomain) || AbusedHosting.Any(h => n.AsciiHost.EndsWith("." + h, StringComparison.OrdinalIgnoreCase)))
            signals.Add(new("Ücretsiz barındırma / tünel servisi", "Herkesin site açabildiği bu servisler oltalama sayfaları için sıkça kullanılır.", ThreatSeverity.Medium));

        if (!n.IsIpLiteral)
        {
            var tokens = n.AsciiHost.Split('.', '-');
            var regLabel = n.RegistrableDomain.Split('.')[0];
            foreach (var (brand, official) in Brands)
            {
                if (official.Any(o => n.RegistrableDomain.Equals(o, StringComparison.OrdinalIgnoreCase))) continue;
                var mentions = tokens.Any(t => t.Equals(brand, StringComparison.OrdinalIgnoreCase)
                                               || brand.Length >= 6 && t.Contains(brand, StringComparison.OrdinalIgnoreCase));
                if (mentions)
                {
                    signals.Add(new($"'{brand}' markasını taklit ediyor olabilir",
                        $"Adres '{brand}' adını içeriyor ancak resmi alan adı ({official[0]}) değil.", ThreatSeverity.High));
                    break;
                }

                foreach (var o in official)
                {
                    var officialLabel = o.Split('.')[0];
                    if (officialLabel.Length < 5 || regLabel.Equals(officialLabel, StringComparison.OrdinalIgnoreCase)) continue;
                    var d = Levenshtein(regLabel, officialLabel);
                    var maxDistance = officialLabel.Length >= 8 ? 2 : 1;
                    if (d >= 1 && d <= maxDistance && regLabel.Length >= 5)
                    {
                        signals.Add(new("Benzer alan adı (typosquatting)",
                            $"'{n.RegistrableDomain}', resmi '{o}' adresine çok benziyor.", ThreatSeverity.High));
                        goto doneBrands;
                    }
                }
            }
        }
        doneBrands:

        if (LureWords.IsMatch(uri.AbsolutePath + uri.Query) && signals.Any(s => s.Severity >= ThreatSeverity.Medium))
            signals.Add(new("Kimlik bilgisi isteyen ifadeler", "Bağlantı 'giriş / doğrula / hesap' gibi oltalamada sık kullanılan kelimeler içeriyor.", ThreatSeverity.Low));

        if (Regex.IsMatch(uri.AbsolutePath, @"\.(exe|scr|msi|bat|cmd|ps1|vbs|js|jar|apk|dmg|pkg|iso|zip|rar|7z)$", RegexOptions.IgnoreCase))
            signals.Add(new("Doğrudan dosya indirme", "Bağlantı çalıştırılabilir veya arşiv bir dosyayı indiriyor.", ThreatSeverity.Medium));

        return signals;
    }

    public static int Score(IEnumerable<RiskSignal> signals) =>
        Math.Clamp(signals.Sum(s => s.Severity switch
        {
            ThreatSeverity.Critical => 45,
            ThreatSeverity.High => 28,
            ThreatSeverity.Medium => 14,
            ThreatSeverity.Low => 6,
            _ => 0
        }), 0, 100);

    internal static int Levenshtein(string a, string b)
    {
        var d = new int[a.Length + 1, b.Length + 1];
        for (var i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (var j = 0; j <= b.Length; j++) d[0, j] = j;
        for (var i = 1; i <= a.Length; i++)
            for (var j = 1; j <= b.Length; j++)
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + (char.ToLowerInvariant(a[i - 1]) == char.ToLowerInvariant(b[j - 1]) ? 0 : 1));
        return d[a.Length, b.Length];
    }
}
