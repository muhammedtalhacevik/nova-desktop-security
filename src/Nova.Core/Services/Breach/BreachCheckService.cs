using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Nova.Core.Models;
using Nova.Core.Storage;

namespace Nova.Core.Services.Breach;

public sealed class BreachCheckService(SettingsService settings, EventLogService events)
{
    private readonly JsonStore<List<BreachCheckResult>> _store = new("breach-history.json");

    public IReadOnlyList<BreachCheckResult> History => _store.Load().OrderByDescending(r => r.CheckedAt).ToList();

    public static bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email) || email.Length > 254) return false;
        if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")) return false;
        try { return new MailAddress(email).Address.Equals(email, StringComparison.OrdinalIgnoreCase); }
        catch (FormatException) { return false; }
    }

    public async Task<BreachCheckResult> CheckEmailAsync(string email, CancellationToken ct)
    {
        email = email.Trim().ToLowerInvariant();
        var result = new BreachCheckResult { Email = email };
        if (!IsValidEmail(email))
        {
            result.Error = "Geçerli bir e-posta adresi girin.";
            return result;
        }

        try
        {
            if (settings.Current.HibpApiKey.Trim().Length > 0)
            {
                result.Provider = "Have I Been Pwned";
                result.Breaches = await HibpAsync(email, settings.Current.HibpApiKey.Trim(), ct);
            }
            else
            {
                result.Provider = "XposedOrNot";
                result.Breaches = await XposedOrNotAsync(email, ct);
            }
        }
        catch (BreachServiceException ex)
        {
            result.Error = ex.Message;
            return result;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            if (ct.IsCancellationRequested) throw;
            result.Error = "İhlal kontrol servisine ulaşılamadı. İnternet bağlantınızı kontrol edip tekrar deneyin.";
            return result;
        }

        result.Breaches = result.Breaches.OrderByDescending(b => b.BreachDate ?? DateTimeOffset.MinValue).ToList();

        var history = _store.Load();
        history.RemoveAll(h => h.Email == email);
        history.Add(result);
        _store.Save(history.TakeLast(20).ToList());

        events.Add(EventCategory.Breach,
            result.Found ? ThreatSeverity.High : ThreatSeverity.Info,
            result.Found ? "E-posta veri ihlalinde bulundu" : "Veri ihlali bulunamadı",
            result.Found ? $"{Mask(email)} adresi {result.Breaches.Count} ihlalde yer alıyor." : $"{Mask(email)} bilinen ihlallerde yok.");
        return result;
    }

    public static async Task<long> CheckPasswordAsync(string password, CancellationToken ct)
    {
        var sha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var prefix = sha1[..5];
        var suffix = sha1[5..];

        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.pwnedpasswords.com/range/{prefix}");
        req.Headers.Add("Add-Padding", "true");
        using var resp = await NovaHttp.Shared.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct);
        foreach (var line in body.Split('\n'))
        {
            var parts = line.Trim().Split(':');
            if (parts.Length == 2 && parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase) && long.TryParse(parts[1], out var n))
                return n;
        }
        return 0;
    }

    private static async Task<List<BreachInfo>> HibpAsync(string email, string key, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get,
            $"https://haveibeenpwned.com/api/v3/breachedaccount/{Uri.EscapeDataString(email)}?truncateResponse=false");
        req.Headers.Add("hibp-api-key", key);
        using var resp = await NovaHttp.Shared.SendAsync(req, ct);

        switch (resp.StatusCode)
        {
            case HttpStatusCode.NotFound: return [];
            case HttpStatusCode.Unauthorized: throw new BreachServiceException("HIBP API anahtarı geçersiz.");
            case HttpStatusCode.TooManyRequests: throw new BreachServiceException("Çok fazla sorgu yapıldı; birkaç saniye sonra tekrar deneyin.");
        }
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var list = new List<BreachInfo>();
        foreach (var b in doc.RootElement.EnumerateArray())
        {
            list.Add(new BreachInfo
            {
                Name = Str(b, "Title") ?? Str(b, "Name") ?? "Bilinmeyen",
                Domain = Str(b, "Domain"),
                BreachDate = DateTimeOffset.TryParse(Str(b, "BreachDate"), out var d) ? d : null,
                Records = b.TryGetProperty("PwnCount", out var pc) && pc.TryGetInt64(out var n) ? n : null,
                DataClasses = b.TryGetProperty("DataClasses", out var dc) ? dc.EnumerateArray().Select(x => TranslateDataClass(x.GetString() ?? "")).ToList() : [],
                Description = StripHtml(Str(b, "Description")),
                Verified = b.TryGetProperty("IsVerified", out var v) && v.ValueKind == JsonValueKind.True
            });
        }
        return list;
    }

    private static async Task<List<BreachInfo>> XposedOrNotAsync(string email, CancellationToken ct)
    {
        using var resp = await NovaHttp.Shared.GetAsync($"https://api.xposedornot.com/v1/breach-analytics?email={Uri.EscapeDataString(email)}", ct);
        if (resp.StatusCode == HttpStatusCode.NotFound) return [];
        if (resp.StatusCode == HttpStatusCode.TooManyRequests) throw new BreachServiceException("Çok fazla sorgu yapıldı; bir dakika sonra tekrar deneyin.");
        resp.EnsureSuccessStatusCode();

        var text = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(text);
        var root = doc.RootElement;
        var list = new List<BreachInfo>();

        if (root.TryGetProperty("ExposedBreaches", out var exposed) && exposed.ValueKind == JsonValueKind.Object
            && exposed.TryGetProperty("breaches_details", out var details) && details.ValueKind == JsonValueKind.Array)
        {
            foreach (var b in details.EnumerateArray())
            {
                var year = Str(b, "xposed_date");
                list.Add(new BreachInfo
                {
                    Name = Str(b, "breach") ?? "Bilinmeyen",
                    Domain = Str(b, "domain"),
                    BreachDate = int.TryParse(year, out var y) && y > 1990 ? new DateTimeOffset(y, 1, 1, 0, 0, 0, TimeSpan.Zero) : null,
                    Records = b.TryGetProperty("xposed_records", out var rec) && rec.TryGetInt64(out var r) ? r : null,
                    DataClasses = (Str(b, "xposed_data") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(TranslateDataClass).ToList(),
                    Description = Str(b, "details"),
                    Verified = Str(b, "verified")?.Equals("Yes", StringComparison.OrdinalIgnoreCase) == true,
                    PasswordRisk = Str(b, "password_risk")
                });
            }
            return list;
        }

        using var simple = await NovaHttp.Shared.GetAsync($"https://api.xposedornot.com/v1/check-email/{Uri.EscapeDataString(email)}", ct);
        if (simple.StatusCode == HttpStatusCode.NotFound) return [];
        simple.EnsureSuccessStatusCode();
        using var sdoc = JsonDocument.Parse(await simple.Content.ReadAsStringAsync(ct));
        if (sdoc.RootElement.TryGetProperty("breaches", out var arr) && arr.ValueKind == JsonValueKind.Array)
            foreach (var group in arr.EnumerateArray())
                foreach (var name in group.ValueKind == JsonValueKind.Array ? group.EnumerateArray() : Enumerable.Repeat(group, 1))
                    list.Add(new BreachInfo { Name = name.GetString() ?? "Bilinmeyen" });
        return list;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) ? v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetRawText(),
            _ => null
        } : null;

    private static string? StripHtml(string? html) => html is null ? null : WebUtility.HtmlDecode(Regex.Replace(html, "<.*?>", ""));

    private static string Mask(string email)
    {
        var at = email.IndexOf('@');
        return at <= 1 ? email : email[0] + new string('•', Math.Min(at - 1, 6)) + email[at..];
    }

    private static string TranslateDataClass(string c) => c.ToLowerInvariant() switch
    {
        "email addresses" or "email" or "emails" => "E-posta adresleri",
        "passwords" or "password" => "Parolalar",
        "usernames" or "username" => "Kullanıcı adları",
        "names" or "name" => "Ad soyad",
        "phone numbers" or "phone" => "Telefon numaraları",
        "ip addresses" or "ip address" => "IP adresleri",
        "physical addresses" or "address" or "addresses" => "Fiziksel adresler",
        "dates of birth" or "date of birth" or "dob" => "Doğum tarihleri",
        "genders" or "gender" => "Cinsiyet",
        "geographic locations" or "location" => "Konum bilgisi",
        "credit cards" or "credit card" or "partial credit card data" => "Kredi kartı bilgileri",
        "social media profiles" => "Sosyal medya profilleri",
        "job titles" => "Meslek bilgisi",
        "employers" => "İşveren bilgisi",
        "password hints" => "Parola ipuçları",
        "security questions and answers" => "Güvenlik soruları",
        "government issued ids" or "national ids" => "Kimlik numaraları",
        _ => c
    };
}

public sealed class BreachServiceException(string message) : Exception(message);
