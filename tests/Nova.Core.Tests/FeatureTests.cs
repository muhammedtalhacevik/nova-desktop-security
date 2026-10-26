using System.Security.Cryptography;
using Nova.Core.Models;
using Nova.Core.Services.Breach;
using Nova.Core.Services.Privacy;
using Nova.Core.Services.Web;

namespace Nova.Core.Tests;

public class QuarantineTests
{
    private readonly NovaCore _core = TestEnv.Core;

    [Fact]
    public void Quarantine_and_restore_round_trip()
    {
        var dir = TestEnv.NewSampleDir();
        var data = RandomNumberGenerator.GetBytes(100_000);
        var path = Path.Combine(dir, "suspect.exe");
        File.WriteAllBytes(path, data);
        var threat = new ThreatDetection { FilePath = path, ThreatName = "Test.Q", Sha256 = TestEnv.Sha256(data), FileSize = data.Length };

        var q = _core.Quarantine.Quarantine(threat);

        Assert.True(q.Success, q.Message);
        Assert.False(File.Exists(path));
        Assert.Equal(ThreatAction.Quarantined, threat.Action);
        var stored = File.ReadAllBytes(Path.Combine(AppPaths.Quarantine, q.Item!.StoredFileName));
        Assert.False(stored.AsSpan(4).SequenceEqual(data));

        var r = _core.Quarantine.Restore(q.Item.Id);

        Assert.True(r.Success, r.Message);
        Assert.Equal(data, File.ReadAllBytes(path));
        Assert.Contains(threat.Sha256!, _core.Settings.Current.AllowedHashes);
        Assert.DoesNotContain(_core.Quarantine.Items, i => i.Id == q.Item.Id);
    }

    [Fact]
    public void Delete_removes_quarantined_copy()
    {
        var dir = TestEnv.NewSampleDir();
        var path = Path.Combine(dir, "x.bin");
        File.WriteAllBytes(path, RandomNumberGenerator.GetBytes(64));
        var q = _core.Quarantine.Quarantine(new ThreatDetection { FilePath = path, ThreatName = "Test.D" });
        Assert.True(q.Success);
        var stored = Path.Combine(AppPaths.Quarantine, q.Item!.StoredFileName);
        Assert.True(File.Exists(stored));

        Assert.True(_core.Quarantine.Delete(q.Item.Id).Success);
        Assert.False(File.Exists(stored));
    }
}

public class UrlAnalyzerTests
{
    [Theory]
    [InlineData("example.com", "https://example.com/")]
    [InlineData("  https://Example.com/a?b=1 ", "https://example.com/a?b=1")]
    [InlineData("http://test.com.tr", "http://test.com.tr/")]
    public void Normalizes_valid_input(string input, string expected)
    {
        Assert.True(UrlAnalyzer.TryNormalize(input, out var n, out _));
        Assert.Equal(expected, n!.Uri.AbsoluteUri);
    }

    [Theory]
    [InlineData("")]
    [InlineData("javascript:alert(1)")]
    [InlineData("ftp://files.example.com")]
    [InlineData("localhost")]
    [InlineData("http://exa mple.com")]
    public void Rejects_invalid_input(string input)
    {
        Assert.False(UrlAnalyzer.TryNormalize(input, out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Theory]
    [InlineData("www.ornek.com.tr", "ornek.com.tr")]
    [InlineData("a.b.example.co.uk", "example.co.uk")]
    [InlineData("login.example.com", "example.com")]
    public void Finds_registrable_domain(string host, string expected) =>
        Assert.Equal(expected, UrlAnalyzer.RegistrableDomain(host));

    private static List<RiskSignal> Signals(string url)
    {
        Assert.True(UrlAnalyzer.TryNormalize(url, out var n, out _));
        return UrlAnalyzer.Analyze(n!);
    }

    [Fact]
    public void Flags_brand_impersonation()
    {
        var s = Signals("https://paypal-secure-login.xyz/verify/account");
        Assert.Contains(s, x => x.Title.Contains("paypal") && x.Severity == ThreatSeverity.High);
        Assert.Contains(s, x => x.Title.Contains(".xyz"));
        Assert.True(UrlAnalyzer.Score(s) >= 25);
    }

    [Fact]
    public void Flags_typosquatting() =>
        Assert.Contains(Signals("https://gooogle.com"), x => x.Title.Contains("typosquatting"));

    [Fact]
    public void Flags_ip_address_and_userinfo()
    {
        Assert.Contains(Signals("http://185.12.4.9/login"), x => x.Title.Contains("IP adresi"));
        Assert.Contains(Signals("https://www.google.com@evil.example/"), x => x.Title.Contains("@"));
    }

    [Fact]
    public void Official_sites_have_no_high_signals()
    {
        foreach (var url in new[] { "https://www.google.com", "https://www.paypal.com/signin", "https://www.turkiye.gov.tr", "https://www.garantibbva.com.tr" })
            Assert.DoesNotContain(Signals(url), x => x.Severity >= ThreatSeverity.High);
    }
}

public class MiscTests
{
    [Theory]
    [InlineData("ad.soyad@ornek.com", true)]
    [InlineData("a@b.co", true)]
    [InlineData("eksik@", false)]
    [InlineData("bosluk var@ornek.com", false)]
    [InlineData("iki@@ornek.com", false)]
    [InlineData("", false)]
    public void Validates_email(string email, bool valid) => Assert.Equal(valid, BreachCheckService.IsValidEmail(email));

    [Fact]
    public void Extracts_executable_from_startup_commands()
    {
        Assert.Equal(@"C:\Program Files\App\app.exe", StartupAppsService.ExtractExecutable("\"C:\\Program Files\\App\\app.exe\" --minimized"));
        Assert.Equal(@"C:\Tools\tool.exe", StartupAppsService.ExtractExecutable(@"C:\Tools\tool.exe /background"));
        Assert.Equal(@"C:\Users\a\AppData\evil.dll", StartupAppsService.ExtractExecutable(@"C:\Windows\System32\rundll32.exe C:\Users\a\AppData\evil.dll,Start"));
    }

    [Fact]
    public void Protection_status_reports_missing_scan()
    {
        var status = TestEnv.Core.GetStatus();
        Assert.Contains(status.Issues, i => i.ActionKey is "scan" or "signatures");
    }
}
