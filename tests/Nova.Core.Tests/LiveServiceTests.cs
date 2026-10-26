using Nova.Core.Models;
using Nova.Core.Services.Breach;

namespace Nova.Core.Tests;

[Trait("Category", "Live")]
public class LiveServiceTests
{
    private readonly NovaCore _core = TestEnv.Core;

    [Fact]
    public async Task Url_check_of_well_known_site_is_safe()
    {
        var r = await _core.Web.CheckAsync("https://www.google.com", CancellationToken.None);
        Assert.Null(r.Error);
        Assert.Equal(UrlVerdict.Safe, r.Verdict);
        Assert.True(r.CertificateValid);
        Assert.NotEmpty(r.ResolvedIps);
        Assert.Contains(r.Intel, i => i.Provider.StartsWith("OpenPhish") && i.Checked);
    }

    [Fact]
    public async Task Url_check_of_lookalike_domain_is_not_safe()
    {
        var r = await _core.Web.CheckAsync("http://paypal-account-verify.xyz/login", CancellationToken.None);
        Assert.NotEqual(UrlVerdict.Safe, r.Verdict);
    }

    [Fact]
    public async Task Breach_lookup_returns_without_error()
    {
        var r = await _core.Breach.CheckEmailAsync("test@example.com", CancellationToken.None);
        Assert.Null(r.Error);
    }

    [Fact]
    public async Task Common_password_is_found_in_breaches()
    {
        Assert.True(await BreachCheckService.CheckPasswordAsync("123456", CancellationToken.None) > 1000);
    }

    [Fact]
    public async Task Network_analysis_finds_primary_adapter()
    {
        var r = await _core.Network.AnalyzeAsync(CancellationToken.None);
        Assert.NotNull(r.Primary);
        Assert.NotEmpty(r.Checks);
    }

    [Fact]
    public async Task Signature_feed_update_succeeds()
    {
        var before = _core.Signatures.HashCount;
        await _core.UpdateSignaturesAsync(CancellationToken.None);
        Assert.True(_core.Signatures.HashCount >= before);
    }

    [Fact]
    public async Task Startup_items_and_permissions_are_listed()
    {
        var items = await _core.Startup.GetItemsAsync();
        var perms = await _core.Permissions.GetReportAsync();
        Assert.NotNull(items);
        Assert.NotNull(perms);
        if (OperatingSystem.IsWindows()) Assert.NotEmpty(perms.Groups);
    }
}
