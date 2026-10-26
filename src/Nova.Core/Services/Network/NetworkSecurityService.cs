using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Nova.Core.Models;
using Nova.Core.Services.Platform;

namespace Nova.Core.Services.Network;

public sealed class NetworkSecurityService(EventLogService events)
{
    private static readonly Dictionary<string, string> KnownResolvers = new()
    {
        ["8.8.8.8"] = "Google", ["8.8.4.4"] = "Google",
        ["1.1.1.1"] = "Cloudflare", ["1.0.0.1"] = "Cloudflare", ["1.1.1.2"] = "Cloudflare (Güvenli)", ["1.0.0.2"] = "Cloudflare (Güvenli)",
        ["9.9.9.9"] = "Quad9", ["149.112.112.112"] = "Quad9",
        ["208.67.222.222"] = "OpenDNS", ["208.67.220.220"] = "OpenDNS",
        ["94.140.14.14"] = "AdGuard", ["94.140.15.15"] = "AdGuard",
        ["195.175.39.39"] = "Türk Telekom", ["195.175.39.40"] = "Türk Telekom",
        ["2001:4860:4860::8888"] = "Google", ["2001:4860:4860::8844"] = "Google",
        ["2606:4700:4700::1111"] = "Cloudflare", ["2606:4700:4700::1001"] = "Cloudflare"
    };

    private static readonly (int Port, string Service, CheckState State)[] RiskyPorts =
    [
        (23, "Telnet", CheckState.Fail),
        (21, "FTP", CheckState.Warning),
        (3389, "Uzak Masaüstü (RDP)", CheckState.Warning),
        (5900, "VNC ekran paylaşımı", CheckState.Warning),
        (445, "SMB dosya paylaşımı", CheckState.Info),
        (139, "NetBIOS", CheckState.Info),
        (5985, "WinRM", CheckState.Info),
        (22, "SSH", CheckState.Info)
    ];

    public NetworkReport? LastReport { get; private set; }

    public async Task<NetworkReport> AnalyzeAsync(CancellationToken ct)
    {
        var report = new NetworkReport();
        report.Adapters = GetAdapters();
        report.Primary = report.Adapters.FirstOrDefault(a => a.Gateways.Count > 0) ?? report.Adapters.FirstOrDefault();
        report.VpnActive = DetectVpn();

        if (OperatingSystem.IsMacOS() && report.Primary is { DnsServers.Count: 0 } p)
            p.DnsServers.AddRange(await MacDnsServersAsync(ct));

        var wifiTask = GetWifiAsync(report.Primary, ct);
        var publicTask = PublicIpAsync(report, ct);
        var captiveTask = CaptivePortalAsync(ct);
        var hijackTask = NxDomainHijackAsync(ct);
        var arpTask = ArpTableAsync(ct);
        var firewallTask = FirewallAsync(ct);

        await Task.WhenAll(wifiTask, publicTask, captiveTask, hijackTask, arpTask, firewallTask);

        report.Wifi = await wifiTask;
        report.FirewallEnabled = await firewallTask;
        BuildChecks(report, await captiveTask, await hijackTask, await arpTask);

        LastReport = report;
        var risks = report.Checks.Count(c => c.State == CheckState.Fail);
        if (risks > 0)
            events.Add(EventCategory.Network, ThreatSeverity.High, "Ağ güvenliği riski",
                $"{report.Wifi?.Ssid ?? report.Primary?.Name ?? "Ağ"}: {risks} kritik bulgu tespit edildi.");
        else if (report.RiskCount > 0)
            events.Add(EventCategory.Network, ThreatSeverity.Low, "Ağ analizi tamamlandı",
                $"{report.RiskCount} uyarı — ayrıntılar için Ağ Güvenliği ekranına bakın.");
        return report;
    }

    private static List<NetworkAdapterInfo> GetAdapters()
    {
        var list = new List<NetworkAdapterInfo>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

            IPInterfaceProperties props;
            try { props = ni.GetIPProperties(); } catch { continue; }

            var info = new NetworkAdapterInfo
            {
                Name = ni.Name,
                Description = ni.Description,
                Type = DescribeType(ni.NetworkInterfaceType),
                IsWireless = ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211
                             || ni.Description.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase)
                             || ni.Description.Contains("Wireless", StringComparison.OrdinalIgnoreCase)
                             || ni.Description.Contains("WLAN", StringComparison.OrdinalIgnoreCase),
                Mac = FormatMac(ni.GetPhysicalAddress()),
                SpeedMbps = SafeSpeed(ni)
            };

            foreach (var ua in props.UnicastAddresses)
            {
                if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    info.IPv4.Add(ua.Address.ToString());
                    try { info.SubnetMask ??= ua.IPv4Mask?.ToString(); } catch { }
                }
                else if (ua.Address.AddressFamily == AddressFamily.InterNetworkV6 && !ua.Address.IsIPv6LinkLocal)
                    info.IPv6.Add(ua.Address.ToString());
            }
            if (info.IPv4.Count == 0 && info.IPv6.Count == 0) continue;

            try
            {
                info.Gateways.AddRange(props.GatewayAddresses
                    .Select(g => g.Address)
                    .Where(a => !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any))
                    .Select(a => a.ToString()));
            }
            catch { }

            try { info.DnsServers.AddRange(props.DnsAddresses.Where(a => !a.IsIPv6SiteLocal).Select(a => a.ToString())); }
            catch (PlatformNotSupportedException) { }
            catch (NetworkInformationException) { }

            if (OperatingSystem.IsMacOS() && ni.Name == "en0" && ni.NetworkInterfaceType != NetworkInterfaceType.Wireless80211)
                info.IsWireless = true;

            info.Gateways = info.Gateways.OrderBy(g => g.Contains(':')).ToList();
            info.DnsServers = info.DnsServers.Distinct().OrderBy(d => d.Contains(':')).ToList();
            list.Add(info);
        }
        return list.OrderByDescending(a => a.Gateways.Count).ThenByDescending(a => a.IsWireless).ToList();
    }

    private static long SafeSpeed(NetworkInterface ni)
    {
        try { return ni.Speed > 0 ? ni.Speed / 1_000_000 : 0; } catch { return 0; }
    }

    private static string DescribeType(NetworkInterfaceType t) => t switch
    {
        NetworkInterfaceType.Wireless80211 => "Wi-Fi",
        NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetT => "Ethernet",
        NetworkInterfaceType.Ppp => "PPP / VPN",
        NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2 => "Mobil geniş bant",
        _ => t.ToString()
    };

    private static string FormatMac(PhysicalAddress mac)
    {
        var bytes = mac.GetAddressBytes();
        return bytes.Length == 0 ? "—" : string.Join(':', bytes.Select(b => b.ToString("X2")));
    }

    private static bool DetectVpn()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(ni =>
                ni.OperationalStatus == OperationalStatus.Up &&
                (ni.NetworkInterfaceType is NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel && !ni.Name.StartsWith("Teredo", StringComparison.OrdinalIgnoreCase)
                 || Regex.IsMatch(ni.Name + " " + ni.Description, @"\b(utun[1-9]\d*|wg\d+|tun\d+|tap\d*|ipsec\d+|WireGuard|OpenVPN|TAP-Windows|Wintun|NordLynx|ProtonVPN|Cisco AnyConnect|FortiClient|GlobalProtect)\b", RegexOptions.IgnoreCase)));
        }
        catch { return false; }
    }

    private static async Task<WifiInfo?> GetWifiAsync(NetworkAdapterInfo? primary, CancellationToken ct)
    {
        if (OperatingSystem.IsWindows()) return await Task.Run(WlanNative.Query, ct);
        if (OperatingSystem.IsMacOS()) return await MacWifiAsync(primary, ct);
        return null;
    }

    private static async Task<WifiInfo?> MacWifiAsync(NetworkAdapterInfo? primary, CancellationToken ct)
    {
        if (OperatingSystem.IsMacOS() && MacLocation.ReadWifi() is { Authentication: not null } native)
            return native;

        var res = await ProcessRunner.RunAsync("/usr/sbin/system_profiler", ["SPAirPortDataType", "-json"], TimeSpan.FromSeconds(15), ct);
        if (!res.Ok) return null;
        try
        {
            using var doc = JsonDocument.Parse(res.StdOut);
            foreach (var entry in doc.RootElement.GetProperty("SPAirPortDataType").EnumerateArray())
            {
                if (!entry.TryGetProperty("spairport_airport_interfaces", out var ifaces)) continue;
                foreach (var iface in ifaces.EnumerateArray())
                {
                    if (!iface.TryGetProperty("spairport_current_network_information", out var cur)) continue;
                    var name = cur.TryGetProperty("_name", out var n) ? n.GetString() : null;
                    var mode = cur.TryGetProperty("spairport_security_mode", out var m) ? m.GetString() ?? "" : "";
                    int? channel = null;
                    if (cur.TryGetProperty("spairport_network_channel", out var ch))
                    {
                        var chText = ch.ValueKind == JsonValueKind.Number ? ch.GetInt32().ToString() : ch.GetString() ?? "";
                        if (int.TryParse(Regex.Match(chText, @"\d+").Value, out var c)) channel = c;
                    }
                    int? signal = null;
                    if (cur.TryGetProperty("spairport_signal_noise", out var sn) && Regex.Match(sn.GetString() ?? "", @"-?\d+") is { Success: true } dbm)
                        signal = Math.Clamp(2 * (int.Parse(dbm.Value) + 100), 0, 100);

                    var (auth, open, weak) = mode switch
                    {
                        var s when s.Contains("none") => ("Açık (şifresiz)", true, true),
                        var s when s.Contains("wep") => ("WEP", false, true),
                        var s when s.Contains("wpa3") => (s.Contains("enterprise") ? "WPA3-Enterprise" : "WPA3-Personal", false, false),
                        var s when s.Contains("wpa2") => (s.Contains("enterprise") ? "WPA2-Enterprise" : "WPA2-Personal", false, false),
                        var s when s.Contains("wpa") => ("WPA", false, true),
                        var s when s.Contains("owe") => ("OWE (Gelişmiş Açık)", false, false),
                        _ => (mode.Length > 0 ? mode.Replace("spairport_security_mode_", "") : "Bilinmiyor", false, false)
                    };
                    var redacted = name is null or "<redacted>";
                    return new WifiInfo
                    {
                        Ssid = redacted ? null : name,
                        Authentication = auth,
                        IsOpen = open,
                        IsWeak = weak,
                        SecurityEnabled = !open,
                        Channel = channel,
                        SignalPercent = signal,
                        PhyType = cur.TryGetProperty("spairport_network_phymode", out var phy) ? phy.GetString() : null,
                        Note = redacted ? "macOS, Wi-Fi adını göstermek için Konum Servisleri izni istiyor." : null
                    };
                }
            }
        }
        catch (Exception) { }
        return primary?.IsWireless == true ? new WifiInfo { Note = "Wi-Fi ayrıntıları okunamadı." } : null;
    }

    private static async Task<List<string>> MacDnsServersAsync(CancellationToken ct)
    {
        var res = await ProcessRunner.RunAsync("/usr/sbin/scutil", ["--dns"], TimeSpan.FromSeconds(5), ct);
        return Regex.Matches(res.StdOut, @"nameserver\[\d+\]\s*:\s*(\S+)").Select(m => m.Groups[1].Value).Distinct().Take(6).ToList();
    }

    private static async Task PublicIpAsync(NetworkReport report, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            var json = await NovaHttp.Shared.GetStringAsync("https://ipinfo.io/json", cts.Token);
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            report.PublicIp = r.TryGetProperty("ip", out var ip) ? ip.GetString() : null;
            report.Isp = r.TryGetProperty("org", out var org) ? Regex.Replace(org.GetString() ?? "", @"^AS\d+\s+", "") : null;
            var city = r.TryGetProperty("city", out var c) ? c.GetString() : null;
            var country = r.TryGetProperty("country", out var co) ? co.GetString() : null;
            report.Location = string.Join(", ", new[] { city, country }.Where(s => !string.IsNullOrEmpty(s)));
        }
        catch (Exception)
        {
            try
            {
                report.PublicIp = (await NovaHttp.Shared.GetStringAsync("https://api.ipify.org", ct)).Trim();
            }
            catch (Exception) { }
        }
    }

    private static async Task<bool?> CaptivePortalAsync(CancellationToken ct)
    {
        var (url, expected) = OperatingSystem.IsMacOS()
            ? ("http://captive.apple.com/hotspot-detect.html", "Success")
            : ("http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test");
        try
        {
            using var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
            using var http = NovaHttp.Create(TimeSpan.FromSeconds(6), handler);
            using var resp = await http.GetAsync(url, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);
            return !(resp.StatusCode == HttpStatusCode.OK && body.Contains(expected, StringComparison.Ordinal));
        }
        catch (Exception) when (!ct.IsCancellationRequested) { return null; }
    }

    private static async Task<string?> NxDomainHijackAsync(CancellationToken ct)
    {
        var name = $"nova-{Guid.NewGuid():N}"[..28] + ".com";
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(name, ct).WaitAsync(TimeSpan.FromSeconds(5), ct);
            return addrs.Length > 0 ? addrs[0].ToString() : null;
        }
        catch (Exception) { return null; }
    }

    private static async Task<List<(string Ip, string Mac)>> ArpTableAsync(CancellationToken ct)
    {
        var res = OperatingSystem.IsWindows()
            ? await ProcessRunner.RunAsync("arp", ["-a"], TimeSpan.FromSeconds(6), ct)
            : await ProcessRunner.RunAsync("/usr/sbin/arp", ["-an"], TimeSpan.FromSeconds(6), ct);
        var list = new List<(string, string)>();
        foreach (Match m in Regex.Matches(res.StdOut, @"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})"))
        {
            var mac = string.Join(':', m.Groups[2].Value.Split(':', '-').Select(p => p.PadLeft(2, '0').ToUpperInvariant()));
            if (mac is "FF:FF:FF:FF:FF:FF" or "00:00:00:00:00:00" || mac.StartsWith("01:00:5E", StringComparison.Ordinal) || mac.StartsWith("33:33", StringComparison.Ordinal)) continue;
            list.Add((m.Groups[1].Value, mac));
        }
        return list;
    }

    private static async Task<bool?> FirewallAsync(CancellationToken ct)
    {
        if (OperatingSystem.IsWindows()) return WindowsFirewall();
        if (OperatingSystem.IsMacOS())
        {
            var res = await ProcessRunner.RunAsync("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], TimeSpan.FromSeconds(5), ct);
            if (res.StdOut.Contains("enabled", StringComparison.OrdinalIgnoreCase) || res.StdOut.Contains("State = 1", StringComparison.Ordinal) || res.StdOut.Contains("State = 2", StringComparison.Ordinal))
                return true;
            if (res.StdOut.Contains("disabled", StringComparison.OrdinalIgnoreCase) || res.StdOut.Contains("State = 0", StringComparison.Ordinal))
                return false;
        }
        return null;
    }

    [SupportedOSPlatform("windows")]
    private static bool? WindowsFirewall()
    {
        try
        {
            const string basePath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
            bool? any = null;
            foreach (var profile in new[] { "StandardProfile", "PublicProfile", "DomainProfile" })
            {
                using var key = Registry.LocalMachine.OpenSubKey(basePath + profile);
                if (key?.GetValue("EnableFirewall") is int v)
                {
                    if (v == 0 && profile != "DomainProfile") return false;
                    any = true;
                }
            }
            return any;
        }
        catch { return null; }
    }

    private static void BuildChecks(NetworkReport r, bool? captive, string? hijackIp, List<(string Ip, string Mac)> arp)
    {
        var checks = r.Checks;
        var primary = r.Primary;

        if (primary is null)
        {
            checks.Add(new("İnternet bağlantısı", "Etkin bir ağ bağlantısı bulunamadı.", CheckState.Fail));
            return;
        }

        if (r.Wifi is { } w)
        {
            if (w.Authentication is null)
                checks.Add(new("Wi-Fi şifreleme", w.Note ?? "Şifreleme türü okunamadı.", CheckState.Unavailable, "Wi-Fi ayrıntılarını görmek için konum iznini açın."));
            else if (w.IsOpen)
                checks.Add(new("Wi-Fi şifreleme", $"{w.Authentication} — trafik şifrelenmiyor.", CheckState.Fail,
                    "Bu ağda bankacılık veya parola gerektiren işlemler yapmayın; bir VPN kullanın."));
            else if (w.IsWeak)
                checks.Add(new("Wi-Fi şifreleme", $"{w.Authentication}{(w.Cipher is null ? "" : " / " + w.Cipher)} — eski ve kırılabilir.", CheckState.Fail,
                    "Modem ayarlarından WPA2-AES veya WPA3'e geçin."));
            else
                checks.Add(new("Wi-Fi şifreleme", $"{w.Authentication}{(w.Cipher is null ? "" : " / " + w.Cipher)}", CheckState.Pass));

            if (w.SignalPercent is < 30)
                checks.Add(new("Sinyal gücü", $"%{w.SignalPercent} — zayıf sinyal bağlantı kopmalarına yol açabilir.", CheckState.Info));
        }
        else
        {
            checks.Add(new("Bağlantı türü", $"{primary.Type} kablolu bağlantı — Wi-Fi şifreleme kontrolü gerekmiyor.", CheckState.Pass));
        }

        var gw = primary.Gateways.FirstOrDefault(g => IPAddress.TryParse(g, out var a) && a.AddressFamily == AddressFamily.InterNetwork)
                 ?? primary.Gateways.FirstOrDefault();
        if (gw is null)
            checks.Add(new("Varsayılan ağ geçidi", "Ağ geçidi yok — internete erişim olmayabilir.", CheckState.Warning));
        else if (IPAddress.TryParse(gw, out var gwIp) && gwIp.AddressFamily == AddressFamily.InterNetwork && !IsPrivate(gwIp))
            checks.Add(new("Varsayılan ağ geçidi", $"{gw} genel bir IP adresi; olağan dışı bir yapılandırma.", CheckState.Warning, "Ağ yöneticinize danışın."));
        else
            checks.Add(new("Varsayılan ağ geçidi", gw, CheckState.Pass));

        if (gw is not null && arp.FirstOrDefault(a => a.Ip == gw) is { Mac: not null } gwEntry && gwEntry.Mac.Length > 0)
        {
            var clones = arp.Where(a => a.Mac == gwEntry.Mac && a.Ip != gw).Select(a => a.Ip).ToList();
            checks.Add(clones.Count > 0
                ? new("ARP zehirlenmesi", $"Ağ geçidinin MAC adresi ({gwEntry.Mac}) başka cihazlarda da görünüyor: {string.Join(", ", clones.Take(3))}.", CheckState.Fail,
                    "Ortadaki adam (MITM) saldırısı belirtisi olabilir. Ağdan ayrılın ve modemi kontrol edin.")
                : new("ARP zehirlenmesi", "Ağ geçidi MAC adresi benzersiz; ARP sahteciliği belirtisi yok.", CheckState.Pass));
        }
        else
        {
            checks.Add(new("ARP zehirlenmesi", "ARP tablosu okunamadı.", CheckState.Unavailable));
        }

        if (primary.DnsServers.Count == 0)
            checks.Add(new("DNS sunucuları", "DNS sunucusu bilgisi alınamadı.", CheckState.Unavailable));
        else
        {
            var unknownPublic = primary.DnsServers
                .Where(d => IPAddress.TryParse(d, out var a) && a.AddressFamily == AddressFamily.InterNetwork
                            && !IsPrivate(a) && !KnownResolvers.ContainsKey(d) && !primary.Gateways.Contains(d))
                .ToList();
            var known = primary.DnsServers.Where(KnownResolvers.ContainsKey).Select(d => KnownResolvers[d]).Distinct().ToList();
            if (unknownPublic.Count > 0)
                checks.Add(new("DNS sunucuları", $"{string.Join(", ", unknownPublic)} — bilinen bir genel çözümleyici değil.", CheckState.Info,
                    "Bu adres servis sağlayıcınıza ait değilse ve siz ayarlamadıysanız DNS ayarlarınız değiştirilmiş olabilir."));
            else
                checks.Add(new("DNS sunucuları", known.Count > 0 ? $"Güvenilir çözümleyici: {string.Join(", ", known)}" : "Yerel ağ / servis sağlayıcı DNS'i", CheckState.Pass));
        }

        checks.Add(hijackIp is not null
            ? new("DNS yönlendirme (NXDOMAIN)", $"Var olmayan alan adları {hijackIp} adresine yönlendiriliyor.", CheckState.Warning,
                "DNS yanıtları değiştiriliyor; güvenli bir DNS (ör. 1.1.1.1, 9.9.9.9) kullanmayı düşünün.")
            : new("DNS yönlendirme (NXDOMAIN)", "Var olmayan alan adları doğru şekilde reddediliyor.", CheckState.Pass));

        checks.Add(captive switch
        {
            true => new NetworkCheck("Ağ müdahalesi / Captive portal", "Bağlantı testi beklenmeyen içerik döndürdü — giriş sayfası veya trafiği değiştiren bir aracı var.", CheckState.Warning,
                "Otel / kafe ağlarında giriş sayfası normaldir; aksi halde trafik izleniyor olabilir."),
            false => new NetworkCheck("Ağ müdahalesi / Captive portal", "Trafiğe müdahale belirtisi yok.", CheckState.Pass),
            _ => new NetworkCheck("Ağ müdahalesi / Captive portal", "Bağlantı testi yapılamadı.", CheckState.Unavailable)
        });

        checks.Add(r.FirewallEnabled switch
        {
            true => new NetworkCheck("Güvenlik duvarı", "Açık", CheckState.Pass),
            false => new NetworkCheck("Güvenlik duvarı", "Kapalı — gelen bağlantılar engellenmiyor.", CheckState.Fail, "Sistem ayarlarından güvenlik duvarını açın."),
            _ => new NetworkCheck("Güvenlik duvarı", "Durum okunamadı.", CheckState.Unavailable)
        });

        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
                .Where(e => e.Address.Equals(IPAddress.Any) || e.Address.Equals(IPAddress.IPv6Any))
                .Select(e => e.Port).ToHashSet();
            var exposed = RiskyPorts.Where(p => listeners.Contains(p.Port)).ToList();
            var openNetwork = r.Wifi?.IsOpen == true;
            if (exposed.Count == 0)
                checks.Add(new("Açık servisler", "Riskli bir ağ servisi dışarıya açık değil.", CheckState.Pass));
            else
            {
                var worst = exposed.Any(e => e.State == CheckState.Fail) ? CheckState.Fail
                    : exposed.Any(e => e.State == CheckState.Warning) ? (openNetwork ? CheckState.Fail : CheckState.Warning)
                    : openNetwork ? CheckState.Warning : CheckState.Info;
                checks.Add(new("Açık servisler", string.Join(", ", exposed.Select(e => $"{e.Service} ({e.Port})")) + " ağdaki diğer cihazlara açık.", worst,
                    worst == CheckState.Info
                        ? "Ev / iş ağında olağandır; halka açık ağlarda güvenlik duvarının 'Ortak ağ' profilini kullanın."
                        : "Kullanmıyorsanız bu servisleri kapatın; halka açık ağlarda özellikle risklidir."));
            }
        }
        catch (Exception)
        {
            checks.Add(new("Açık servisler", "Dinlenen portlar okunamadı.", CheckState.Unavailable));
        }

        checks.Add(r.VpnActive
            ? new("VPN", "Etkin bir VPN / tünel bağlantısı var; trafiğiniz şifreli tünelden geçiyor.", CheckState.Pass)
            : new("VPN", "VPN kullanılmıyor.", r.Wifi?.IsOpen == true ? CheckState.Warning : CheckState.Info,
                r.Wifi?.IsOpen == true ? "Açık ağlarda güvenilir bir VPN kullanın." : null));
    }

    internal static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal || IPAddress.IsLoopback(ip);
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)
               || (b[0] == 169 && b[1] == 254) || b[0] == 127 || (b[0] == 100 && b[1] is >= 64 and <= 127);
    }
}
