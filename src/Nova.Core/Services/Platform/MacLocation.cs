using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Nova.Core.Models;

namespace Nova.Core.Services.Platform;

[SupportedOSPlatform("macos")]
public static class MacLocation
{
    private const string ObjC = "/usr/lib/libobjc.A.dylib";
    private const string CoreLocationPath = "/System/Library/Frameworks/CoreLocation.framework/CoreLocation";
    private const string CoreWlanPath = "/System/Library/Frameworks/CoreWLAN.framework/CoreWLAN";

    public const int NotDetermined = 0;
    public const int Restricted = 1;
    public const int Denied = 2;
    public const int Authorized = 3;

    private static IntPtr _manager;
    private static bool _updating;
    private static readonly object Gate = new();

    [DllImport(ObjC)] private static extern IntPtr objc_getClass(string name);
    [DllImport(ObjC)] private static extern IntPtr sel_registerName(string name);
    [DllImport(ObjC, EntryPoint = "objc_msgSend")] private static extern IntPtr Msg(IntPtr receiver, IntPtr selector);
    [DllImport(ObjC, EntryPoint = "objc_msgSend")] private static extern int MsgInt(IntPtr receiver, IntPtr selector);
    [DllImport(ObjC, EntryPoint = "objc_msgSend")] private static extern long MsgLong(IntPtr receiver, IntPtr selector);
    [DllImport(ObjC, EntryPoint = "objc_msgSend")] private static extern void MsgVoid(IntPtr receiver, IntPtr selector);
    [DllImport(ObjC, EntryPoint = "objc_msgSend")]
    [return: MarshalAs(UnmanagedType.I1)]
    private static extern bool MsgBool(IntPtr receiver, IntPtr selector);

    private static IntPtr Sel(string name) => sel_registerName(name);

    private static bool LoadFramework(string path) => NativeLibrary.TryLoad(path, out _);

    public static bool IsGranted(int status) => status is 3 or 4;

    public static int Request()
    {
        lock (Gate)
        {
            try
            {
                if (!LoadFramework(CoreLocationPath)) return Denied;
                if (_manager == IntPtr.Zero)
                    _manager = Msg(Msg(objc_getClass("CLLocationManager"), Sel("alloc")), Sel("init"));
                if (_manager == IntPtr.Zero) return Denied;

                var status = MsgInt(_manager, Sel("authorizationStatus"));
                if (status == NotDetermined)
                {
                    MsgVoid(_manager, Sel("requestWhenInUseAuthorization"));
                    if (!_updating)
                    {
                        MsgVoid(_manager, Sel("startUpdatingLocation"));
                        _updating = true;
                    }
                }
                else if (_updating)
                {
                    MsgVoid(_manager, Sel("stopUpdatingLocation"));
                    _updating = false;
                }
                return status;
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException)
            {
                return Denied;
            }
        }
    }

    public static int Status()
    {
        lock (Gate)
        {
            if (_manager == IntPtr.Zero) return Request();
            try
            {
                var status = MsgInt(_manager, Sel("authorizationStatus"));
                if (status != NotDetermined && _updating)
                {
                    MsgVoid(_manager, Sel("stopUpdatingLocation"));
                    _updating = false;
                }
                return status;
            }
            catch (Exception) { return Denied; }
        }
    }

    public static bool ServicesEnabled()
    {
        try
        {
            return LoadFramework(CoreLocationPath) && MsgBool(objc_getClass("CLLocationManager"), Sel("locationServicesEnabled"));
        }
        catch (Exception) { return true; }
    }

    public static string DescribeProblem()
    {
        if (!ServicesEnabled())
            return "Konum Servisleri sistem genelinde kapalı. Sistem Ayarları › Gizlilik ve Güvenlik › Konum Servisleri'ni açın.";
        return Status() switch
        {
            NotDetermined => "Wi-Fi adını göstermek için çıkan konum izni penceresinde 'İzin Ver'i seçin.",
            Denied or Restricted => "Konum izni reddedilmiş. Sistem Ayarları › Gizlilik ve Güvenlik › Konum Servisleri'nde Nova'yı açın.",
            _ => "Wi-Fi adı okunamadı."
        };
    }

    public static WifiInfo? ReadWifi()
    {
        try
        {
            if (!LoadFramework(CoreWlanPath)) return null;
            var client = Msg(objc_getClass("CWWiFiClient"), Sel("sharedWiFiClient"));
            if (client == IntPtr.Zero) return null;
            var iface = Msg(client, Sel("interface"));
            if (iface == IntPtr.Zero) return null;
            if (!MsgBool(iface, Sel("powerOn"))) return null;

            var ssid = Str(Msg(iface, Sel("ssid")));
            var bssid = Str(Msg(iface, Sel("bssid")));
            var security = MsgLong(iface, Sel("security"));
            var rssi = MsgLong(iface, Sel("rssiValue"));
            var phy = MsgLong(iface, Sel("activePHYMode"));
            var channelObj = Msg(iface, Sel("wlanChannel"));
            var channel = channelObj != IntPtr.Zero ? MsgLong(channelObj, Sel("channelNumber")) : 0;

            if (rssi == 0 && security == 0 && ssid is null && bssid is null)
                return null;

            var (auth, open, weak) = security switch
            {
                0 => ("Açık (şifresiz)", true, true),
                1 => ("WEP", false, true),
                2 => ("WPA-Personal", false, true),
                3 => ("WPA/WPA2-Personal", false, true),
                4 => ("WPA2-Personal", false, false),
                5 => ("Personal", false, false),
                6 => ("Dinamik WEP", false, true),
                7 => ("WPA-Enterprise", false, true),
                8 => ("WPA/WPA2-Enterprise", false, true),
                9 => ("WPA2-Enterprise", false, false),
                10 => ("Enterprise", false, false),
                11 => ("WPA3-Personal", false, false),
                12 => ("WPA3-Enterprise", false, false),
                13 => ("WPA3-Personal (geçiş)", false, false),
                14 or 15 => ("OWE (Gelişmiş Açık)", false, false),
                _ => ($"Bilinmiyor ({security})", false, false)
            };

            return new WifiInfo
            {
                Ssid = ssid,
                Bssid = bssid,
                Authentication = auth,
                IsOpen = open,
                IsWeak = weak,
                SecurityEnabled = !open,
                SignalPercent = rssi < 0 ? (int)Math.Clamp(2 * (rssi + 100), 0, 100) : null,
                Channel = channel > 0 ? (int)channel : null,
                PhyType = phy switch { 1 => "802.11a", 2 => "802.11b", 3 => "802.11g", 4 => "802.11n (Wi-Fi 4)", 5 => "802.11ac (Wi-Fi 5)", 6 => "802.11ax (Wi-Fi 6)", 7 => "802.11be (Wi-Fi 7)", _ => null },
                Note = ssid is null ? DescribeProblem() : null
            };
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException)
        {
            return null;
        }
    }

    private static string? Str(IntPtr nsString)
    {
        if (nsString == IntPtr.Zero) return null;
        var utf8 = Msg(nsString, Sel("UTF8String"));
        return utf8 == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(utf8);
    }
}
