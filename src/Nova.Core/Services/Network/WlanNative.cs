using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Nova.Core.Models;

namespace Nova.Core.Services.Network;

[SupportedOSPlatform("windows")]
internal static class WlanNative
{
    private const int ErrorAccessDenied = 5;
    private const int OpcodeCurrentConnection = 7;

    public static WifiInfo? Query()
    {
        IntPtr handle = IntPtr.Zero, list = IntPtr.Zero;
        try
        {
            if (WlanOpenHandle(2, IntPtr.Zero, out _, out handle) != 0) return null;
            if (WlanEnumInterfaces(handle, IntPtr.Zero, out list) != 0) return null;

            var count = Marshal.ReadInt32(list);
            var itemSize = Marshal.SizeOf<WLAN_INTERFACE_INFO>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(list + 8 + i * itemSize);
                if (info.isState != 1) continue;

                var guid = info.InterfaceGuid;
                var rc = WlanQueryInterface(handle, ref guid, OpcodeCurrentConnection, IntPtr.Zero, out _, out var data, out _);
                if (rc == ErrorAccessDenied)
                    return new WifiInfo { Note = "Wi-Fi adı için konum izni gerekiyor (Ayarlar › Gizlilik › Konum).", Authentication = null };
                if (rc != 0) continue;
                try
                {
                    var conn = Marshal.PtrToStructure<WLAN_CONNECTION_ATTRIBUTES>(data);
                    var assoc = conn.wlanAssociationAttributes;
                    var sec = conn.wlanSecurityAttributes;
                    var ssid = Encoding.UTF8.GetString(assoc.dot11Ssid.ucSSID, 0, (int)Math.Min(assoc.dot11Ssid.uSSIDLength, 32u));
                    var (auth, open, weak) = DescribeAuth(sec.dot11AuthAlgorithm, sec.bSecurityEnabled);
                    var cipher = DescribeCipher(sec.dot11CipherAlgorithm);
                    if (sec.dot11CipherAlgorithm is 1 or 2 or 5 or 0x101) weak = true;

                    return new WifiInfo
                    {
                        Ssid = ssid.Length > 0 ? ssid : conn.strProfileName,
                        Bssid = string.Join(':', assoc.dot11Bssid.Select(b => b.ToString("X2"))),
                        Authentication = auth,
                        Cipher = cipher,
                        SignalPercent = (int)assoc.wlanSignalQuality,
                        PhyType = DescribePhy(assoc.dot11PhyType),
                        SecurityEnabled = sec.bSecurityEnabled,
                        IsOpen = open,
                        IsWeak = weak,
                        Note = ssid.Length == 0 ? "Wi-Fi adı (SSID) gizli veya konum izni kapalı." : null
                    };
                }
                finally
                {
                    WlanFreeMemory(data);
                }
            }
            return null;
        }
        catch (DllNotFoundException) { return null; }
        catch (EntryPointNotFoundException) { return null; }
        finally
        {
            if (list != IntPtr.Zero) WlanFreeMemory(list);
            if (handle != IntPtr.Zero) WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    private static (string Name, bool Open, bool Weak) DescribeAuth(int algo, bool securityEnabled) => algo switch
    {
        1 => securityEnabled ? ("Açık + WEP", false, true) : ("Açık (şifresiz)", true, true),
        2 => ("WEP (paylaşılan anahtar)", false, true),
        3 => ("WPA-Enterprise", false, true),
        4 => ("WPA-Personal", false, true),
        5 => ("WPA-None", false, true),
        6 => ("WPA2-Enterprise", false, false),
        7 => ("WPA2-Personal", false, false),
        8 => ("WPA3-Enterprise 192-bit", false, false),
        9 => ("WPA3-Personal (SAE)", false, false),
        10 => ("OWE (Gelişmiş Açık)", false, false),
        11 => ("WPA3-Enterprise", false, false),
        _ => ($"Bilinmiyor ({algo})", false, false)
    };

    private static string DescribeCipher(int c) => c switch
    {
        0 => "Yok",
        1 => "WEP-40",
        2 => "TKIP",
        4 => "AES-CCMP",
        5 => "WEP-104",
        8 => "GCMP",
        9 => "GCMP-256",
        10 => "CCMP-256",
        0x100 => "Grup şifresi",
        0x101 => "WEP",
        _ => $"0x{c:X}"
    };

    private static string DescribePhy(int phy) => phy switch
    {
        4 => "802.11a",
        5 => "802.11b",
        6 => "802.11g",
        7 => "802.11n (Wi-Fi 4)",
        8 => "802.11ac (Wi-Fi 5)",
        10 => "802.11ax (Wi-Fi 6)",
        11 => "802.11be (Wi-Fi 7)",
        _ => "—"
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strInterfaceDescription;
        public int isState;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DOT11_SSID
    {
        public uint uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] ucSSID;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_ASSOCIATION_ATTRIBUTES
    {
        public DOT11_SSID dot11Ssid;
        public int dot11BssType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] dot11Bssid;
        public int dot11PhyType;
        public uint uDot11PhyIndex;
        public uint wlanSignalQuality;
        public uint ulRxRate;
        public uint ulTxRate;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_SECURITY_ATTRIBUTES
    {
        [MarshalAs(UnmanagedType.Bool)] public bool bSecurityEnabled;
        [MarshalAs(UnmanagedType.Bool)] public bool bOneXEnabled;
        public int dot11AuthAlgorithm;
        public int dot11CipherAlgorithm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_CONNECTION_ATTRIBUTES
    {
        public int isState;
        public int wlanConnectionMode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strProfileName;
        public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
        public WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes;
    }

    [DllImport("wlanapi.dll")]
    private static extern int WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

    [DllImport("wlanapi.dll")]
    private static extern int WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

    [DllImport("wlanapi.dll")]
    private static extern int WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll")]
    private static extern int WlanQueryInterface(IntPtr hClientHandle, ref Guid pInterfaceGuid, int opCode, IntPtr pReserved,
        out int pdwDataSize, out IntPtr ppData, out int pWlanOpcodeValueType);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr pMemory);
}
