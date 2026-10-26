using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Nova.Core.Services.Privacy;

[SupportedOSPlatform("windows")]
internal static class WinTrust
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);

    public static bool? Verify(string path, out string? signer)
    {
        signer = null;
        if (!File.Exists(path)) return null;

        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path
        };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            var action = GenericVerifyV2;
            var hr = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            if (hr == 0)
            {
                signer = SignerName(path);
                return true;
            }
            if (hr == TRUST_E_NOSIGNATURE)
            {
                var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                return path.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ? null : false;
            }
            return false;
        }
        catch (Exception)
        {
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
        }
    }

    private static string? SignerName(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
}

internal static class ShellLink
{
    public static (string? Target, string? Arguments) Read(string path)
    {
        try
        {
            var b = File.ReadAllBytes(path);
            if (b.Length < 0x4C || BitConverter.ToUInt32(b, 0) != 0x4C) return (null, null);
            var flags = BitConverter.ToUInt32(b, 0x14);
            var pos = 0x4C;
            if ((flags & 0x1) != 0) pos += 2 + BitConverter.ToUInt16(b, pos);

            string? target = null;
            if ((flags & 0x2) != 0)
            {
                var start = pos;
                var size = BitConverter.ToInt32(b, start);
                var headerSize = BitConverter.ToInt32(b, start + 4);
                var infoFlags = BitConverter.ToUInt32(b, start + 8);
                if ((infoFlags & 0x1) != 0)
                {
                    if (headerSize >= 0x24)
                    {
                        var uniOffset = BitConverter.ToInt32(b, start + 0x1C);
                        target = ReadUnicodeZ(b, start + uniOffset);
                    }
                    if (string.IsNullOrEmpty(target))
                    {
                        var offset = BitConverter.ToInt32(b, start + 0x10);
                        target = ReadAnsiZ(b, start + offset);
                    }
                }
                pos = start + size;
            }

            var unicode = (flags & 0x80) != 0;
            string? args = null;
            string? relative = null;
            foreach (var (bit, kind) in new[] { (0x4u, 0), (0x8u, 1), (0x10u, 2), (0x20u, 3) })
            {
                if ((flags & bit) == 0) continue;
                var count = BitConverter.ToUInt16(b, pos);
                pos += 2;
                var bytes = unicode ? count * 2 : count;
                var s = unicode ? Encoding.Unicode.GetString(b, pos, bytes) : Encoding.Default.GetString(b, pos, bytes);
                pos += bytes;
                if (kind == 1) relative = s;
                if (kind == 3) args = s;
            }
            if (string.IsNullOrEmpty(target) && relative is not null)
                target = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, relative));
            return (target, args);
        }
        catch
        {
            return (null, null);
        }
    }

    private static string ReadAnsiZ(byte[] b, int offset)
    {
        var end = Array.IndexOf(b, (byte)0, offset);
        return Encoding.Default.GetString(b, offset, (end < 0 ? b.Length : end) - offset);
    }

    private static string ReadUnicodeZ(byte[] b, int offset)
    {
        var end = offset;
        while (end + 1 < b.Length && (b[end] != 0 || b[end + 1] != 0)) end += 2;
        return Encoding.Unicode.GetString(b, offset, end - offset);
    }
}
