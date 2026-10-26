using System.Runtime.InteropServices;

namespace Nova.Core.Services.Scanning;

public static class FileKind
{
    private const ushort S_IFMT = 0xF000;
    private const ushort S_IFREG = 0x8000;

    [DllImport("libc", EntryPoint = "stat", SetLastError = true)]
    private static extern int stat(string path, byte[] buffer);

    public static bool IsRegularFile(string path)
    {
        if (!OperatingSystem.IsMacOS()) return true;
        try
        {
            var buffer = new byte[512];
            if (stat(path, buffer) != 0) return true;
            return (BitConverter.ToUInt16(buffer, 4) & S_IFMT) == S_IFREG;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return true;
        }
    }
}
