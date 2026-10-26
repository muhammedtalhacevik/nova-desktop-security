using System.Security.Cryptography;

namespace Nova.Core.Services.Scanning;

public sealed class FileSample
{
    public const int DefaultHeadBytes = 4 * 1024 * 1024;
    public const int MaxFullReadBytes = 24 * 1024 * 1024;

    public required string Path { get; init; }
    public required string Extension { get; init; }
    public required long Size { get; init; }
    public required byte[] Head { get; init; }
    public string? Sha256 { get; init; }
    public string? Md5 { get; init; }

    public bool FullyRead => Head.LongLength == Size;
    public string FileName => System.IO.Path.GetFileName(Path);

    public static FileSample Read(string path, long maxHashBytes, bool keepFullContent, CancellationToken ct)
    {
        using var fs = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.ReadWrite | FileShare.Delete,
            BufferSize = 0,
            Options = FileOptions.SequentialScan
        });

        var size = fs.Length;
        var headLimit = keepFullContent && size <= MaxFullReadBytes ? (int)size : (int)Math.Min(size, DefaultHeadBytes);
        var head = new byte[headLimit];
        var hash = size <= maxHashBytes;

        using var sha = hash ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256) : null;
        using var md5 = hash ? IncrementalHash.CreateHash(HashAlgorithmName.MD5) : null;

        var buffer = new byte[1024 * 1024];
        long pos = 0;
        int read;
        while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            if (pos < headLimit)
            {
                var n = (int)Math.Min(read, headLimit - pos);
                Buffer.BlockCopy(buffer, 0, head, (int)pos, n);
            }
            if (!hash && pos + read >= headLimit) { pos += read; break; }
            sha?.AppendData(buffer, 0, read);
            md5?.AppendData(buffer, 0, read);
            pos += read;
        }

        return new FileSample
        {
            Path = path,
            Extension = System.IO.Path.GetExtension(path).ToLowerInvariant(),
            Size = size,
            Head = head,
            Sha256 = sha is null ? null : Convert.ToHexStringLower(sha.GetHashAndReset()),
            Md5 = md5 is null ? null : Convert.ToHexStringLower(md5.GetHashAndReset())
        };
    }
}

public static class FileTypes
{
    public static readonly HashSet<string> Executable = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".ocx", ".drv",
        ".app", ".dylib", ".so", ".elf", ".bin", ".run", ".appimage", ".pkg", ".dmg", ".apk"
    };

    public static readonly HashSet<string> Script = new(StringComparer.OrdinalIgnoreCase)
    {
        ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
        ".sh", ".bash", ".zsh", ".command", ".tool", ".py", ".pl", ".rb", ".applescript", ".scpt", ".reg", ".lnk", ".url", ".inf"
    };

    public static readonly HashSet<string> Document = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlam", ".ppt", ".pptx", ".pptm",
        ".rtf", ".pdf", ".odt", ".ods", ".one", ".chm"
    };

    public static readonly HashSet<string> Archive = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".cab", ".iso", ".img", ".vhd", ".vhdx", ".jar", ".xz", ".bz2"
    };

    public static readonly HashSet<string> Decoy = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4",
        ".avi", ".mov", ".zip", ".rar", ".csv", ".rtf", ".html", ".htm"
    };

    public static bool IsRisky(string extension) =>
        Executable.Contains(extension) || Script.Contains(extension) || Document.Contains(extension) || Archive.Contains(extension)
        || extension.Length == 0;
}
