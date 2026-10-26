using System.Security.Cryptography;
using Nova.Core;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Nova.Core.Tests;

public static class TestEnv
{
    private static readonly object Gate = new();
    private static NovaCore? _core;

    public static string Root { get; } = Path.Combine(Path.GetTempPath(), "nova-tests-" + Guid.NewGuid().ToString("N")[..8]);

    public static NovaCore Core
    {
        get
        {
            lock (Gate)
            {
                if (_core is null)
                {
                    AppPaths.OverrideRoot(Root);
                    _core = new NovaCore();
                    _core.Settings.Update(s =>
                    {
                        s.UseSystemAntimalwareInterface = false;
                        s.ScanRunningProcesses = false;
                    });
                }
                return _core;
            }
        }
    }

    private static readonly List<string> SampleDirs = [];

    static TestEnv()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            _core?.Dispose();
            foreach (var d in SampleDirs.Append(Root))
                try { Directory.Delete(d, true); } catch { }
        };
    }

    public static string NewSampleDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nova-samples-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        lock (SampleDirs) SampleDirs.Add(dir);
        return dir;
    }

    public static string Sha256(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    public static byte[] FakePe()
    {
        var b = new byte[256];
        b[0] = (byte)'M';
        b[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(b, 0x3C);
        b[0x80] = (byte)'P';
        b[0x81] = (byte)'E';
        RandomNumberGenerator.Fill(b.AsSpan(0x90));
        return b;
    }
}
