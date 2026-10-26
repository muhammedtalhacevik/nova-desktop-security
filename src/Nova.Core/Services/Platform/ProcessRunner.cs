using System.Diagnostics;
using System.Text;

namespace Nova.Core.Services.Platform;

public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Ok => ExitCode == 0;
}

public static class ProcessRunner
{
    public static async Task<ProcessResult> RunAsync(string fileName, IEnumerable<string> args, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = new Process { StartInfo = psi };
        try
        {
            if (!proc.Start()) return new(-1, "", "başlatılamadı");
        }
        catch (Exception ex)
        {
            return new(-1, "", ex.Message);
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(20));

        var stdout = proc.StandardOutput.ReadToEndAsync(cts.Token);
        var stderr = proc.StandardError.ReadToEndAsync(cts.Token);
        try
        {
            await proc.WaitForExitAsync(cts.Token);
            return new(proc.ExitCode, await stdout, await stderr);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(true); } catch { }
            return new(-1, "", "zaman aşımı");
        }
    }

    public static async Task<ProcessResult> RunStreamingAsync(string fileName, IEnumerable<string> args, Action<string> onLine,
        TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = new Process { StartInfo = psi };
        try
        {
            if (!proc.Start()) return new(-1, "", "başlatılamadı");
        }
        catch (Exception ex)
        {
            return new(-1, "", ex.Message);
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout ?? TimeSpan.FromMinutes(10));

        var all = new StringBuilder();
        var gate = new object();

        async Task Pump(StreamReader reader)
        {
            var buffer = new char[512];
            var line = new StringBuilder();
            int n;
            while ((n = await reader.ReadAsync(buffer.AsMemory(), cts.Token)) > 0)
            {
                for (var i = 0; i < n; i++)
                {
                    var c = buffer[i];
                    if (c is '\r' or '\n')
                    {
                        if (line.Length > 0)
                        {
                            var text = line.ToString();
                            line.Clear();
                            lock (gate) all.AppendLine(text);
                            onLine(text);
                        }
                    }
                    else line.Append(c);
                }
            }
            if (line.Length > 0) { var text = line.ToString(); lock (gate) all.AppendLine(text); onLine(text); }
        }

        try
        {
            await Task.WhenAll(Pump(proc.StandardOutput), Pump(proc.StandardError), proc.WaitForExitAsync(cts.Token));
            string output;
            lock (gate) output = all.ToString();
            return new(proc.ExitCode, output, "");
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(true); } catch { }
            return new(-1, "", "zaman aşımı");
        }
    }

    public static void Open(string target)
    {
        try
        {
            if (OperatingSystem.IsMacOS())
                Process.Start(new ProcessStartInfo("open", [target]) { UseShellExecute = false });
            else if (OperatingSystem.IsWindows())
                Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
            else
                Process.Start(new ProcessStartInfo("xdg-open", [target]) { UseShellExecute = false });
        }
        catch { }
    }

    public static void Reveal(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = false });
            else if (OperatingSystem.IsMacOS())
                Process.Start(new ProcessStartInfo("open", ["-R", path]) { UseShellExecute = false });
            else
                Open(Path.GetDirectoryName(path) ?? path);
        }
        catch { }
    }
}
