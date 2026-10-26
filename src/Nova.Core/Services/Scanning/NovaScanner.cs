using System.Diagnostics;
using System.Threading.Channels;
using Nova.Core.Models;

namespace Nova.Core.Services.Scanning;

public sealed class NovaScanner
{
    private readonly SettingsService _settings;
    private readonly ScanHistoryService _history;
    private readonly QuarantineService _quarantine;
    private readonly EventLogService _events;
    private readonly IReadOnlyList<IScanEngine> _engines;
    private static readonly TimeSpan FileTimeout = TimeSpan.FromSeconds(45);
    private int _running;

    public NovaScanner(SettingsService settings, ScanHistoryService history, QuarantineService quarantine,
        EventLogService events, IEnumerable<IScanEngine> engines)
    {
        _settings = settings;
        _history = history;
        _quarantine = quarantine;
        _events = events;
        _engines = engines.ToList();
    }

    public bool IsScanning => Volatile.Read(ref _running) > 0;

    public IReadOnlyList<IScanEngine> Engines => _engines;

    public IEnumerable<IScanEngine> ActiveEngines => _engines.Where(e =>
        e.IsAvailable && (e is not AmsiEngine || _settings.Current.UseSystemAntimalwareInterface));

    public bool IsExcluded(string path)
    {
        if (path.StartsWith(AppPaths.Root, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var ex in _settings.Current.Exclusions)
            if (ex.Length > 0 && path.StartsWith(ex, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public ThreatDetection? ScanFile(string path, CancellationToken ct = default) => ScanFile(path, out _, ct);

    public ThreatDetection? ScanFile(string path, out long bytesRead, CancellationToken ct = default)
    {
        bytesRead = 0;
        if (IsExcluded(path) || !FileKind.IsRegularFile(path)) return null;

        var engines = ActiveEngines.ToList();
        var ext = Path.GetExtension(path).ToLowerInvariant();
        var wantsFull = engines.Any(e => e.WantsFullContent(ext));
        var maxHash = (long)_settings.Current.MaxFileSizeMb * 1024 * 1024;

        FileSample sample;
        try
        {
            sample = FileSample.Read(path, maxHash, wantsFull, ct);
        }
        catch (IOException ex) when (QuarantineService.IsVirusBlocked(ex))
        {
            return new ThreatDetection
            {
                FilePath = path,
                ThreatName = "OS.Blocked.Malware",
                Engine = OperatingSystem.IsWindows() ? "Microsoft Defender" : "Sistem koruması",
                Severity = ThreatSeverity.High,
                Description = "Sistemin antivirüs yazılımı bu dosyanın açılmasını zararlı içerik nedeniyle engelledi."
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return null;
        }

        bytesRead = Math.Min(sample.Size, Math.Max(sample.Head.LongLength, sample.Sha256 is null ? 0 : sample.Size));
        if (sample.Sha256 is not null && _settings.Current.AllowedHashes.Contains(sample.Sha256, StringComparer.OrdinalIgnoreCase))
            return null;

        foreach (var engine in engines)
        {
            ct.ThrowIfCancellationRequested();
            ThreatDetection? hit;
            try { hit = engine.Scan(sample); }
            catch (Exception) { continue; }
            if (hit is not null) return hit;
        }
        return null;
    }

    public async Task<ScanSession> RunScanAsync(ScanType type, IReadOnlyList<string>? customTargets,
        IProgress<ScanProgress>? progress, PauseToken pause, CancellationToken ct)
    {
        if (Interlocked.Increment(ref _running) > 1)
        {
            Interlocked.Decrement(ref _running);
            throw new InvalidOperationException("Zaten devam eden bir tarama var.");
        }

        var roots = type switch
        {
            ScanType.Quick => ScanTargets.Quick(),
            ScanType.Full => ScanTargets.Full(),
            _ => ScanTargets.Custom(customTargets ?? [])
        };

        var session = new ScanSession { Type = type, Targets = roots.Select(r => r.Path).ToList() };
        _history.Upsert(session);
        _events.Add(EventCategory.Scan, ThreatSeverity.Info, $"{type.ToTurkish()} başlatıldı", ScanTargets.Describe(type));

        var sw = Stopwatch.StartNew();
        long scanned = 0, discovered = 0, skipped = 0, bytes = 0;
        var enumerationDone = false;
        var current = "";
        var threatsLock = new object();

        void Report() => progress?.Report(new ScanProgress(
            Interlocked.Read(ref scanned), Interlocked.Read(ref discovered), Volatile.Read(ref enumerationDone),
            session.Threats.Count, Volatile.Read(ref current), sw.Elapsed, Interlocked.Read(ref bytes)));

        using var ticker = new Timer(_ => Report(), null, 0, 150);

        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(20_000) { SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        var workerCount = Math.Clamp(Environment.ProcessorCount / 2, 2, 6);

        var producer = Task.Run(async () =>
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (type != ScanType.Custom && _settings.Current.ScanRunningProcesses)
                {
                    foreach (var image in ScanTargets.RunningProcessImages())
                    {
                        if (IsExcluded(image) || !seen.Add(image)) continue;
                        Interlocked.Increment(ref discovered);
                        await channel.Writer.WriteAsync(image, ct);
                    }
                }

                foreach (var root in roots)
                {
                    foreach (var file in ScanTargets.Enumerate(root, IsExcluded, ct))
                    {
                        if (!seen.Add(file)) continue;
                        Interlocked.Increment(ref discovered);
                        await channel.Writer.WriteAsync(file, ct);
                    }
                }
            }
            finally
            {
                Volatile.Write(ref enumerationDone, true);
                channel.Writer.TryComplete();
            }
        }, ct);

        var workers = Enumerable.Range(0, workerCount).Select(_ => Task.Run(async () =>
        {
            await foreach (var file in channel.Reader.ReadAllAsync(ct))
            {
                await pause.WaitWhilePausedAsync(ct);
                Volatile.Write(ref current, file);

                var work = Task.Run(() => { var h = ScanFile(file, out var r, ct); return (Hit: h, Read: r); }, ct);
                if (await Task.WhenAny(work, Task.Delay(FileTimeout, ct)) != work)
                {
                    Interlocked.Increment(ref skipped);
                    Interlocked.Increment(ref scanned);
                    work.ContinueWith(static t => t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                    continue;
                }
                var (hit, read) = await work;
                Interlocked.Add(ref bytes, read);
                if (read == 0) Interlocked.Increment(ref skipped);
                Interlocked.Increment(ref scanned);
                if (hit is not null)
                    lock (threatsLock) session.Threats.Add(hit);
            }
        }, ct)).ToArray();

        try
        {
            await Task.WhenAll(workers.Append(producer));
            session.Status = ScanStatus.Completed;
        }
        catch (OperationCanceledException)
        {
            session.Status = ScanStatus.Cancelled;
        }
        catch (Exception ex)
        {
            session.Status = ScanStatus.Failed;
            session.Error = ex.Message;
        }
        finally
        {
            Interlocked.Decrement(ref _running);
        }

        session.FinishedAt = DateTimeOffset.Now;
        session.FilesScanned = scanned;
        session.FilesSkipped = skipped;
        session.BytesScanned = bytes;
        Volatile.Write(ref enumerationDone, true);

        if (_settings.Current.AutoQuarantine)
            foreach (var t in session.Threats.Where(t => t.Severity >= ThreatSeverity.High))
                _quarantine.Quarantine(t);

        _history.Upsert(session);
        if (type == ScanType.Quick || type == ScanType.Full)
            _settings.Update(s =>
            {
                if (type == ScanType.Quick) s.LastQuickScanAt = session.FinishedAt;
                else s.LastFullScanAt = session.FinishedAt;
            });

        var threatCount = session.Threats.Count;
        _events.Add(EventCategory.Scan,
            threatCount > 0 ? ThreatSeverity.High : ThreatSeverity.Info,
            $"{type.ToTurkish()} {session.Status.ToTurkish().ToLowerInvariant()}",
            threatCount > 0
                ? $"{scanned:N0} dosya tarandı, {threatCount} tehdit bulundu."
                : $"{scanned:N0} dosya tarandı, tehdit bulunamadı.");

        Report();
        return session;
    }
}
