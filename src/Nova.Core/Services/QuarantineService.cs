using System.Text;
using Nova.Core.Models;
using Nova.Core.Storage;

namespace Nova.Core.Services;

public sealed record QuarantineOutcome(bool Success, string Message, QuarantineItem? Item = null);

public sealed class QuarantineService
{
    private static readonly byte[] Key = Encoding.ASCII.GetBytes("NovaDesktopSecurity::Quarantine::v1");
    private static readonly byte[] Magic = "NQF1"u8.ToArray();

    private readonly JsonStore<List<QuarantineItem>> _store = new("quarantine.json");
    private readonly List<QuarantineItem> _items;
    private readonly object _gate = new();
    private readonly SettingsService _settings;
    private readonly EventLogService _events;

    public QuarantineService(SettingsService settings, EventLogService events)
    {
        _settings = settings;
        _events = events;
        _items = _store.Load();
    }

    public event EventHandler? Changed;

    public IReadOnlyList<QuarantineItem> Items
    {
        get { lock (_gate) return _items.OrderByDescending(i => i.QuarantinedAt).ToList(); }
    }

    public int Count { get { lock (_gate) return _items.Count; } }

    public QuarantineOutcome Quarantine(ThreatDetection threat)
    {
        var path = threat.FilePath;
        if (!File.Exists(path))
        {
            threat.Action = ThreatAction.Failed;
            return new(false, "Dosya artık mevcut değil.");
        }

        var item = new QuarantineItem
        {
            OriginalPath = path,
            ThreatName = threat.ThreatName,
            Severity = threat.Severity,
            Sha256 = threat.Sha256,
            Size = threat.FileSize
        };
        item.StoredFileName = item.Id.ToString("N") + ".nqf";
        var stored = Path.Combine(AppPaths.Quarantine, item.StoredFileName);

        try
        {
            Encode(path, stored);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(stored);
            if (IsVirusBlocked(ex))
            {
                try
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                    File.Delete(path);
                    threat.Action = ThreatAction.Deleted;
                    _events.Add(EventCategory.Quarantine, threat.Severity, "Engellenen tehdit silindi", $"{Path.GetFileName(path)} — {threat.ThreatName}");
                    Changed?.Invoke(this, EventArgs.Empty);
                    return new(true, "Sistem antivirüsünün engellediği dosya silindi.");
                }
                catch (Exception) when (!File.Exists(path))
                {
                    threat.Action = ThreatAction.Deleted;
                    return new(true, "Dosya sistem antivirüsü tarafından kaldırıldı.");
                }
                catch (Exception)
                {
                    threat.Action = ThreatAction.Failed;
                    return new(false, "Dosya sistemin antivirüs yazılımı tarafından kilitlendi; sistem antivirüsü kaldıracaktır.");
                }
            }
            threat.Action = ThreatAction.Failed;
            return new(false, $"Dosya okunamadı: {ex.Message}");
        }

        try
        {
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(stored);
            threat.Action = ThreatAction.Failed;
            return new(false, $"Dosya kullanımda veya silme izni yok: {ex.Message}");
        }

        lock (_gate)
        {
            _items.Add(item);
            _store.Save(_items);
        }

        threat.Action = ThreatAction.Quarantined;
        threat.QuarantineId = item.Id;
        _events.Add(EventCategory.Quarantine, threat.Severity, "Tehdit karantinaya alındı", $"{item.FileName} — {item.ThreatName}");
        Changed?.Invoke(this, EventArgs.Empty);
        return new(true, "Dosya karantinaya alındı.", item);
    }

    public QuarantineOutcome Restore(Guid id)
    {
        QuarantineItem? item;
        lock (_gate) item = _items.FirstOrDefault(i => i.Id == id);
        if (item is null) return new(false, "Karantina kaydı bulunamadı.");

        var stored = Path.Combine(AppPaths.Quarantine, item.StoredFileName);
        if (!File.Exists(stored)) return new(false, "Karantina dosyası eksik.");

        var target = item.OriginalPath;
        if (File.Exists(target))
        {
            var dir = Path.GetDirectoryName(target)!;
            target = Path.Combine(dir, $"{Path.GetFileNameWithoutExtension(target)} (geri yüklendi){Path.GetExtension(target)}");
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            Decode(stored, target);
            File.Delete(stored);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(false, $"Geri yüklenemedi: {ex.Message}");
        }

        if (item.Sha256 is { } hash)
            _settings.Update(s => { if (!s.AllowedHashes.Contains(hash)) s.AllowedHashes.Add(hash); });

        lock (_gate)
        {
            _items.Remove(item);
            _store.Save(_items);
        }
        _events.Add(EventCategory.Quarantine, ThreatSeverity.Info, "Dosya geri yüklendi", $"{Path.GetFileName(target)} izin verilenler listesine eklendi.");
        Changed?.Invoke(this, EventArgs.Empty);
        return new(true, $"Dosya geri yüklendi: {target}", item);
    }

    public QuarantineOutcome Delete(Guid id)
    {
        QuarantineItem? item;
        lock (_gate) item = _items.FirstOrDefault(i => i.Id == id);
        if (item is null) return new(false, "Karantina kaydı bulunamadı.");

        TryDelete(Path.Combine(AppPaths.Quarantine, item.StoredFileName));
        lock (_gate)
        {
            _items.Remove(item);
            _store.Save(_items);
        }
        _events.Add(EventCategory.Quarantine, ThreatSeverity.Info, "Karantinadaki dosya silindi", item.FileName);
        Changed?.Invoke(this, EventArgs.Empty);
        return new(true, "Dosya kalıcı olarak silindi.", item);
    }

    private static void Encode(string source, string target)
    {
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write);
        output.Write(Magic);
        Transform(input, output);
    }

    private static void Decode(string source, string target)
    {
        using var input = File.OpenRead(source);
        Span<byte> magic = stackalloc byte[4];
        input.ReadExactly(magic);
        if (!magic.SequenceEqual(Magic)) throw new IOException("Geçersiz karantina dosyası.");
        using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write);
        Transform(input, output);
    }

    private static void Transform(Stream input, Stream output)
    {
        var buffer = new byte[81920];
        long offset = 0;
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (var i = 0; i < read; i++)
                buffer[i] ^= (byte)(Key[(offset + i) % Key.Length] + (byte)((offset + i) >> 8));
            output.Write(buffer, 0, read);
            offset += read;
        }
    }

    internal static bool IsVirusBlocked(Exception ex) =>
        ex.HResult is unchecked((int)0x800700E1) or unchecked((int)0x800700E2);

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
