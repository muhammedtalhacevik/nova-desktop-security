using Nova.Core.Models;
using Nova.Core.Storage;

namespace Nova.Core.Services;

public sealed class SettingsService
{
    private readonly JsonStore<AppSettings> _store = new("settings.json");

    public SettingsService()
    {
        Current = _store.Load();
    }

    public AppSettings Current { get; }

    public event EventHandler? Changed;

    public void Save()
    {
        _store.Save(Current);
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Update(Action<AppSettings> change)
    {
        change(Current);
        Save();
    }
}

public sealed class EventLogService
{
    private const int MaxEvents = 500;
    private readonly JsonStore<List<SecurityEvent>> _store = new("events.json");
    private readonly List<SecurityEvent> _events;
    private readonly object _gate = new();

    public EventLogService()
    {
        _events = _store.Load();
    }

    public event EventHandler<SecurityEvent>? EventAdded;
    public event EventHandler? Changed;

    public IReadOnlyList<SecurityEvent> Events
    {
        get { lock (_gate) return _events.OrderByDescending(e => e.Timestamp).ToList(); }
    }

    public int UnreadCount
    {
        get { lock (_gate) return _events.Count(e => !e.IsRead); }
    }

    public SecurityEvent Add(EventCategory category, ThreatSeverity severity, string title, string message)
    {
        var ev = new SecurityEvent { Category = category, Severity = severity, Title = title, Message = message };
        lock (_gate)
        {
            _events.Add(ev);
            if (_events.Count > MaxEvents)
                _events.RemoveRange(0, _events.Count - MaxEvents);
            _store.Save(_events);
        }
        EventAdded?.Invoke(this, ev);
        Changed?.Invoke(this, EventArgs.Empty);
        return ev;
    }

    public void MarkAllRead()
    {
        lock (_gate)
        {
            foreach (var e in _events) e.IsRead = true;
            _store.Save(_events);
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Remove(Guid id)
    {
        lock (_gate)
        {
            _events.RemoveAll(e => e.Id == id);
            _store.Save(_events);
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Clear()
    {
        lock (_gate)
        {
            _events.Clear();
            _store.Save(_events);
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }
}

public sealed class ScanHistoryService
{
    private const int MaxSessions = 200;
    private readonly JsonStore<List<ScanSession>> _store = new("scan-history.json");
    private readonly List<ScanSession> _sessions;
    private readonly object _gate = new();

    public ScanHistoryService()
    {
        _sessions = _store.Load();
        foreach (var s in _sessions.Where(s => s.Status == ScanStatus.Running))
        {
            s.Status = ScanStatus.Failed;
            s.Error ??= "Uygulama tarama sırasında kapandı.";
        }
    }

    public event EventHandler? Changed;

    public IReadOnlyList<ScanSession> Sessions
    {
        get { lock (_gate) return _sessions.OrderByDescending(s => s.StartedAt).ToList(); }
    }

    public ScanSession? Last
    {
        get { lock (_gate) return _sessions.Where(s => s.Type != ScanType.RealTime).MaxBy(s => s.StartedAt); }
    }

    public long TotalFilesScanned
    {
        get { lock (_gate) return _sessions.Sum(s => s.FilesScanned); }
    }

    public int TotalThreats
    {
        get { lock (_gate) return _sessions.Sum(s => s.ThreatCount); }
    }

    public IReadOnlyList<ThreatDetection> UnresolvedThreats
    {
        get
        {
            lock (_gate)
                return _sessions.SelectMany(s => s.Threats)
                    .Where(t => t.Action is ThreatAction.None or ThreatAction.Failed && File.Exists(t.FilePath))
                    .ToList();
        }
    }

    public void Upsert(ScanSession session)
    {
        lock (_gate)
        {
            var idx = _sessions.FindIndex(s => s.Id == session.Id);
            if (idx >= 0) _sessions[idx] = session;
            else _sessions.Add(session);
            if (_sessions.Count > MaxSessions)
                _sessions.RemoveRange(0, _sessions.Count - MaxSessions);
            _store.Save(_sessions);
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void ThreatUpdated(ThreatDetection threat)
    {
        lock (_gate)
        {
            foreach (var t in _sessions.SelectMany(s => s.Threats).Where(t => t.Id == threat.Id && !ReferenceEquals(t, threat)))
            {
                t.Action = threat.Action;
                t.QuarantineId = threat.QuarantineId;
            }
            _store.Save(_sessions);
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Remove(Guid id)
    {
        lock (_gate)
        {
            _sessions.RemoveAll(s => s.Id == id);
            _store.Save(_sessions);
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Clear()
    {
        lock (_gate)
        {
            _sessions.Clear();
            _store.Save(_sessions);
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }
}
