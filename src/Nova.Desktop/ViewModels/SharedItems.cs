using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Core.Services.Platform;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed class EventItemViewModel(SecurityEvent ev)
{
    public SecurityEvent Event { get; } = ev;
    public string Title => Event.Title;
    public string Message => Event.Message;
    public string Category => Event.Category.ToTurkish();
    public string TimeText => Format.Ago(Event.Timestamp);
    public string FullTime => Event.Timestamp.ToString("dd.MM.yyyy HH:mm");
    public bool IsUnread => !Event.IsRead;
    public string Tone => Event.Severity >= ThreatSeverity.High ? Controls.Tone.Danger
        : Event.Severity == ThreatSeverity.Medium ? Controls.Tone.Warning
        : Event.Category is EventCategory.Scan or EventCategory.RealTime && Event.Severity == ThreatSeverity.Info ? Controls.Tone.Success
        : Controls.Tone.Accent;

    public MaterialIconKind Icon => Event.Category switch
    {
        EventCategory.Scan => MaterialIconKind.ShieldSearch,
        EventCategory.RealTime => MaterialIconKind.FlashOutline,
        EventCategory.Web => MaterialIconKind.Web,
        EventCategory.Network => MaterialIconKind.WifiLock,
        EventCategory.Breach => MaterialIconKind.EmailAlertOutline,
        EventCategory.Privacy => MaterialIconKind.ShieldAccountOutline,
        EventCategory.Quarantine => MaterialIconKind.ArchiveLockOutline,
        _ => MaterialIconKind.InformationOutline
    };
}

public sealed partial class IssueItemViewModel(ProtectionIssue issue) : ObservableObject
{
    public string Title => issue.Title;
    public string Detail => issue.Detail;
    public string Tone => Controls.Tone.FromSeverity(issue.Severity);
    public MaterialIconKind Icon => issue.Severity >= ThreatSeverity.High ? MaterialIconKind.AlertOctagonOutline : MaterialIconKind.AlertCircleOutline;

    public string ActionText => issue.ActionKey switch
    {
        "threats" => "İncele",
        "realtime" => "Aç",
        "scan" => "Tara",
        "signatures" => "Güncelle",
        "network" => "Görüntüle",
        _ => "Düzelt"
    };

    [RelayCommand]
    private void Fix() => AppServices.Shell.ResolveIssue(issue.ActionKey);
}

public sealed partial class ThreatItemViewModel : ObservableObject
{
    private readonly Action? _changed;

    public ThreatItemViewModel(ThreatDetection threat, Action? changed = null)
    {
        Threat = threat;
        _changed = changed;
    }

    public ThreatDetection Threat { get; }
    public string Name => Threat.ThreatName;
    public string FileName => Threat.FileName;
    public string FilePath => Threat.FilePath;
    public string Description => Threat.Description;
    public string Engine => Threat.Engine;
    public string SeverityText => Threat.Severity.ToTurkish();
    public string SeverityTone => Controls.Tone.FromSeverity(Threat.Severity);
    public string ActionText => Threat.Action.ToTurkish();
    public string ActionTone => Threat.Action switch
    {
        ThreatAction.Quarantined or ThreatAction.Deleted => Controls.Tone.Success,
        ThreatAction.Allowed => Controls.Tone.Neutral,
        ThreatAction.Failed => Controls.Tone.Danger,
        _ => Controls.Tone.Warning
    };
    public bool IsPending => Threat.Action is ThreatAction.None or ThreatAction.Failed;

    private void Changed()
    {
        AppServices.Core.History.ThreatUpdated(Threat);
        OnPropertyChanged(nameof(ActionText));
        OnPropertyChanged(nameof(ActionTone));
        OnPropertyChanged(nameof(IsPending));
        _changed?.Invoke();
    }

    [RelayCommand]
    private void Quarantine()
    {
        var r = AppServices.Core.Quarantine.Quarantine(Threat);
        AppServices.Toasts.Show(r.Success ? "Karantinaya alındı" : "Karantina başarısız", r.Success ? FileName : r.Message,
            r.Success ? Controls.Tone.Success : Controls.Tone.Danger, force: true);
        Changed();
    }

    [RelayCommand]
    private async Task Allow()
    {
        if (!await ConfirmDialogViewModel.ShowAsync("Dosyaya izin verilsin mi?",
                $"{FileName} bir daha tehdit olarak işaretlenmeyecek. Yalnızca dosyanın güvenli olduğundan eminseniz devam edin.", "İzin ver"))
            return;
        if (Threat.Sha256 is { } hash)
            AppServices.Core.Settings.Update(s => { if (!s.AllowedHashes.Contains(hash)) s.AllowedHashes.Add(hash); });
        else
            AppServices.Core.Settings.Update(s => { if (!s.Exclusions.Contains(FilePath)) s.Exclusions.Add(FilePath); });
        Threat.Action = ThreatAction.Allowed;
        Changed();
    }

    [RelayCommand]
    private async Task Delete()
    {
        if (!await ConfirmDialogViewModel.ShowAsync("Dosya kalıcı olarak silinsin mi?", $"{FilePath}\n\nBu işlem geri alınamaz.", "Sil", destructive: true))
            return;
        try
        {
            File.SetAttributes(FilePath, FileAttributes.Normal);
            File.Delete(FilePath);
            Threat.Action = ThreatAction.Deleted;
            AppServices.Toasts.Show("Dosya silindi", FileName, Controls.Tone.Success, force: true);
        }
        catch (Exception ex)
        {
            Threat.Action = ThreatAction.Failed;
            AppServices.Toasts.Show("Silinemedi", ex.Message, Controls.Tone.Danger, force: true);
        }
        Changed();
    }

    [RelayCommand]
    private void Reveal() => ProcessRunner.Reveal(FilePath);
}

public sealed record InfoPair(string Label, string Value, MaterialIconKind Icon = MaterialIconKind.InformationOutline);

public sealed record StatusRow(string Title, string Detail, string Tone, MaterialIconKind Icon, string? Advice = null)
{
    public bool HasAdvice => !string.IsNullOrEmpty(Advice);
}

public sealed record SecurityTip(string Title, string Text, MaterialIconKind Icon, string Tone);
