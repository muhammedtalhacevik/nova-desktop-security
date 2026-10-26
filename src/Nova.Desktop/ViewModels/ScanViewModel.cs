using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Core.Services.Platform;
using Nova.Core.Services.Scanning;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed record EngineInfo(string Name, bool Available, string Detail)
{
    public string Tone => Available ? Controls.Tone.Success : Controls.Tone.Neutral;
}

public sealed partial class ScanViewModel : PageViewModel
{
    private readonly NovaCore _core;
    private CancellationTokenSource? _cts;
    private PauseTokenSource? _pause;

    public ScanViewModel(NovaCore core)
    {
        _core = core;
        RefreshInfo();
    }

    public override string Title => "Virüs Taraması";

    [ObservableProperty] private bool _isIdle = true;
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private bool _isFinished;
    [ObservableProperty] private bool _isPaused;

    [ObservableProperty] private string _runningTitle = "";
    [ObservableProperty] private string _runningSub = "";
    [ObservableProperty] private double _percent;
    [ObservableProperty] private double _progressAngle;
    [ObservableProperty] private bool _isIndeterminate = true;
    [ObservableProperty] private string _percentText = "";
    [ObservableProperty] private string _filesText = "0";
    [ObservableProperty] private string _discoveredText = "";
    [ObservableProperty] private string _threatsFoundText = "0";
    [ObservableProperty] private string _elapsedText = "0 sn";
    [ObservableProperty] private string _speedText = "—";
    [ObservableProperty] private string _currentFile = "";

    [ObservableProperty] private string _resultHeadline = "";
    [ObservableProperty] private string _resultSub = "";
    [ObservableProperty] private string _resultTone = Tone.Success;
    [ObservableProperty] private MaterialIconKind _resultIcon = MaterialIconKind.ShieldCheck;
    [ObservableProperty] private bool _hasThreats;
    [ObservableProperty] private bool _hasPendingThreats;
    [ObservableProperty] private string _resultFiles = "";
    [ObservableProperty] private string _resultDuration = "";
    [ObservableProperty] private string _resultData = "";
    [ObservableProperty] private string _resultThreats = "";

    [ObservableProperty] private string _signatureText = "";
    [ObservableProperty] private string _signatureUpdated = "";
    [ObservableProperty] private bool _isUpdatingSignatures;
    [ObservableProperty] private string _lastQuickText = "";
    [ObservableProperty] private string _lastFullText = "";

    public ObservableCollection<ThreatItemViewModel> Threats { get; } = [];
    public ObservableCollection<EngineInfo> Engines { get; } = [];

    public ScanSession? LastSession { get; private set; }

    public override void OnNavigatedTo() => RefreshInfo();

    private void RefreshInfo()
    {
        SignatureText = $"{_core.Signatures.HashCount:N0} hash imzası · {_core.Signatures.PatternCount} içerik imzası";
        SignatureUpdated = _core.Settings.Current.SignaturesUpdatedAt is { } u ? $"Son güncelleme: {Format.Ago(u)}" : "İmzalar henüz çevrimiçi güncellenmedi";
        LastQuickText = $"Son: {Format.Ago(_core.Settings.Current.LastQuickScanAt)}";
        LastFullText = $"Son: {Format.Ago(_core.Settings.Current.LastFullScanAt)}";

        Engines.Clear();
        Engines.Add(new("Nova İmza Motoru", true, "SHA-256 / MD5 ve içerik imzaları (MalwareBazaar akışı)"));
        Engines.Add(new("Nova Sezgisel Analiz", true, "Çift uzantı, gizlenmiş betik, sahte belge, fidye yazılımı komutları"));
        if (OperatingSystem.IsWindows())
        {
            var amsi = _core.Amsi.IsAvailable && _core.Settings.Current.UseSystemAntimalwareInterface;
            Engines.Add(new("Windows AMSI", amsi, amsi ? "Sistemin kötü amaçlı yazılım motoru (Microsoft Defender) ile çift kontrol" : "Kapalı veya kullanılamıyor"));
        }
        else
        {
            Engines.Add(new("Sistem koruması (Gatekeeper / XProtect)", true, "macOS kendi imza denetimini ayrıca uygular"));
        }
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private Task QuickScan() => RunAsync(ScanType.Quick, null);

    [RelayCommand(CanExecute = nameof(CanStart))]
    private Task FullScan() => RunAsync(ScanType.Full, null);

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task CustomScan()
    {
        var folders = await Pickers.PickFoldersAsync("Taranacak klasörleri seçin");
        if (folders.Count > 0) await RunAsync(ScanType.Custom, folders);
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task FileScan()
    {
        var files = await Pickers.PickFilesAsync("Taranacak dosyaları seçin");
        if (files.Count > 0) await RunAsync(ScanType.Custom, files);
    }

    public Task ScanPathsAsync(IReadOnlyList<string> paths) => CanStart() ? RunAsync(ScanType.Custom, paths) : Task.CompletedTask;

    private bool CanStart() => !IsRunning;

    public bool TryStartAutomated(ScanType type)
    {
        if (IsRunning || _core.Scanner.IsScanning) return false;
        AppServices.Toasts.Show("Zamanlanmış tarama başladı", $"{type.ToTurkish()} planlandığı gibi çalışıyor.", Tone.Accent, MaterialIconKind.CalendarClock,
            () => AppServices.Shell.Navigate("scan"));
        _ = RunAsync(type, null);
        return true;
    }

    public async Task ScanNewDriveAsync(string path)
    {
        for (var i = 0; i < 360 && (IsRunning || _core.Scanner.IsScanning); i++) await Task.Delay(5000);
        if (IsRunning || _core.Scanner.IsScanning || !Directory.Exists(path)) return;
        AppServices.Toasts.Show("Yeni sürücü taranıyor", $"{path} sürücüsü takıldı ve otomatik taranıyor.", Tone.Accent, MaterialIconKind.UsbFlashDrive,
            () => AppServices.Shell.Navigate("scan"), force: false);
        await RunAsync(ScanType.Custom, [path]);
    }

    private async Task RunAsync(ScanType type, IReadOnlyList<string>? targets)
    {
        if (_core.Scanner.IsScanning) return;

        _cts = new CancellationTokenSource();
        _pause = new PauseTokenSource();
        IsIdle = false;
        IsFinished = false;
        IsRunning = true;
        IsPaused = false;
        NotifyCommands();

        RunningTitle = $"{type.ToTurkish()} sürüyor";
        RunningSub = type == ScanType.Custom && targets is not null
            ? string.Join(", ", targets.Take(3).Select(Path.GetFileName)) + (targets.Count > 3 ? $" ve {targets.Count - 3} öğe daha" : "")
            : ScanTargets.Describe(type);
        Percent = 0;
        ProgressAngle = 0;
        IsIndeterminate = true;
        PercentText = "";
        FilesText = "0";
        ThreatsFoundText = "0";
        CurrentFile = "Dosyalar listeleniyor…";

        var progress = new Progress<ScanProgress>(UpdateProgress);
        ScanSession session;
        try
        {
            session = await Task.Run(() => _core.Scanner.RunScanAsync(type, targets, progress, _pause.Token, _cts.Token));
        }
        catch (Exception ex)
        {
            AppServices.Toasts.Show("Tarama başlatılamadı", ex.Message, Tone.Danger, force: true);
            IsRunning = false;
            IsIdle = true;
            NotifyCommands();
            return;
        }

        ShowResult(session);
        IsRunning = false;
        IsFinished = true;
        NotifyCommands();
        RefreshInfo();

        AppServices.Toasts.Show(
            session.Threats.Count > 0 ? $"{session.Threats.Count} tehdit bulundu" : $"{type.ToTurkish()} tamamlandı",
            session.Threats.Count > 0 ? "Ayrıntılar ve önerilen işlemler için tarama sonuçlarına bakın." : $"{session.FilesScanned:N0} dosya tarandı, cihazınız temiz.",
            session.Threats.Count > 0 ? Tone.Danger : Tone.Success,
            onClick: () => AppServices.Shell.Navigate("scan"));
    }

    private void UpdateProgress(ScanProgress p)
    {
        FilesText = p.FilesScanned.ToString("N0");
        DiscoveredText = p.EnumerationComplete ? $"/ {p.FilesDiscovered:N0}" : $"/ {p.FilesDiscovered:N0}+";
        ThreatsFoundText = p.ThreatsFound.ToString();
        ElapsedText = Format.Duration(p.Elapsed);
        SpeedText = p.Elapsed.TotalSeconds > 1 ? $"{p.FilesScanned / p.Elapsed.TotalSeconds:N0} dosya/sn" : "—";
        if (p.CurrentFile.Length > 0) CurrentFile = Format.ShortPath(p.CurrentFile, 110);
        IsIndeterminate = !p.EnumerationComplete;
        Percent = p.Percent;
        ProgressAngle = p.Percent * 3.6;
        PercentText = p.EnumerationComplete ? $"%{p.Percent:0}" : "";
    }

    private void ShowResult(ScanSession session)
    {
        LastSession = session;
        Threats.Clear();
        foreach (var t in session.Threats) Threats.Add(new ThreatItemViewModel(t, UpdateResultState));
        HasThreats = Threats.Count > 0;

        ResultFiles = session.FilesScanned.ToString("N0");
        ResultDuration = Format.Duration(session.Duration);
        ResultData = Format.Bytes(session.BytesScanned);
        ResultThreats = session.Threats.Count.ToString();
        UpdateResultState();

        if (session.Status == ScanStatus.Cancelled)
            ResultSub = $"Tarama durduruldu. {session.FilesScanned:N0} dosya tarandı.";
        else if (session.Status == ScanStatus.Failed)
            ResultSub = $"Tarama hata ile sonlandı: {session.Error}";
    }

    private void UpdateResultState()
    {
        var pending = Threats.Count(t => t.IsPending);
        HasPendingThreats = pending > 0;
        if (Threats.Count == 0)
        {
            ResultHeadline = "Tehdit bulunamadı";
            ResultSub = "Taranan konumlarda zararlı yazılım tespit edilmedi.";
            ResultTone = Tone.Success;
            ResultIcon = MaterialIconKind.ShieldCheck;
        }
        else if (pending > 0)
        {
            ResultHeadline = $"{Threats.Count} tehdit bulundu";
            ResultSub = $"{pending} tehdit işleminizi bekliyor. Karantinaya almanızı öneririz.";
            ResultTone = Tone.Danger;
            ResultIcon = MaterialIconKind.ShieldAlert;
        }
        else
        {
            ResultHeadline = "Tüm tehditler giderildi";
            ResultSub = $"{Threats.Count} tehdit karantinaya alındı veya işlendi.";
            ResultTone = Tone.Success;
            ResultIcon = MaterialIconKind.ShieldCheck;
        }
    }

    [RelayCommand]
    private void PauseResume()
    {
        if (_pause is null) return;
        if (_pause.IsPaused)
        {
            _pause.Resume();
            IsPaused = false;
            RunningTitle = RunningTitle.Replace("duraklatıldı", "sürüyor");
        }
        else
        {
            _pause.Pause();
            IsPaused = true;
            RunningTitle = RunningTitle.Replace("sürüyor", "duraklatıldı");
        }
    }

    [RelayCommand]
    private void Stop()
    {
        _pause?.Resume();
        _cts?.Cancel();
    }

    [RelayCommand]
    private void QuarantineAll()
    {
        var count = 0;
        foreach (var t in Threats.Where(t => t.IsPending).ToList())
        {
            if (_core.Quarantine.Quarantine(t.Threat).Success) count++;
            t.QuarantineCommand.NotifyCanExecuteChanged();
        }
        if (LastSession is not null) _core.History.Upsert(LastSession);
        if (LastSession is not null) ShowResult(LastSession);
        AppServices.Toasts.Show("Karantina", $"{count} dosya karantinaya alındı.", Tone.Success, force: true);
    }

    [RelayCommand]
    private async Task ExportReport()
    {
        if (LastSession is null) return;
        var path = await Pickers.SaveFileAsync("Tarama raporunu kaydet", ReportExporter.DefaultFileName(LastSession), "html", "HTML raporu");
        if (path is null) return;
        await File.WriteAllTextAsync(path, ReportExporter.ToHtml(LastSession));
        AppServices.Toasts.Show("Rapor kaydedildi", Path.GetFileName(path), Tone.Success, MaterialIconKind.FileDocumentCheckOutline,
            () => ProcessRunner.Open(path), force: true);
    }

    [RelayCommand]
    private void NewScan()
    {
        IsFinished = false;
        IsIdle = true;
    }

    [RelayCommand]
    private async Task UpdateSignatures()
    {
        if (IsUpdatingSignatures) return;
        IsUpdatingSignatures = true;
        SignatureUpdated = "İmzalar indiriliyor…";
        try
        {
            var added = await Task.Run(() => _core.UpdateSignaturesAsync(CancellationToken.None));
            AppServices.Toasts.Show("İmzalar güncellendi", $"{added:N0} yeni imza eklendi.", Tone.Success, force: true);
        }
        catch (Exception ex)
        {
            AppServices.Toasts.Show("İmza güncellemesi başarısız", ex.Message, Tone.Danger, force: true);
        }
        finally
        {
            IsUpdatingSignatures = false;
            RefreshInfo();
        }
    }

    private void NotifyCommands()
    {
        QuickScanCommand.NotifyCanExecuteChanged();
        FullScanCommand.NotifyCanExecuteChanged();
        CustomScanCommand.NotifyCanExecuteChanged();
        FileScanCommand.NotifyCanExecuteChanged();
    }
}
