using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Core.Services.Platform;
using Nova.Core.Services.WindowsTools;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed partial class AuditItemViewModel(AuditCheck check)
{
    public string Title => check.Title;
    public string Detail => check.Detail;
    public string? Advice => check.Advice;
    public bool HasAdvice => !string.IsNullOrEmpty(check.Advice) && check.State is AuditState.Fail or AuditState.Warning;
    public bool HasFix => check.FixTarget is not null && check.State is AuditState.Fail or AuditState.Warning or AuditState.Info;
    public string StateText => check.State switch { AuditState.Pass => "Güvenli", AuditState.Warning => "Uyarı", AuditState.Fail => "Risk", _ => "Bilgi" };
    public string Tone => check.State switch { AuditState.Pass => Controls.Tone.Success, AuditState.Warning => Controls.Tone.Warning, AuditState.Fail => Controls.Tone.Danger, _ => Controls.Tone.Neutral };
    public MaterialIconKind Icon => check.State switch
    {
        AuditState.Pass => MaterialIconKind.CheckCircleOutline,
        AuditState.Warning => MaterialIconKind.AlertCircleOutline,
        AuditState.Fail => MaterialIconKind.AlertOctagonOutline,
        _ => MaterialIconKind.InformationOutline
    };

    [RelayCommand]
    private void Fix()
    {
        if (check.FixTarget is { } target) ProcessRunner.Open(target);
    }
}

public sealed partial class SecurityAuditViewModel(NovaCore core) : PageViewModel
{
    public override string Title => "Güvenlik Denetimi";

    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _hasReport;
    [ObservableProperty] private int _score;
    [ObservableProperty] private string _scoreText = "";
    [ObservableProperty] private string _headline = "";
    [ObservableProperty] private string _sub = "";
    [ObservableProperty] private string _tone = Controls.Tone.Success;
    [ObservableProperty] private MaterialIconKind _icon = MaterialIconKind.ShieldCheck;
    [ObservableProperty] private string _checkedAt = "";
    [ObservableProperty] private string _passText = "0";
    [ObservableProperty] private string _warnText = "0";
    [ObservableProperty] private string _failText = "0";

    public ObservableCollection<AuditItemViewModel> Items { get; } = [];

    public override void OnNavigatedTo()
    {
        if (core.Audit.LastReport is { } last && DateTimeOffset.Now - last.CheckedAt < TimeSpan.FromMinutes(5)) Show(last);
        else RunCommand.Execute(null);
    }

    [RelayCommand]
    private async Task Run()
    {
        if (IsLoading) return;
        IsLoading = true;
        try
        {
            Show(await core.Audit.RunAsync());
            core.Events.Add(EventCategory.System, ThreatSeverity.Info, "Güvenlik denetimi tamamlandı", $"Puan: {Score}/100");
        }
        catch (Exception ex)
        {
            AppServices.Toasts.Show("Denetim yapılamadı", ex.Message, Controls.Tone.Danger, force: true);
        }
        finally { IsLoading = false; }
    }

    private void Show(SecurityAuditReport r)
    {
        HasReport = true;
        Score = r.Score;
        ScoreText = $"{r.Score}/100";
        CheckedAt = $"Son denetim: {r.CheckedAt:HH:mm:ss}";
        PassText = r.Checks.Count(c => c.State == AuditState.Pass).ToString();
        WarnText = r.WarningCount.ToString();
        FailText = r.FailCount.ToString();
        (Headline, Sub, Tone, Icon) = r.FailCount > 0
            ? ($"{r.FailCount} ciddi risk", "Aşağıdaki ayarları düzeltmeniz önerilir.", Controls.Tone.Danger, MaterialIconKind.ShieldAlert)
            : r.WarningCount > 0
                ? ($"{r.WarningCount} iyileştirme önerisi", "Cihazınız büyük oranda korunuyor; birkaç ayar geliştirilebilir.", Controls.Tone.Warning, MaterialIconKind.ShieldAlertOutline)
                : ("Ayarlarınız güvenli", "Denetlenen tüm Windows güvenlik ayarları doğru yapılandırılmış.", Controls.Tone.Success, MaterialIconKind.ShieldCheck);

        Items.Clear();
        foreach (var c in r.Checks.OrderBy(c => c.State switch { AuditState.Fail => 0, AuditState.Warning => 1, AuditState.Info => 2, _ => 3 }))
            Items.Add(new AuditItemViewModel(c));
        AppServices.Shell?.NotifyStatusChanged();
    }
}

public sealed partial class CleanCategoryViewModel : ObservableObject
{
    private readonly Action _selectionChanged;

    public CleanCategoryViewModel(CleanerCategory category, Action selectionChanged)
    {
        Category = category;
        _selectionChanged = selectionChanged;
        _isSelected = category.DefaultSelected;
    }

    public CleanerCategory Category { get; }
    public string Title => Category.Title;
    public string Description => Category.Description;
    public bool NeedsAdmin => Category.NeedsAdmin;
    public MaterialIconKind Icon => Category.Id switch
    {
        "user-temp" => MaterialIconKind.FileClockOutline,
        "browser-cache" => MaterialIconKind.Web,
        "crash-reports" => MaterialIconKind.BugOutline,
        "windows-update" => MaterialIconKind.MicrosoftWindows,
        "windows-temp" => MaterialIconKind.FolderTableOutline,
        _ => MaterialIconKind.DeleteOutline
    };

    [ObservableProperty] private bool _isSelected;
    [ObservableProperty] private bool _isScanning = true;
    [ObservableProperty] private string _sizeText = "Hesaplanıyor…";
    [ObservableProperty] private string _detail = "";
    [ObservableProperty] private bool _incomplete;

    public long Bytes { get; private set; }

    partial void OnIsSelectedChanged(bool value) => _selectionChanged();

    public void SetScan(CleanScan scan)
    {
        Bytes = scan.Bytes;
        IsScanning = false;
        SizeText = Format.Bytes(scan.Bytes);
        Detail = scan.Files > 0 ? $"{scan.Files:N0} dosya" : "Temizlenecek bir şey yok";
        Incomplete = scan.MayBeIncomplete && Category.NeedsAdmin;
        _selectionChanged();
    }

    public void SetCleaned(CleanOutcome outcome)
    {
        Bytes = 0;
        IsScanning = false;
        SizeText = "Temiz";
        Detail = outcome.Skipped > 0
            ? $"{outcome.Deleted:N0} dosya silindi · {outcome.Skipped:N0} dosya kullanımda olduğu için atlandı"
            : $"{outcome.Deleted:N0} dosya silindi";
        _selectionChanged();
    }
}

public sealed partial class CleanerViewModel(NovaCore core) : PageViewModel
{
    private bool _loaded;

    public override string Title => "Temizleyici";

    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private bool _isCleaning;
    [ObservableProperty] private string _totalText = "0 B";
    [ObservableProperty] private string _selectedText = "0 B";
    [ObservableProperty] private string _selectedCountText = "";
    [ObservableProperty] private bool _hasResult;
    [ObservableProperty] private string _resultText = "";
    [ObservableProperty] private bool _showAdminBanner;
    [ObservableProperty] private bool _canClean;

    public ObservableCollection<CleanCategoryViewModel> Categories { get; } = [];

    public override void OnNavigatedTo()
    {
        ShowAdminBanner = !CleanerService.IsElevated() && core.Cleaner.Categories.Any(c => c.NeedsAdmin);
        if (!_loaded) ScanCommand.Execute(null);
    }

    [RelayCommand]
    private async Task Scan()
    {
        if (IsScanning || IsCleaning) return;
        _loaded = true;
        IsScanning = true;
        HasResult = false;
        Categories.Clear();
        foreach (var c in core.Cleaner.Categories) Categories.Add(new CleanCategoryViewModel(c, UpdateTotals));
        UpdateTotals();

        try
        {
            await Task.WhenAll(Categories.Select(async vm => vm.SetScan(await core.Cleaner.ScanAsync(vm.Category))));
        }
        catch (Exception ex)
        {
            AppServices.Toasts.Show("Tarama başarısız", ex.Message, Controls.Tone.Danger, force: true);
        }
        finally
        {
            IsScanning = false;
            UpdateTotals();
        }
    }

    private void UpdateTotals()
    {
        var ready = Categories.Where(c => !c.IsScanning).ToList();
        TotalText = Format.Bytes(ready.Sum(c => c.Bytes));
        SelectedText = Format.Bytes(ready.Where(c => c.IsSelected).Sum(c => c.Bytes));
        SelectedCountText = $"{ready.Count(c => c.IsSelected)} / {Categories.Count} kategori seçili";
        CanClean = !IsCleaning && !IsScanning && ready.Any(c => c.IsSelected && (c.Bytes > 0 || c.Category.IsRecycleBin));
    }

    partial void OnIsScanningChanged(bool value) => UpdateTotals();
    partial void OnIsCleaningChanged(bool value) => UpdateTotals();

    [RelayCommand]
    private async Task Clean()
    {
        var chosen = Categories.Where(c => c.IsSelected && !c.IsScanning).ToList();
        if (chosen.Count == 0) return;

        var recycle = chosen.Any(c => c.Category.IsRecycleBin);
        var message = $"{string.Join(", ", chosen.Select(c => c.Title))} temizlenecek (yaklaşık {SelectedText}). " +
                      (recycle ? "Geri dönüşüm kutusundaki dosyalar kalıcı olarak silinir. " : "") +
                      "Belgeleriniz, çerezleriniz ve parolalarınız silinmez.";
        if (!await ConfirmDialogViewModel.ShowAsync("Temizlik başlatılsın mı?", message, "Temizle", destructive: recycle)) return;

        IsCleaning = true;
        long freed = 0, deleted = 0, skipped = 0;
        try
        {
            foreach (var vm in chosen)
            {
                vm.IsScanning = true;
                vm.SizeText = "Temizleniyor…";
                var outcome = await core.Cleaner.CleanAsync(vm.Category);
                vm.SetCleaned(outcome);
                freed += outcome.FreedBytes; deleted += outcome.Deleted; skipped += outcome.Skipped;
            }
            HasResult = true;
            ResultText = $"{Format.Bytes(freed)} yer açıldı · {deleted:N0} dosya silindi" + (skipped > 0 ? $" · {skipped:N0} dosya kullanımda olduğu için atlandı" : "");
            core.Events.Add(EventCategory.System, ThreatSeverity.Info, "Temizlik tamamlandı", ResultText);
            AppServices.Toasts.Show("Temizlik tamamlandı", $"{Format.Bytes(freed)} yer açıldı.", Controls.Tone.Success, MaterialIconKind.Broom, force: true);
        }
        catch (Exception ex)
        {
            AppServices.Toasts.Show("Temizlik başarısız", ex.Message, Controls.Tone.Danger, force: true);
        }
        finally { IsCleaning = false; }
    }

    [RelayCommand]
    private void RestartAsAdmin()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = "--wait-for-previous --page=cleaner"
            });
            (Avalonia.Application.Current as App)?.ExitApplication();
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }
}

public sealed partial class UpdateItemViewModel(AppUpdate app, UpdaterViewModel owner) : ObservableObject
{
    public AppUpdate App { get; } = app;
    public string Name => app.Name;
    public string Id => app.Id;
    public string Versions => $"{app.CurrentVersion} → {app.AvailableVersion}";

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string _tone = Controls.Tone.Accent;
    [ObservableProperty] private bool _done;
    [ObservableProperty] private double _progress;
    [ObservableProperty] private bool _isIndeterminate = true;
    [ObservableProperty] private Avalonia.Media.Imaging.Bitmap? _icon;

    public bool HasIcon => Icon is not null;
    partial void OnIconChanged(Avalonia.Media.Imaging.Bitmap? value) => OnPropertyChanged(nameof(HasIcon));
    public string Initial => Name.Length > 0 ? Name[..1].ToUpperInvariant() : "?";
    public Avalonia.Media.IBrush Glow => Controls.Glow.Accent;

    public bool HasStatus => !string.IsNullOrEmpty(Status);
    public bool CanUpdate => !IsBusy && !Done;
    partial void OnStatusChanged(string value) => OnPropertyChanged(nameof(HasStatus));
    partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(CanUpdate));
    partial void OnDoneChanged(bool value) => OnPropertyChanged(nameof(CanUpdate));

    [RelayCommand]
    private Task Update() => owner.UpdateOneAsync(this);
}

public sealed partial class UpdaterViewModel(NovaCore core) : PageViewModel
{
    private bool _loaded;

    public override string Title => "Yazılım Güncelleyici";

    [ObservableProperty] private bool _isChecking;
    [ObservableProperty] private bool _isUpdating;
    [ObservableProperty] private string? _error;
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private bool _hasUpdates;
    [ObservableProperty] private bool _allCurrent;

    public bool HasError => !string.IsNullOrEmpty(Error);
    partial void OnErrorChanged(string? value) => OnPropertyChanged(nameof(HasError));

    public ObservableCollection<UpdateItemViewModel> Items { get; } = [];

    public override void OnNavigatedTo()
    {
        if (!_loaded) CheckCommand.Execute(null);
    }

    [RelayCommand]
    private async Task Check()
    {
        if (IsChecking || IsUpdating) return;
        _loaded = true;
        IsChecking = true;
        Error = null;
        AllCurrent = false;
        try
        {
            var result = await core.Updater.CheckAsync();
            Items.Clear();
            foreach (var u in result.Updates) Items.Add(new UpdateItemViewModel(u, this));
            Error = result.Error;
            HasUpdates = Items.Count > 0;
            AllCurrent = result.Error is null && Items.Count == 0;
            RefreshSummary();
            _ = LoadIconsAsync(Items.ToList());
        }
        catch (Exception ex) { Error = ex.Message; }
        finally { IsChecking = false; }
    }

    private void RefreshSummary() =>
        Summary = Items.Count == 0 ? "" : $"{Items.Count(i => !i.Done)} uygulama güncellenebilir";

    private async Task LoadIconsAsync(List<UpdateItemViewModel> items)
    {
        foreach (var item in items)
        {
            var bytes = await Task.Run(() => core.Icons.GetIconPng(item.Name));
            if (bytes is null) continue;
            try { item.Icon = new Avalonia.Media.Imaging.Bitmap(new MemoryStream(bytes)); }
            catch (Exception) { /* corrupt icon: keep the letter tile */ }
        }
    }

    public async Task UpdateOneAsync(UpdateItemViewModel item)
    {
        if (item.IsBusy || item.Done) return;
        item.IsBusy = true;
        item.Tone = Controls.Tone.Accent;
        item.IsIndeterminate = true;
        item.Progress = 0;
        item.Status = "Hazırlanıyor…";

        var progress = new Progress<UpdateProgress>(p =>
        {
            item.IsIndeterminate = p.Percent is null;
            if (p.Percent is { } pct) item.Progress = pct;
            item.Status = p.Percent is { } v ? $"{p.Phase} %{v:0}" : $"{p.Phase}…";
        });
        var result = await core.Updater.UpdateAsync(item.App, progress);
        item.IsBusy = false;
        item.Done = result.Success;
        item.Progress = result.Success ? 100 : item.Progress;
        item.IsIndeterminate = false;
        item.Tone = result.Success ? Controls.Tone.Success : Controls.Tone.Danger;
        item.Status = result.Success ? "Güncellendi" : result.Message;
        if (result.Success) core.Events.Add(EventCategory.System, ThreatSeverity.Info, "Uygulama güncellendi", $"{item.Name} → {item.App.AvailableVersion}");
        RefreshSummary();
    }

    [RelayCommand]
    private async Task UpdateAll()
    {
        if (IsUpdating || Items.Count == 0) return;
        if (!await ConfirmDialogViewModel.ShowAsync("Tüm uygulamalar güncellensin mi?",
                $"{Items.Count(i => !i.Done)} uygulama sırayla güncellenecek. Bazı yükleyiciler Windows'tan izin isteyebilir ve açık uygulamaları kapatmanızı gerektirebilir.", "Güncelle"))
            return;

        IsUpdating = true;
        try
        {
            foreach (var item in Items.Where(i => !i.Done).ToList()) await UpdateOneAsync(item);
            var ok = Items.Count(i => i.Done);
            AppServices.Toasts.Show("Güncelleme bitti", $"{ok} / {Items.Count} uygulama güncellendi.", ok == Items.Count ? Controls.Tone.Success : Controls.Tone.Warning, force: true);
        }
        finally { IsUpdating = false; }
    }
}
