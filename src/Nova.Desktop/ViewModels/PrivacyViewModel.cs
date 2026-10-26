using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Core.Services.Platform;
using Nova.Core.Services.Privacy;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed partial class StartupItemViewModel : ObservableObject
{
    private readonly StartupAppsService _service;
    private bool _reverting;

    public StartupItemViewModel(StartupItem item, StartupAppsService service)
    {
        Item = item;
        _service = service;
        _enabled = item.Enabled;
    }

    public StartupItem Item { get; }
    public string Name => Item.Name;
    public string Initial => Item.Name.Length > 0 ? Item.Name[..1].ToUpperInvariant() : "?";
    public Avalonia.Media.IBrush Glow => Controls.Glow.ForTone(Tone);

    [ObservableProperty] private Avalonia.Media.Imaging.Bitmap? _icon;
    public bool HasIcon => Icon is not null;
    partial void OnIconChanged(Avalonia.Media.Imaging.Bitmap? value) => OnPropertyChanged(nameof(HasIcon));
    public string Publisher => Item.Publisher ?? "Bilinmeyen yayıncı";
    public string Command => Item.Command;
    public string Location => Item.Location;
    public bool CanToggle => Item.CanToggle;
    public string ToggleHint => Item.CanToggle ? (Item.RequiresAdmin ? "Yönetici izni gerekebilir" : "") : "Bu öğe Nova tarafından değiştirilemez";
    public string Warnings => string.Join(" ", Item.Warnings);
    public bool HasWarnings => Item.Warnings.Count > 0;
    public string Tone => HasWarnings ? Controls.Tone.Warning : Item.IsSigned == true ? Controls.Tone.Success : Controls.Tone.Accent;
    public string SignedText => Item.IsSigned switch { true => "İmzalı", false => "İmzasız", _ => "İmza bilinmiyor" };
    public string SignedTone => Item.IsSigned switch { true => Controls.Tone.Success, false => Controls.Tone.Warning, _ => Controls.Tone.Neutral };

    [ObservableProperty] private bool _enabled;

    partial void OnEnabledChanged(bool value)
    {
        if (_reverting) return;
        _ = ApplyAsync(value);
    }

    private async Task ApplyAsync(bool value)
    {
        var r = await _service.SetEnabledAsync(Item, value);
        AppServices.Toasts.Show(r.Success ? "Başlangıç ayarı değişti" : "Değiştirilemedi", r.Message, r.Success ? Controls.Tone.Success : Controls.Tone.Danger, force: true);
        if (!r.Success)
        {
            _reverting = true;
            Enabled = !value;
            _reverting = false;
        }
        else
        {
            AppServices.Core.Events.Add(EventCategory.Privacy, ThreatSeverity.Info, value ? "Başlangıç öğesi etkinleştirildi" : "Başlangıç öğesi devre dışı bırakıldı", Item.Name);
        }
    }

    [RelayCommand]
    private void Reveal()
    {
        if (Item.ExecutablePath is { } p && (File.Exists(p) || Directory.Exists(p))) ProcessRunner.Reveal(p);
        else if (Item.SourceKey is { } src && File.Exists(src)) ProcessRunner.Reveal(src);
    }

    [RelayCommand]
    private async Task Scan()
    {
        if (Item.ExecutablePath is { } p && File.Exists(p))
        {
            AppServices.Shell.Navigate("scan");
            await AppServices.Shell.Scan.ScanPathsAsync([p]);
        }
    }
}

public sealed class PermissionAppViewModel(PermissionApp app)
{
    public string Name => app.AppName;
    public string Path => app.AppPath ?? "";
    public bool HasPath => !string.IsNullOrEmpty(app.AppPath);
    public string AllowedText => app.Allowed ? "İzinli" : "Reddedildi";
    public string AllowedTone => app.Allowed ? Tone.Accent : Tone.Neutral;
    public string LastUsedText => app.LastUsed is { } t ? $"Son kullanım: {Format.Ago(t)}" : "Kullanım kaydı yok";
    public bool InUse => app.InUse;
}

public sealed partial class PermissionGroupViewModel(PermissionGroup group) : ObservableObject
{
    public string Title => group.Title;
    public MaterialIconKind Icon => Enum.TryParse<MaterialIconKind>(group.Icon, out var k) ? k : MaterialIconKind.ShieldOutline;
    public IReadOnlyList<PermissionAppViewModel> Apps { get; } = group.Apps.Select(a => new PermissionAppViewModel(a)).ToList();
    public bool HasApps => Apps.Count > 0;
    public string CountText => Apps.Count == 0 ? "Uygulama yok" : $"{Apps.Count(a => a.AllowedText == "İzinli")} izinli / {Apps.Count} uygulama";
    public bool InUse => group.Apps.Any(a => a.InUse);
    public string GlobalText => group.GloballyAllowed switch { true => "Açık", false => "Kapalı", _ => "" };
    public bool HasGlobal => group.GloballyAllowed is not null;
    public string GlobalTone => group.GloballyAllowed == true ? Controls.Tone.Success : Controls.Tone.Neutral;
    public string Tone => InUse ? Controls.Tone.Danger : Controls.Tone.Accent;

    [ObservableProperty] private bool _isExpanded;

    [RelayCommand]
    private void Toggle() => IsExpanded = !IsExpanded;

    [RelayCommand]
    private void OpenSettings() => PermissionsService.OpenSettings(group);
}

public sealed partial class PrivacyViewModel(NovaCore core) : PageViewModel
{
    private bool _loaded;

    public override string Title => "Gizlilik ve Başlangıç";

    [ObservableProperty] private int _selectedTab;
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private int _enabledCount;
    [ObservableProperty] private int _warningCount;
    [ObservableProperty] private string? _permissionNote;
    [ObservableProperty] private bool _permissionsLimited;
    [ObservableProperty] private int _inUseCount;

    public bool IsMac => OperatingSystem.IsMacOS();
    public bool HasPermissionNote => !string.IsNullOrEmpty(PermissionNote);
    partial void OnPermissionNoteChanged(string? value) => OnPropertyChanged(nameof(HasPermissionNote));

    public ObservableCollection<StartupItemViewModel> StartupItems { get; } = [];
    public ObservableCollection<PermissionGroupViewModel> Permissions { get; } = [];

    public override void OnNavigatedTo()
    {
        if (!_loaded) RefreshCommand.Execute(null);
    }

    [RelayCommand]
    private async Task Refresh()
    {
        if (IsLoading) return;
        _loaded = true;
        IsLoading = true;
        try
        {
            var itemsTask = core.Startup.GetItemsAsync();
            var permsTask = core.Permissions.GetReportAsync();
            var items = await itemsTask;
            var perms = await permsTask;

            StartupItems.Clear();
            foreach (var i in items.OrderByDescending(i => i.Warnings.Count).ThenBy(i => i.Name))
                StartupItems.Add(new StartupItemViewModel(i, core.Startup));
            UpdateCounts();
            _ = LoadIconsAsync(StartupItems.ToList());

            Permissions.Clear();
            foreach (var g in perms.Groups.OrderByDescending(g => g.Apps.Any(a => a.InUse)).ThenByDescending(g => g.Apps.Count))
                Permissions.Add(new PermissionGroupViewModel(g));
            InUseCount = perms.Groups.Sum(g => g.Apps.Count(a => a.InUse));
            PermissionNote = perms.Note;
            PermissionsLimited = perms.Limited;
            if (Permissions.FirstOrDefault(p => p.HasApps) is { } first) first.IsExpanded = true;
        }
        catch (Exception ex)
        {
            AppServices.Toasts.Show("Liste yüklenemedi", ex.Message, Tone.Danger, force: true);
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task LoadIconsAsync(List<StartupItemViewModel> items)
    {
        foreach (var item in items)
        {
            var bytes = await Task.Run(() => core.Icons.GetIconPngForFile(item.Item.ExecutablePath));
            if (bytes is null) continue;
            try { item.Icon = new Avalonia.Media.Imaging.Bitmap(new MemoryStream(bytes)); }
            catch (Exception) { /* keep the letter */ }
        }
    }

    [RelayCommand]
    private async Task LoadLoginItems()
    {
        var items = await StartupAppsService.GetMacLoginItemsAsync(CancellationToken.None);
        foreach (var i in items.Where(i => StartupItems.All(s => s.Item.Id != i.Id)))
            StartupItems.Add(new StartupItemViewModel(i, core.Startup));
        UpdateCounts();
        if (items.Count == 0)
            AppServices.Toasts.Show("Oturum açma öğeleri", "Öğe bulunamadı veya Otomasyon izni verilmedi.", Tone.Warning, force: true);
    }

    [RelayCommand]
    private void OpenStartupSettings() =>
        ProcessRunner.Open(OperatingSystem.IsMacOS() ? "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" : "ms-settings:startupapps");

    [RelayCommand]
    private void OpenFullDiskAccess() =>
        ProcessRunner.Open("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles");

    private void UpdateCounts()
    {
        TotalCount = StartupItems.Count;
        EnabledCount = StartupItems.Count(i => i.Enabled);
        WarningCount = StartupItems.Count(i => i.HasWarnings);
        Summary = $"{TotalCount} başlangıç öğesi · {EnabledCount} etkin · {WarningCount} uyarı";
    }
}
