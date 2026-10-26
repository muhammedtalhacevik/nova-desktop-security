using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed partial class UrlHistoryItem(UrlCheckResult result, WebSafetyViewModel owner) : ObservableObject
{
    public UrlCheckResult Result { get; } = result;
    public string Host => Result.Host;
    public string Url => Result.NormalizedUrl;
    public string TimeText => Format.Ago(Result.CheckedAt);
    public string VerdictText => WebSafetyViewModel.NameFor(Result.Verdict);
    public string Tone => WebSafetyViewModel.ToneFor(Result.Verdict);

    [RelayCommand]
    private void Show() => owner.Display(Result);
}

public sealed partial class WebSafetyViewModel : PageViewModel
{
    private readonly NovaCore _core;
    private CancellationTokenSource? _cts;

    public WebSafetyViewModel(NovaCore core)
    {
        _core = core;
        LoadHistory();
    }

    public override string Title => "Web Güvenliği";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckCommand))]
    private string _url = "";

    [ObservableProperty] private bool _isChecking;
    [ObservableProperty] private bool _hasResult;
    [ObservableProperty] private string? _error;
    [ObservableProperty] private string _verdictText = "";
    [ObservableProperty] private string _verdictSub = "";
    [ObservableProperty] private string _verdictTone = Tone.Success;
    [ObservableProperty] private MaterialIconKind _verdictIcon = MaterialIconKind.ShieldCheck;
    [ObservableProperty] private string _host = "";
    [ObservableProperty] private string _checkedUrl = "";
    [ObservableProperty] private int _score;
    [ObservableProperty] private string _scoreText = "";
    [ObservableProperty] private bool _hasSignals;
    [ObservableProperty] private bool _hasRedirects;
    [ObservableProperty] private bool _hasHistory;
    [ObservableProperty] private string _providerSummary = "";

    public bool HasError => !string.IsNullOrEmpty(Error);
    partial void OnErrorChanged(string? value) => OnPropertyChanged(nameof(HasError));

    public ObservableCollection<StatusRow> Intel { get; } = [];
    public ObservableCollection<InfoPair> Facts { get; } = [];
    public ObservableCollection<StatusRow> Signals { get; } = [];
    public ObservableCollection<string> Redirects { get; } = [];
    public ObservableCollection<UrlHistoryItem> History { get; } = [];

    public override void OnNavigatedTo()
    {
        var providers = new List<string> { "VirusTotal", "OpenPhish" };
        if (_core.Settings.Current.GoogleSafeBrowsingApiKey.Length > 0) providers.Insert(0, "Google Safe Browsing");
        ProviderSummary = "Tehdit istihbaratı: " + string.Join(" · ", providers);
    }

    private bool CanCheck() => !string.IsNullOrWhiteSpace(Url) && !IsChecking;

    [RelayCommand(CanExecute = nameof(CanCheck))]
    private async Task Check()
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        IsChecking = true;
        Error = null;
        CheckCommand.NotifyCanExecuteChanged();
        try
        {
            var result = await Task.Run(() => _core.Web.CheckAsync(Url, _cts.Token));
            if (result.Error is not null)
            {
                Error = result.Error;
                HasResult = false;
                return;
            }
            Display(result);
            LoadHistory();
            if (result.Verdict == UrlVerdict.Dangerous)
                AppServices.Toasts.Show("Tehlikeli web sitesi", $"{result.Host} adresini açmayın.", Tone.Danger, force: true);
        }
        catch (OperationCanceledException)
        {
            Error = "Kontrol zaman aşımına uğradı. Lütfen tekrar deneyin.";
        }
        catch (Exception ex)
        {
            Error = ex.Message;
        }
        finally
        {
            IsChecking = false;
            CheckCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand]
    private async Task Paste()
    {
        if (AppServices.MainWindow?.Clipboard is { } cb && await cb.GetTextAsync() is { Length: > 0 } text)
            Url = text.Trim();
    }

    [RelayCommand]
    private void ClearHistory()
    {
        _core.Web.ClearHistory();
        LoadHistory();
    }

    public void Display(UrlCheckResult r)
    {
        Error = null;
        HasResult = true;
        Host = r.Host;
        CheckedUrl = r.NormalizedUrl;
        Score = 100 - r.RiskScore;
        ScoreText = $"{100 - r.RiskScore}/100";
        VerdictText = NameFor(r.Verdict);
        VerdictTone = ToneFor(r.Verdict);
        VerdictIcon = r.Verdict switch
        {
            UrlVerdict.Dangerous => MaterialIconKind.ShieldAlert,
            UrlVerdict.Suspicious => MaterialIconKind.AlertOutline,
            UrlVerdict.Safe => MaterialIconKind.ShieldCheck,
            _ => MaterialIconKind.HelpCircleOutline
        };
        VerdictSub = r.Verdict switch
        {
            UrlVerdict.Dangerous => "Bu siteyi açmayın ve bilgilerinizi girmeyin. Tehdit istihbaratı veya güçlü risk sinyalleri zararlı olduğunu gösteriyor.",
            UrlVerdict.Suspicious => "Bu bağlantıda dikkat edilmesi gereken işaretler var. Kişisel bilgi veya parola girmeden önce adresi doğrulayın.",
            _ => "Belirgin bir risk bulunamadı. Yine de yalnızca beklediğiniz sitelerde bilgi paylaşın."
        };

        Intel.Clear();
        foreach (var i in r.Intel)
            Intel.Add(new StatusRow(i.Provider, i.Summary,
                !i.Checked ? Tone.Neutral : i.Flagged ? Tone.Danger : Tone.Success,
                !i.Checked ? MaterialIconKind.MinusCircleOutline : i.Flagged ? MaterialIconKind.AlertOctagon : MaterialIconKind.CheckCircleOutline));

        Facts.Clear();
        Facts.Add(new("Bağlantı", r.NormalizedUrl.StartsWith("https", StringComparison.OrdinalIgnoreCase) ? "HTTPS (şifreli)" : "HTTP (şifresiz)", MaterialIconKind.Lock));
        if (r.CertificateValid is { } valid)
            Facts.Add(new("SSL sertifikası", valid ? "Geçerli" : "Geçersiz / doğrulanamadı", valid ? MaterialIconKind.ShieldCheckOutline : MaterialIconKind.ShieldOffOutline));
        if (r.CertificateIssuer is { } issuer) Facts.Add(new("Sertifikayı veren", issuer, MaterialIconKind.CertificateOutline));
        if (r.CertificateExpires is { } exp) Facts.Add(new("Sertifika bitişi", exp.ToString("dd.MM.yyyy"), MaterialIconKind.CalendarClock));
        if (r.ResolvedIps.Count > 0) Facts.Add(new("IP adresi", string.Join(", ", r.ResolvedIps.Take(3)), MaterialIconKind.IpNetworkOutline));
        if (r.HttpStatus is { } st) Facts.Add(new("HTTP yanıtı", st.ToString(), MaterialIconKind.ServerNetwork));
        if (r.DomainRegisteredAt is { } reg) Facts.Add(new("Alan adı kaydı", $"{reg:dd.MM.yyyy} ({(int)(DateTimeOffset.Now - reg).TotalDays / 365} yıl)", MaterialIconKind.CalendarStart));
        if (r.Registrar is { } registrar) Facts.Add(new("Kayıt şirketi", registrar, MaterialIconKind.Domain));
        Facts.Add(new("Ana alan adı", r.RegistrableDomain, MaterialIconKind.Web));

        Signals.Clear();
        foreach (var s in r.Signals.OrderByDescending(s => s.Severity))
            Signals.Add(new StatusRow(s.Title, s.Detail, Tone.FromSeverity(s.Severity),
                s.Severity >= ThreatSeverity.High ? MaterialIconKind.AlertOctagonOutline
                : s.Severity == ThreatSeverity.Info ? MaterialIconKind.InformationOutline
                : MaterialIconKind.AlertCircleOutline));
        HasSignals = Signals.Count > 0;

        Redirects.Clear();
        if (r.RedirectChain.Count > 1)
            foreach (var u in r.RedirectChain) Redirects.Add(u);
        HasRedirects = Redirects.Count > 0;
    }

    private void LoadHistory()
    {
        History.Clear();
        foreach (var h in _core.Web.History.Take(8)) History.Add(new UrlHistoryItem(h, this));
        HasHistory = History.Count > 0;
    }

    public static string NameFor(UrlVerdict v) => v switch
    {
        UrlVerdict.Dangerous => "Tehlikeli",
        UrlVerdict.Suspicious => "Şüpheli",
        UrlVerdict.Safe => "Güvenli görünüyor",
        _ => "Belirlenemedi"
    };

    public static string ToneFor(UrlVerdict v) => v switch
    {
        UrlVerdict.Dangerous => Tone.Danger,
        UrlVerdict.Suspicious => Tone.Warning,
        UrlVerdict.Safe => Tone.Success,
        _ => Tone.Neutral
    };
}
