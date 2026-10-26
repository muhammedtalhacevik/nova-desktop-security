using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Core.Models;
using Nova.Core.Services.Breach;
using Nova.Desktop.Controls;
using Nova.Desktop.Services;

namespace Nova.Desktop.ViewModels;

public sealed class BreachItemViewModel(BreachInfo b)
{
    public string Name => b.Name;
    public string Initial => b.Name.Length > 0 ? b.Name[..1].ToUpperInvariant() : "?";
    public string Domain => b.Domain ?? "";
    public bool HasDomain => !string.IsNullOrEmpty(b.Domain);
    public string DateText => b.BreachDate is { } d ? (d.Month == 1 && d.Day == 1 ? d.Year.ToString() : d.ToString("dd.MM.yyyy")) : "Tarih bilinmiyor";
    public string RecordsText => b.Records is { } r ? $"{r:N0} hesap" : "";
    public bool HasRecords => b.Records is not null;
    public IReadOnlyList<string> DataClasses => b.DataClasses;
    public bool HasDataClasses => b.DataClasses.Count > 0;
    public string Description => b.Description is { Length: > 320 } d ? d[..320] + "…" : b.Description ?? "";
    public bool HasDescription => !string.IsNullOrWhiteSpace(b.Description);
    public bool Verified => b.Verified;
    public bool ExposesPassword => b.DataClasses.Any(c => c.Contains("Parola", StringComparison.OrdinalIgnoreCase))
                                   || b.PasswordRisk is { } risk && !risk.Contains("unknown", StringComparison.OrdinalIgnoreCase);
}

public sealed partial class BreachViewModel(NovaCore core) : PageViewModel
{
    public override string Title => "Veri İhlali";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckCommand))]
    private string _email = "";

    [ObservableProperty] private bool _isChecking;
    [ObservableProperty] private bool _hasResult;
    [ObservableProperty] private bool _found;
    [ObservableProperty] private string? _error;
    [ObservableProperty] private string _resultHeadline = "";
    [ObservableProperty] private string _resultSub = "";
    [ObservableProperty] private string _resultTone = Tone.Success;
    [ObservableProperty] private MaterialIconKind _resultIcon = MaterialIconKind.ShieldCheck;
    [ObservableProperty] private string _providerText = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckPasswordCommand))]
    private string _password = "";

    [ObservableProperty] private bool _isCheckingPassword;
    [ObservableProperty] private string? _passwordResult;
    [ObservableProperty] private string _passwordTone = Tone.Success;

    public bool HasError => !string.IsNullOrEmpty(Error);
    public bool HasPasswordResult => !string.IsNullOrEmpty(PasswordResult);
    partial void OnErrorChanged(string? value) => OnPropertyChanged(nameof(HasError));
    partial void OnPasswordResultChanged(string? value) => OnPropertyChanged(nameof(HasPasswordResult));

    public ObservableCollection<BreachItemViewModel> Breaches { get; } = [];

    public override void OnNavigatedTo()
    {
        ProviderText = core.Settings.Current.HibpApiKey.Length > 0
            ? "Sorgular Have I Been Pwned üzerinden yapılır."
            : "Sorgular XposedOrNot veri ihlali servisi üzerinden yapılır.";
    }

    private bool CanCheck() => !IsChecking && !string.IsNullOrWhiteSpace(Email);

    [RelayCommand(CanExecute = nameof(CanCheck))]
    private async Task Check()
    {
        Error = null;
        if (!BreachCheckService.IsValidEmail(Email.Trim()))
        {
            Error = "Geçerli bir e-posta adresi girin (ör. ad@ornek.com).";
            return;
        }

        IsChecking = true;
        CheckCommand.NotifyCanExecuteChanged();
        try
        {
            var r = await Task.Run(() => core.Breach.CheckEmailAsync(Email, CancellationToken.None));
            if (r.Error is not null)
            {
                Error = r.Error;
                HasResult = false;
                return;
            }

            Breaches.Clear();
            foreach (var b in r.Breaches) Breaches.Add(new BreachItemViewModel(b));
            Found = r.Found;
            HasResult = true;
            if (r.Found)
            {
                ResultHeadline = $"{r.Breaches.Count} veri ihlalinde bulundu";
                ResultSub = $"{r.Email} adresi aşağıdaki sızıntılarda yer alıyor. Parolalarınızı değiştirmeniz önerilir.";
                ResultTone = Tone.Danger;
                ResultIcon = MaterialIconKind.EmailAlert;
            }
            else
            {
                ResultHeadline = "Bilinen bir ihlal bulunamadı";
                ResultSub = $"{r.Email} adresi {r.Provider} veritabanındaki ihlallerde yer almıyor.";
                ResultTone = Tone.Success;
                ResultIcon = MaterialIconKind.EmailCheck;
            }
        }
        finally
        {
            IsChecking = false;
            CheckCommand.NotifyCanExecuteChanged();
        }
    }

    private bool CanCheckPassword() => !IsCheckingPassword && Password.Length > 0;

    [RelayCommand(CanExecute = nameof(CanCheckPassword))]
    private async Task CheckPassword()
    {
        IsCheckingPassword = true;
        CheckPasswordCommand.NotifyCanExecuteChanged();
        try
        {
            var count = await BreachCheckService.CheckPasswordAsync(Password, CancellationToken.None);
            if (count > 0)
            {
                PasswordResult = $"Bu parola sızdırılmış veri setlerinde {count:N0} kez görüldü. Hiçbir hesapta kullanmayın.";
                PasswordTone = Tone.Danger;
            }
            else
            {
                PasswordResult = "Bu parola bilinen sızıntılarda bulunamadı. Yine de her hesap için farklı parola kullanın.";
                PasswordTone = Tone.Success;
            }
        }
        catch (Exception)
        {
            PasswordResult = "Parola kontrol servisine ulaşılamadı.";
            PasswordTone = Tone.Warning;
        }
        finally
        {
            Password = "";
            IsCheckingPassword = false;
            CheckPasswordCommand.NotifyCanExecuteChanged();
        }
    }
}
