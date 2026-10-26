using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Material.Icons;
using Nova.Core;
using Nova.Desktop.Controls;
using Nova.Desktop.ViewModels;
using Nova.Desktop.Views;

namespace Nova.Desktop.Services;

public static class AppServices
{
    public static NovaCore Core { get; set; } = null!;
    public static MainWindowViewModel Shell { get; set; } = null!;
    public static ToastService Toasts { get; } = new();
    public static Window? MainWindow { get; set; }
}

public sealed partial class ToastViewModel : ObservableObject
{
    public required string Title { get; init; }
    public required string Message { get; init; }
    public required string Tone { get; init; }
    public required MaterialIconKind Icon { get; init; }
    public Action? OnClick { get; init; }

    [RelayCommand]
    private void Open()
    {
        OnClick?.Invoke();
        AppServices.Toasts.Dismiss(this);
    }

    [RelayCommand]
    private void Close() => AppServices.Toasts.Dismiss(this);
}

public sealed class ToastService
{
    public ObservableCollection<ToastViewModel> Items { get; } = [];

    public void Show(string title, string message, string tone = Tone.Accent, MaterialIconKind? icon = null, Action? onClick = null, bool force = false)
    {
        if (!force && !AppServices.Core.Settings.Current.NotificationsEnabled) return;

        Dispatcher.UIThread.Post(() =>
        {
            var toast = new ToastViewModel
            {
                Title = title,
                Message = message,
                Tone = tone,
                Icon = icon ?? tone switch
                {
                    Tone.Danger => MaterialIconKind.ShieldAlert,
                    Tone.Warning => MaterialIconKind.AlertCircle,
                    Tone.Success => MaterialIconKind.ShieldCheck,
                    _ => MaterialIconKind.InformationOutline
                },
                OnClick = onClick
            };

            var window = AppServices.MainWindow;
            if (window is null || !window.IsVisible || window.WindowState == WindowState.Minimized)
            {
                new ToastWindow(toast).ShowToast();
                return;
            }

            Items.Insert(0, toast);
            while (Items.Count > 4) Items.RemoveAt(Items.Count - 1);
            DispatcherTimer.RunOnce(() => Items.Remove(toast), TimeSpan.FromSeconds(tone == Tone.Danger ? 9 : 5));
        });
    }

    public void Dismiss(ToastViewModel toast) => Items.Remove(toast);
}

public static class Pickers
{
    private static IStorageProvider? Provider => AppServices.MainWindow?.StorageProvider;

    public static async Task<IReadOnlyList<string>> PickFoldersAsync(string title, bool multiple = true)
    {
        if (Provider is null) return [];
        var result = await Provider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = title, AllowMultiple = multiple });
        return result.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
    }

    public static async Task<IReadOnlyList<string>> PickFilesAsync(string title, bool multiple = true)
    {
        if (Provider is null) return [];
        var result = await Provider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = title, AllowMultiple = multiple });
        return result.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
    }

    public static async Task<string?> SaveFileAsync(string title, string suggestedName, string extension, string typeName)
    {
        if (Provider is null) return null;
        var file = await Provider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
            DefaultExtension = extension,
            FileTypeChoices = [new FilePickerFileType(typeName) { Patterns = [$"*.{extension}"] }]
        });
        return file?.TryGetLocalPath();
    }

    public static async Task CopyToClipboardAsync(string text)
    {
        if (AppServices.MainWindow?.Clipboard is { } clipboard)
            await clipboard.SetTextAsync(text);
    }
}

public sealed partial class ConfirmDialogViewModel : ObservableObject
{
    private readonly TaskCompletionSource<bool> _tcs = new();

    public required string Title { get; init; }
    public required string Message { get; init; }
    public string ConfirmText { get; init; } = "Onayla";
    public string CancelText { get; init; } = "Vazgeç";
    public bool IsDestructive { get; init; }

    public Task<bool> Result => _tcs.Task;

    [RelayCommand]
    private void Confirm()
    {
        AppServices.Shell.Dialog = null;
        _tcs.TrySetResult(true);
    }

    [RelayCommand]
    private void Cancel()
    {
        AppServices.Shell.Dialog = null;
        _tcs.TrySetResult(false);
    }

    public static Task<bool> ShowAsync(string title, string message, string confirm = "Onayla", bool destructive = false)
    {
        var dlg = new ConfirmDialogViewModel { Title = title, Message = message, ConfirmText = confirm, IsDestructive = destructive };
        AppServices.Shell.Dialog = dlg;
        return dlg.Result;
    }
}
