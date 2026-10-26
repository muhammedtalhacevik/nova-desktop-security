using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Platform.Storage;
using Avalonia.VisualTree;
using Nova.Desktop.Services;

namespace Nova.Desktop.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        foreach (var region in new Control[] { SidebarHeader, TopBar })
        {
            region.PointerPressed += OnDragRegionPressed;
            region.DoubleTapped += (_, _) => ToggleMaximize();
        }

        if (OperatingSystem.IsMacOS())
            SidebarHeader.Padding = new Thickness(24, 46, 20, 26);

        DragDrop.SetAllowDrop(this, true);
        AddHandler(DragDrop.DragOverEvent, (_, e) =>
        {
            e.DragEffects = e.Data.Contains(DataFormats.Files) ? DragDropEffects.Copy : DragDropEffects.None;
        });
        AddHandler(DragDrop.DropEvent, async (_, e) =>
        {
            var paths = e.Data.GetFiles()?.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
            if (paths is { Count: > 0 })
            {
                AppServices.Shell.Navigate("scan");
                await AppServices.Shell.Scan.ScanPathsAsync(paths);
            }
        });
    }

    private void OnDragRegionPressed(object? sender, PointerPressedEventArgs e)
    {
        if (e.Source is Visual v && v.FindAncestorOfType<Button>(true) is not null) return;
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed && e.ClickCount == 1)
            BeginMoveDrag(e);
    }

    private void ToggleMaximize() =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
}
