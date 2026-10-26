using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using Nova.Desktop.Services;

namespace Nova.Desktop.Views;

public partial class ToastWindow : Window
{
    private static readonly List<ToastWindow> Open = [];
    private readonly ToastViewModel? _toast;

    public ToastWindow()
    {
        InitializeComponent();
    }

    public ToastWindow(ToastViewModel toast) : this()
    {
        _toast = toast;
        DataContext = toast;
        CloseButton.Click += (_, e) => { e.Handled = true; Close(); };
        Root.PointerPressed += (_, _) =>
        {
            Close();
            (Application.Current as App)?.ShowWindow();
            toast.OpenCommand.Execute(null);
        };
    }

    public void ShowToast()
    {
        Opened += (_, _) => Position = ComputePosition();
        Closed += (_, _) => Open.Remove(this);
        Open.Add(this);
        Show();
        DispatcherTimer.RunOnce(() => { if (IsVisible) Close(); }, TimeSpan.FromSeconds(_toast?.Tone == "danger" ? 10 : 6));
    }

    private PixelPoint ComputePosition()
    {
        var screen = Screens.Primary ?? Screens.All.FirstOrDefault();
        if (screen is null) return new PixelPoint(40, 40);
        var area = screen.WorkingArea;
        var scale = screen.Scaling;
        var w = (int)(Bounds.Width * scale);
        var h = (int)(Bounds.Height * scale);
        var stackOffset = Open.TakeWhile(t => t != this).Sum(t => (int)(t.Bounds.Height * scale));
        var top = OperatingSystem.IsMacOS()
            ? area.Y + 8 + stackOffset
            : area.Bottom - h - 8 - stackOffset;
        return new PixelPoint(area.Right - w - 8, top);
    }
}
