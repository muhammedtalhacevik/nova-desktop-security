using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Nova.Desktop.ViewModels;

public abstract class ViewModelBase : ObservableObject
{
    protected static void OnUi(Action action)
    {
        if (Dispatcher.UIThread.CheckAccess()) action();
        else Dispatcher.UIThread.Post(action);
    }
}

public abstract class PageViewModel : ViewModelBase
{
    public abstract string Title { get; }

    public virtual void OnNavigatedTo() { }
}

public static class Format
{
    public static string Ago(DateTimeOffset? time)
    {
        if (time is null) return "Hiç";
        var d = DateTimeOffset.Now - time.Value;
        if (d.TotalSeconds < 60) return "Az önce";
        if (d.TotalMinutes < 60) return $"{(int)d.TotalMinutes} dk önce";
        if (d.TotalHours < 24) return $"{(int)d.TotalHours} saat önce";
        if (d.TotalDays < 7) return $"{(int)d.TotalDays} gün önce";
        return time.Value.ToString("dd.MM.yyyy");
    }

    public static string Bytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        var i = 0;
        while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {units[i]}";
    }

    public static string Duration(TimeSpan t) =>
        t.TotalHours >= 1 ? $"{(int)t.TotalHours} sa {t.Minutes} dk" :
        t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes} dk {t.Seconds} sn" :
        $"{Math.Max(0, t.Seconds)} sn";

    public static string ShortPath(string path, int max = 90)
    {
        if (path.Length <= max) return path;
        var file = Path.GetFileName(path);
        var keep = Math.Max(10, max - file.Length - 4);
        return path[..Math.Min(keep, path.Length)] + "…" + Path.DirectorySeparatorChar + file;
    }
}
