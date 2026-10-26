using Avalonia;
using Nova.Core.Models;

namespace Nova.Desktop.Controls;

public static class Tone
{
    public const string Success = "success";
    public const string Warning = "warning";
    public const string Danger = "danger";
    public const string Accent = "accent";
    public const string Neutral = "neutral";
    public const string Purple = "purple";
    public const string Cyan = "cyan";

    private static readonly string[] All = [Success, Warning, Danger, Accent, Neutral, Purple, Cyan];

    public static readonly AttachedProperty<string?> ClassProperty =
        AvaloniaProperty.RegisterAttached<StyledElement, string?>("Class", typeof(Tone));

    static Tone()
    {
        ClassProperty.Changed.AddClassHandler<StyledElement>((element, e) =>
        {
            foreach (var c in All) element.Classes.Remove(c);
            if (e.NewValue is string { Length: > 0 } tone) element.Classes.Add(tone);
        });
    }

    public static string? GetClass(StyledElement element) => element.GetValue(ClassProperty);
    public static void SetClass(StyledElement element, string? value) => element.SetValue(ClassProperty, value);

    public static string FromSeverity(ThreatSeverity s) => s switch
    {
        ThreatSeverity.Critical or ThreatSeverity.High => Danger,
        ThreatSeverity.Medium => Warning,
        ThreatSeverity.Low => Accent,
        _ => Neutral
    };

    public static string FromState(CheckState s) => s switch
    {
        CheckState.Pass => Success,
        CheckState.Warning => Warning,
        CheckState.Fail => Danger,
        CheckState.Info => Accent,
        _ => Neutral
    };
}
