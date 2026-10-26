using Avalonia.Media;

namespace Nova.Desktop.Controls;

public static class Glow
{
    public static IBrush Accent { get; } = Make("#3B82F6");
    public static IBrush Success { get; } = Make("#22C55E");
    public static IBrush Warning { get; } = Make("#F5A524");
    public static IBrush Danger { get; } = Make("#EF4444");
    public static IBrush Neutral { get; } = Make("#A3ADC2");

    public static IBrush ForTone(string? tone) => tone switch
    {
        Tone.Success => Success,
        Tone.Warning => Warning,
        Tone.Danger => Danger,
        Tone.Neutral => Neutral,
        _ => Accent
    };

    private static IBrush Make(string color)
    {
        var c = Color.Parse(color);
        return new RadialGradientBrush
        {
            GradientStops =
            [
                new GradientStop(Color.FromArgb(0x9A, c.R, c.G, c.B), 0),
                new GradientStop(Color.FromArgb(0x4A, c.R, c.G, c.B), 0.5),
                new GradientStop(Color.FromArgb(0x00, c.R, c.G, c.B), 1)
            ]
        };
    }
}
