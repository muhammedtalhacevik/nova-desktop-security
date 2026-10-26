using System.Globalization;
using Avalonia.Data.Converters;

namespace Nova.Desktop.Controls;

public sealed class InitialConverter : IValueConverter
{
    public static readonly InitialConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string { Length: > 0 } s ? char.ToUpper(s[0], culture).ToString() : "?";

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
