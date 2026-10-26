namespace Nova.Core;

internal static class BuiltInKeys
{
    public static string VirusTotal { get; } = Load("NOVA_VT_KEY", "Nova.Core.builtin-virustotal.key");

    private static string Load(string environmentVariable, string resourceName)
    {
        if (Environment.GetEnvironmentVariable(environmentVariable) is { Length: > 0 } fromEnv)
            return fromEnv.Trim();

        using var stream = typeof(BuiltInKeys).Assembly.GetManifestResourceStream(resourceName);
        if (stream is null) return "";
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim();
    }
}
