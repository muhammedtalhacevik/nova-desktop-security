namespace Nova.Core;

public static class AppPaths
{
    public const string AppFolderName = "NovaDesktopSecurity";

    private static string? _root;

    public static string Root
    {
        get
        {
            if (_root is null)
            {
                var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (OperatingSystem.IsMacOS())
                    baseDir = Path.Combine(Home, "Library", "Application Support");
                _root = Path.Combine(baseDir, AppFolderName);
                Directory.CreateDirectory(_root);
            }
            return _root;
        }
    }

    public static void OverrideRoot(string path)
    {
        _root = path;
        Directory.CreateDirectory(path);
    }

    public static string Home => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public static string Quarantine => Ensure(Path.Combine(Root, "Quarantine"));
    public static string Signatures => Ensure(Path.Combine(Root, "Signatures"));
    public static string Data => Ensure(Path.Combine(Root, "Data"));
    public static string Reports => Ensure(Path.Combine(Root, "Reports"));
    public static string Cache => Ensure(Path.Combine(Root, "Cache"));

    public static string Downloads => Path.Combine(Home, "Downloads");
    public static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) is { Length: > 0 } d ? d : Path.Combine(Home, "Desktop");
    public static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) is { Length: > 0 } d ? d : Path.Combine(Home, "Documents");

    private static string Ensure(string p)
    {
        Directory.CreateDirectory(p);
        return p;
    }
}
