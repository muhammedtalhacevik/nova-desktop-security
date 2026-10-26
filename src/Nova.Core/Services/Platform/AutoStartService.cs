using System.Runtime.Versioning;
using System.Security;
using Microsoft.Win32;

namespace Nova.Core.Services.Platform;

public static class AutoStartService
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "NovaDesktopSecurity";
    private const string MacLabel = "com.perasoft.novadesktopsecurity";

    private static string MacPlistPath => Path.Combine(AppPaths.Home, "Library", "LaunchAgents", MacLabel + ".plist");

    public static bool Apply(bool enable)
    {
        var exe = Environment.ProcessPath;
        if (exe is null) return false;
        try
        {
            if (OperatingSystem.IsWindows()) return ApplyWindows(enable, exe);
            if (OperatingSystem.IsMacOS()) return ApplyMac(enable, exe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
        }
        return false;
    }

    [SupportedOSPlatform("windows")]
    private static bool ApplyWindows(bool enable, string exe)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey, true);
        if (enable) key.SetValue(ValueName, $"\"{exe}\" --minimized");
        else key.DeleteValue(ValueName, false);
        return true;
    }

    private static bool ApplyMac(bool enable, string exe)
    {
        if (!enable)
        {
            if (File.Exists(MacPlistPath)) File.Delete(MacPlistPath);
            return true;
        }
        Directory.CreateDirectory(Path.GetDirectoryName(MacPlistPath)!);
        var plist = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>Label</key><string>{MacLabel}</string>
              <key>ProgramArguments</key>
              <array><string>{SecurityElement.Escape(exe)}</string><string>--minimized</string></array>
              <key>RunAtLoad</key><true/>
              <key>ProcessType</key><string>Interactive</string>
            </dict>
            </plist>
            """;
        File.WriteAllText(MacPlistPath, plist);
        return true;
    }
}
