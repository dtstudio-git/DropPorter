using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Interop;

namespace DropPorter.Wpf;

internal sealed record SavedWindowPlacement(int Left, int Top, int Right, int Bottom, bool Maximized)
{
    public bool IsValid => (long)Right - Left is > 0 and <= int.MaxValue &&
                           (long)Bottom - Top is > 0 and <= int.MaxValue;
}

internal static class WindowPlacement
{
    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DropPorter", "window-placement.json");

    public static void Restore(Window window)
    {
        if (Read(SettingsPath) is not { } saved) return;
        var placement = NewPlacement();
        placement.ShowCommand = saved.Maximized ? ShowMaximized : ShowNormal;
        placement.Normal = new() { Left = saved.Left, Top = saved.Top, Right = saved.Right, Bottom = saved.Bottom };
        // Keep workspace coordinates paired with GetWindowPlacement. Windows
        // moves off-screen placements onto an available monitor on restore.
        SetWindowPlacement(new WindowInteropHelper(window).Handle, ref placement);
    }

    public static SavedWindowPlacement? Capture(Window window)
    {
        var placement = NewPlacement();
        if (!GetWindowPlacement(new WindowInteropHelper(window).Handle, ref placement)) return null;
        var bounds = placement.Normal;
        var saved = new SavedWindowPlacement(bounds.Left, bounds.Top, bounds.Right, bounds.Bottom,
            placement.ShowCommand == ShowMaximized || (placement.Flags & RestoreToMaximized) != 0);
        return saved.IsValid ? saved : null;
    }

    internal static SavedWindowPlacement? Read(string path)
    {
        try
        {
            if (new FileInfo(path).Length > 4096) return null;
            var saved = JsonSerializer.Deserialize<SavedWindowPlacement>(File.ReadAllText(path));
            return saved is { IsValid: true } ? saved : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    public static void Save(SavedWindowPlacement? saved) => Write(SettingsPath, saved);

    internal static void Write(string path, SavedWindowPlacement? saved)
    {
        if (saved is not { IsValid: true }) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(saved));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }

    private const uint ShowNormal = 1, ShowMaximized = 3, RestoreToMaximized = 2;
    private static Placement NewPlacement() => new() { Length = (uint)Marshal.SizeOf<Placement>(),
        Minimum = new() { X = -1, Y = -1 }, Maximum = new() { X = -1, Y = -1 } };
    [StructLayout(LayoutKind.Sequential)]
    private struct Point { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Rectangle { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Placement
    {
        public uint Length, Flags, ShowCommand;
        public Point Minimum, Maximum;
        public Rectangle Normal;
    }
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowPlacement(nint window, ref Placement placement);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPlacement(nint window, ref Placement placement);
}
