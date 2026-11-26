using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace DropPorter.Wpf;

// Shows the Explorer thumbnail of a file (images, videos), or its file icon when
// it has none. Extraction runs off the UI thread, as the Shell documentation requires.
public sealed class FileThumbnail : Image
{
    public static readonly DependencyProperty PathProperty = DependencyProperty.Register(
        nameof(Path), typeof(string), typeof(FileThumbnail), new PropertyMetadata(null, (d, _) => ((FileThumbnail)d).Load()));

    public string? Path
    {
        get => (string?)GetValue(PathProperty);
        set => SetValue(PathProperty, value);
    }

    private void Load()
    {
        Source = null;
        var path = Path;
        if (string.IsNullOrEmpty(path)) return;
        var scale = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var size = Math.Max(Width, Height) * (double.IsFinite(scale) ? scale : 1);
        var pixels = double.IsFinite(size) ? Math.Max((int)Math.Ceiling(size), 16) : 64;
        // Back on this control's thread; a newer path may have replaced the request.
        ShellThumbnails.LoadAsync(path, pixels).ContinueWith(task =>
            Dispatcher.BeginInvoke(() => { if (path == Path) Source = task.Result; }), TaskScheduler.Default);
    }
}

internal static class ShellThumbnails
{
    private const int CacheLimit = 256;
    private static readonly ConcurrentDictionary<(string, int, DateTime), BitmapSource?> Cache = new();
    private static readonly BlockingCollection<Action> Work = new();

    static ShellThumbnails()
    {
        // Shell items are COM objects; give them a single-threaded apartment of their own.
        var worker = new Thread(() => { foreach (var item in Work.GetConsumingEnumerable()) item(); })
        {
            IsBackground = true,
            Name = "DropPorter thumbnails",
        };
        worker.SetApartmentState(ApartmentState.STA);
        worker.Start();
    }

    internal static Task<BitmapSource?> LoadAsync(string path, int pixels)
    {
        DateTime written;
        try { written = File.GetLastWriteTimeUtc(path); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { return Task.FromResult<BitmapSource?>(null); }
        var key = (path, pixels, written);
        if (Cache.TryGetValue(key, out var cached)) return Task.FromResult(cached);
        var completion = new TaskCompletionSource<BitmapSource?>(TaskCreationOptions.RunContinuationsAsynchronously);
        Work.Add(() =>
        {
            BitmapSource? image = null;
            try { image = Extract(path, pixels); }
            catch (Exception error) when (error is COMException or ArgumentException or OutOfMemoryException) { }
            if (Cache.Count >= CacheLimit) Cache.Clear();
            Cache[key] = image;
            completion.SetResult(image);
        });
        return completion.Task;
    }

    private static BitmapSource? Extract(string path, int pixels)
    {
        var iid = typeof(IShellItemImageFactory).GUID;
        if (SHCreateItemFromParsingName(path, 0, ref iid, out var factory) != 0 || factory is null) return null;
        try
        {
            // RESIZETOFIT (0): the thumbnail, or the item's icon when there is none.
            if (factory.GetImage(new NativeSize(pixels, pixels), 0, out var bitmap) != 0 || bitmap == 0) return null;
            try { return ToBitmapSource(bitmap); }
            finally { DeleteObject(bitmap); }
        }
        finally { Marshal.ReleaseComObject(factory); }
    }

    private static BitmapSource? ToBitmapSource(nint bitmap)
    {
        if (GetObject(bitmap, Marshal.SizeOf<NativeBitmap>(), out var info) == 0 || info.Width <= 0 || info.Height <= 0) return null;
        var width = info.Width;
        var height = Math.Abs(info.Height);
        var pixels = new byte[width * height * 4];
        var header = new BitmapInfoHeader
        {
            Size = Marshal.SizeOf<BitmapInfoHeader>(), Width = width, Height = -height, // top-down rows
            Planes = 1, BitCount = 32,
        };
        var dc = CreateCompatibleDC(0);
        try
        {
            if (GetDIBits(dc, bitmap, 0, (uint)height, pixels, ref header, 0) == 0) return null;
        }
        finally { DeleteDC(dc); }
        // Thumbnails of opaque files can come without alpha; show them opaque.
        var hasAlpha = false;
        for (var i = 3; i < pixels.Length; i += 4) if (pixels[i] != 0) { hasAlpha = true; break; }
        var image = BitmapSource.Create(width, height, 96, 96, hasAlpha ? PixelFormats.Pbgra32 : PixelFormats.Bgr32,
            null, pixels, width * 4);
        image.Freeze();
        return image;
    }

    [ComImport, Guid("bcc18b79-ba16-442f-80c4-8a59c30c463b"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItemImageFactory
    {
        [PreserveSig] int GetImage(NativeSize size, int flags, out nint bitmap);
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct NativeSize(int Width, int Height);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeBitmap { public int Type, Width, Height, WidthBytes; public ushort Planes, BitsPixel; public nint Bits; }

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfoHeader
    {
        public int Size, Width, Height; public short Planes, BitCount; public int Compression, SizeImage, XPelsPerMeter, YPelsPerMeter, ClrUsed, ClrImportant;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    private static extern int SHCreateItemFromParsingName(string path, nint bindContext, ref Guid iid,
        [MarshalAs(UnmanagedType.Interface)] out IShellItemImageFactory? item);
    [DllImport("gdi32.dll")] private static extern int GetObject(nint handle, int size, out NativeBitmap bitmap);
    [DllImport("gdi32.dll")] private static extern int GetDIBits(nint dc, nint bitmap, uint start, uint lines, byte[] bits, ref BitmapInfoHeader info, uint usage);
    [DllImport("gdi32.dll")] private static extern nint CreateCompatibleDC(nint dc);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(nint dc);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(nint handle);
}
