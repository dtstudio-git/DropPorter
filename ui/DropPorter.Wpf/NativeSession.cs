using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CoreJ2K;
using CoreJ2K.Configuration;

namespace DropPorter.Wpf;

internal static class Native
{
    private const string Library = "DropPorterBridge.dll";

    static Native()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, (name, _, _) =>
        {
            if (name != Library) return nint.Zero;
            // The bridge is staged next to the host, outside the single-file extraction directory.
            var hostDirectory = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
            return NativeLibrary.Load(Path.Combine(hostDirectory, "runtime", Library));
        });
    }

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern nint DD_Create(nint owner);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int DD_Destroy(nint session);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)] internal static extern int DD_Command(nint session, TransferMode mode, BridgeCommand command, string? path, int index);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int DD_Value(nint session, TransferMode mode, ValueKind kind, int field = 0);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] private static extern nint DD_Text(nint session, TransferMode mode, TextField field, int index);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int DD_Progress(nint session, TransferMode mode, out ulong processed, out ulong total);
    internal static string Text(nint session, TransferMode mode, TextField field, int index = -1) => Marshal.PtrToStringUni(DD_Text(session, mode, field, index)) ?? "";
}

public sealed record SendTargetRow(string Name, string Suffix, string FullAddress)
{
    public string AccessibleName => Suffix.Length == 0 ? Name : $"{Name} {Suffix}";

    internal static SendTargetRow Create(string label, string address)
    {
        if (address.Length != 12) return new(label, "", "");
        var fullAddress = string.Join(":", Enumerable.Range(0, 6).Select(index => address.Substring(index * 2, 2)));
        var suffix = $"[{fullAddress[^8..]}]";
        var name = label.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
            ? label[..^suffix.Length].TrimEnd() : label;
        return new(name, suffix, fullAddress);
    }
}

public sealed class TransferModel : INotifyPropertyChanged
{
    private const int ControlFieldCount = (int)TextField.ItemLabel;
    private readonly string[] text = new string[ControlFieldCount];
    private readonly bool[] enabled = new bool[ControlFieldCount];
    private int selected = -1;
    public ObservableCollection<string> Items { get; } = [];
    public ObservableCollection<SendTargetRow> Targets { get; } = [];
    public string FilePath => text[(int)TextField.FilePath];
    public string Status => text[(int)TextField.Status];
    public string Details => text[(int)TextField.Details];
    public string Peer => text[(int)TextField.Target];
    public bool HasPeer => !string.IsNullOrEmpty(Peer);
    public string Action => text[(int)TextField.PrimaryAction];
    public string Cancel => text[(int)TextField.Cancel];
    public bool CanChoose => enabled[(int)TextField.ChooseFile];
    public bool CanAct => enabled[(int)TextField.PrimaryAction];
    public bool CanCancel => enabled[(int)TextField.Cancel];
    public bool CanSelect => enabled[(int)TextField.Target];
    public bool CanRefreshTargets { get; private set; }
    public bool CanOpenFile => enabled[(int)TextField.OpenFile];
    public bool CanOpenFolder => enabled[(int)TextField.OpenFolder];
    public int Selected { get => selected; set { if (selected != value) { selected = value; Changed(nameof(Selected)); } } }
    public bool IsIncoming { get; private set; }
    public bool ShowRegular => !IsIncoming;
    public int OfferFileCount { get; private set; }
    public string OfferSize { get; private set; } = "";
    public string OfferNotificationText => $"ファイル{OfferFileCount}件を受信できます。{OfferSize}です。";
    public BitmapSource? OfferPreview { get; private set; }
    public bool HasOfferPreview => OfferPreview is not null;
    public string ResultTitle { get; private set; } = "";
    public string ResultDetail { get; private set; } = "";
    public string RestorationText { get; private set; } = "";
    public bool ShowResult => !IsIncoming && !string.IsNullOrEmpty(ResultTitle);
    public bool ShowResultDetail => !string.IsNullOrEmpty(ResultDetail);
    public bool ShowRestoration => !string.IsNullOrEmpty(RestorationText);
    public bool ShowDriverHelp { get; private set; }
    public bool ShowStatus => (!ShowResult || IsStagePending) && !string.IsNullOrEmpty(Status);
    public bool ShowReceiveStatus => !string.IsNullOrEmpty(Status) && (ShowStatus || CanCancel);
    public string SendFooterText
    {
        get
        {
            if (ShowStatus) return Status;
            if (ShowResult || !CanChoose) return "";
            if (!HasFile) return "送信中はWi-Fi接続が切断されます。";
            return CanAct ? "送信先を探してください。" : "";
        }
    }
    public bool ShowCancel => CanCancel || HasProgress || IsStagePending || IsIncoming;
    public bool HasSavedActions => HasSavedFiles && !IsIncoming;
    public bool EmphasizeReceive => !HasSavedActions;
    public bool DefaultReceiveAction => ShowRegular && EmphasizeReceive;
    public bool HasProgress { get; private set; }
    public bool IsStagePending { get; private set; }
    public bool ShowBusyRing { get; private set; }
    public bool ShowDetails => !ShowResult && !HasProgress && !IsStagePending && !IsIncoming && !string.IsNullOrEmpty(Details);
    public IReadOnlyList<string> SendFiles { get; private set; } = [];
    public string SendSelectionSize { get; private set; } = "";
    public int SendFileCount => SendFiles.Count;
    public bool HasFile => SendFiles.Count != 0;
    public bool HasNoFile => !HasFile;
    public string FilePickLabel => HasFile ? "変更" : "ファイルを選ぶ";
    public bool ShowSearchHelp { get; private set; }
    public bool ShowItems => Targets.Count > 0 && CanSelect;
    public SendTargetRow? SelectedTarget => Selected >= 0 && Selected < Targets.Count ? Targets[Selected] : null;
    public bool ShowTargetSummary => !ShowItems && (!CanChoose || ShowResult) && SelectedTarget is not null;
    public bool ShowTargetSection => CanRefreshTargets || ShowItems || ShowTargetSummary;
    public bool HasSavedFiles => Items.Count > 0;
    public double ProgressValue { get; private set; }
    public string ProgressPercent { get; private set; } = "";
    public string TransferredText { get; private set; } = "";
    public string SpeedText { get; private set; } = "";
    public string RemainingText { get; private set; } = "";
    public bool HasSpeed => SpeedText.Length != 0;
    public bool HasRemaining => RemainingText.Length != 0;
    public bool HasProgressMetrics => HasSpeed || HasRemaining;
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed(string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private const double SpeedWindowSeconds = 3;
    private string offerPreviewPath = "";
    private bool loadingOfferPreview;
    private readonly Queue<(TimeSpan At, ulong Bytes)> samples = new();
    private readonly TransferEta transferEta = new();
    internal void Refresh(nint session, TransferMode mode)
    {
        for (int i = 0; i < ControlFieldCount; i++)
        {
            text[i] = Native.Text(session, mode, (TextField)i);
            enabled[i] = Native.DD_Value(session, mode, ValueKind.ControlEnabled, i) == 1;
        }
        var indices = Enumerable.Range(0, Native.DD_Value(session, mode, ValueKind.ItemCount));
        if (mode == TransferMode.Send)
        {
            var targets = indices.Select(i => SendTargetRow.Create(
                Native.Text(session, mode, TextField.ItemLabel, i),
                Native.Text(session, mode, TextField.ItemPeerAddress, i))).ToArray();
            if (!Targets.SequenceEqual(targets)) { Targets.Clear(); foreach (var target in targets) Targets.Add(target); }
        }
        else
        {
            var items = indices.Select(i => Native.Text(session, mode, TextField.ItemLabel, i)).ToArray();
            if (!Items.SequenceEqual(items)) { Items.Clear(); foreach (var item in items) Items.Add(item); }
        }
        Selected = Native.DD_Value(session, mode, ValueKind.SelectedItem);
        IsIncoming = Native.DD_Value(session, mode, ValueKind.HasIncoming) == 1;
        ResultTitle = Native.Text(session, mode, TextField.ResultTitle);
        ResultDetail = Native.Text(session, mode, TextField.ResultDetail);
        RestorationText = Native.Text(session, mode, TextField.RestorationText);
        ShowDriverHelp = Native.DD_Value(session, mode, ValueKind.ShowDriverHelp) == 1;
        ShowSearchHelp = Native.DD_Value(session, mode, ValueKind.ShowSearchHelp) == 1;
        CanRefreshTargets = mode == TransferMode.Send && Native.DD_Value(session, mode, ValueKind.CanRefreshTargets) == 1;
        if (mode == TransferMode.Send)
        {
            var files = Enumerable.Range(0, Math.Max(0, Native.DD_Value(session, mode, ValueKind.SendFileCount)))
                .Select(i => Native.Text(session, mode, TextField.SendFilePath, i)).ToArray();
            if (!SendFiles.SequenceEqual(files)) SendFiles = files;
            SendSelectionSize = Native.Text(session, mode, TextField.SendSelectionSize);
        }
        else
        {
            OfferFileCount = IsIncoming ? Native.DD_Value(session, mode, ValueKind.OfferFileCount) : 0;
            OfferSize = IsIncoming ? Native.Text(session, mode, TextField.OfferSize) : "";
            UpdateOfferPreview(IsIncoming ? Native.Text(session, mode, TextField.OfferPreviewPath) : "");
        }
        // Native activity is independent of byte counts: a cached 99% must not
        // keep looking like data transfer while waiting for the peer or Wi-Fi.
        var activity = (TransferActivity)Native.DD_Value(session, mode, ValueKind.Activity);
        bool measurable = Native.DD_Progress(session, mode, out var processed, out var total) == 1;
        UpdateProgress(activity, measurable, processed, total);
        Changed();
    }

    private void UpdateOfferPreview(string path)
    {
        if (path == offerPreviewPath) return;
        offerPreviewPath = path;
        OfferPreview = null;
        if (path.Length != 0 && !loadingOfferPreview) _ = LoadOfferPreview();
    }

    private async Task LoadOfferPreview()
    {
        loadingOfferPreview = true;
        try
        {
            while (offerPreviewPath.Length != 0)
            {
                var path = offerPreviewPath;
                var preview = await Task.Run(() => DecodeOfferPreview(path));
                if (path != offerPreviewPath) continue;
                OfferPreview = preview;
                Changed(nameof(OfferPreview));
                Changed(nameof(HasOfferPreview));
                break;
            }
        }
        finally { loadingOfferPreview = false; }
    }

    private static BitmapSource? DecodeOfferPreview(string path)
    {
        const int maxBytes = 1024 * 1024;
        const int maxEdge = 1024;
        try
        {
            // The worker keeps a delete-on-close handle open while approval is pending.
            byte[] encoded;
            using (var file = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var length = file.Length;
                if (length is < 8 or > maxBytes) return null;
                encoded = new byte[(int)length];
                file.ReadExactly(encoded);
            }
            if (encoded.AsSpan() is [0, 0, 0, 12, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a, ..]
                or [0xff, 0x4f, 0xff, 0x51, ..])
                return DecodeJpeg2000Preview(encoded, maxEdge);

            using var stream = new MemoryStream(encoded, writable: false);
            var header = encoded.AsSpan(0, 8);
            const BitmapCreateOptions options = BitmapCreateOptions.IgnoreColorProfile;
            const BitmapCacheOption cache = BitmapCacheOption.None;
            BitmapDecoder? decoder = header switch
            {
                [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] => new PngBitmapDecoder(stream, options, cache),
                [0xff, 0xd8, 0xff, ..] => new JpegBitmapDecoder(stream, options, cache),
                [0x49, 0x49, 0x2a, 0x00, ..] or [0x4d, 0x4d, 0x00, 0x2a, ..] => new TiffBitmapDecoder(stream, options, cache),
                _ => null
            };
            if (decoder is null || decoder.Frames.Count == 0) return null;
            var frame = decoder.Frames[0];
            var width = frame.PixelWidth;
            var height = frame.PixelHeight;
            if (width is < 1 or > maxEdge || height is < 1 or > maxEdge) return null;

            var converted = new FormatConvertedBitmap(frame, PixelFormats.Pbgra32, null, 0);
            var stride = width * 4;
            var pixels = new byte[stride * height];
            converted.CopyPixels(pixels, stride, 0);
            var preview = BitmapSource.Create(width, height, 96, 96, PixelFormats.Pbgra32, null, pixels, stride);
            var query = decoder switch
            {
                JpegBitmapDecoder => "/app1/ifd/{ushort=274}",
                TiffBitmapDecoder => "/ifd/{ushort=274}",
                _ => null
            };
            Matrix transform = (query is null ? 1 : ReadOfferOrientation(frame, query)) switch
            {
                2 => new(-1, 0, 0, 1, 0, 0),
                3 => new(-1, 0, 0, -1, 0, 0),
                4 => new(1, 0, 0, -1, 0, 0),
                5 => new(0, 1, 1, 0, 0, 0),
                6 => new(0, 1, -1, 0, 0, 0),
                7 => new(0, -1, -1, 0, 0, 0),
                8 => new(0, -1, 1, 0, 0, 0),
                _ => Matrix.Identity
            };
            if (!transform.IsIdentity) preview = new TransformedBitmap(preview, new MatrixTransform(transform));
            preview.Freeze();
            return preview;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or
            NotSupportedException or InvalidOperationException or FormatException or COMException or OverflowException or
            OperationCanceledException)
        {
            return null;
        }
    }

    private static BitmapSource? DecodeJpeg2000Preview(byte[] encoded, int maxEdge)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var configuration = new J2KDecoderConfiguration()
            .WithLimits(DecoderLimits.Strict.WithMaxPixels(maxEdge * maxEdge)
                .WithMaxMemoryBytes(40L * 1024 * 1024).WithMaxTileComponents(256))
            .WithMaxDegreeOfParallelism(1)
            .WithCancellationToken(timeout.Token)
            .WithVerbose(false);
        using var image = J2kImage.FromBytes(encoded, configuration);
        var width = image.Width;
        var height = image.Height;
        var components = image.NumberOfComponents;
        if (width is < 1 || width > maxEdge || height is < 1 || height > maxEdge ||
            components is not (1 or 3 or 4))
            return null;

        var format = components switch { 1 => PixelFormats.Gray8, 3 => PixelFormats.Rgb24, _ => PixelFormats.Bgra32 };
        var stride = width * components;
        var pixels = new byte[stride * height];
        if (components == 1)
            image.ToComponentBytes(0, pixels);
        else
        {
            var plane = new byte[width * height];
            for (var component = 0; component < components; component++)
            {
                image.ToComponentBytes(component, plane);
                var channel = components == 4 && component < 3 ? 2 - component : component;
                for (var pixel = 0; pixel < plane.Length; pixel++)
                    pixels[pixel * components + channel] = plane[pixel];
            }
        }
        var bitmap = BitmapSource.Create(width, height, 96, 96, format, null, pixels, stride);
        bitmap.Freeze();
        return bitmap;
    }

    private static ushort ReadOfferOrientation(BitmapFrame frame, string query)
    {
        try
        {
            return frame.Metadata is BitmapMetadata metadata && metadata.GetQuery(query) is ushort orientation
                ? orientation : (ushort)1;
        }
        catch (Exception error) when (error is IOException or ArgumentException or InvalidOperationException or
            NotSupportedException or FormatException or COMException)
        {
            return 1;
        }
    }

    private void UpdateProgress(TransferActivity activity, bool known, ulong processed, ulong total)
    {
        IsStagePending = activity is TransferActivity.AwaitingCompletion or TransferActivity.Restoring or TransferActivity.Stopping;
        HasProgress = activity == TransferActivity.Transferring && known && total > 0;
        ShowBusyRing = activity != TransferActivity.None && !HasProgress;
        if (!HasProgress) {
            samples.Clear(); transferEta.Reset(); ProgressValue = 0;
            ProgressPercent = TransferredText = SpeedText = RemainingText = "";
            return;
        }
        var now = Stopwatch.GetElapsedTime(0);
        if (samples.Count > 0 && processed < samples.Last().Bytes) samples.Clear();
        samples.Enqueue((now, processed));
        while (samples.Count > 2 && (now - samples.Peek().At).TotalSeconds > SpeedWindowSeconds) samples.Dequeue();
        // Completion is confirmed by the peer's response, so the estimate stops at 99%.
        var percent = Math.Min(99, (int)(processed * 100 / total));
        ProgressValue = percent;
        ProgressPercent = $"{percent}%";
        TransferredText = $"{FormatBytes(processed)}/{FormatBytes(total)}";
        var remaining = transferEta.Update(now.TotalSeconds, processed, total);
        RemainingText = remaining.HasValue ? $"約{FormatDuration(remaining.Value)}" : "";
        SpeedText = "";
        var first = samples.Peek();
        var seconds = (now - first.At).TotalSeconds;
        if (seconds >= 1 && processed > first.Bytes)
        {
            var speed = (processed - first.Bytes) / seconds;
            SpeedText = $"{FormatBytes((ulong)speed)}/秒";
        }
    }

    private static string FormatBytes(ulong bytes) => bytes switch
    {
        < 1024 => $"{bytes}B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1}KiB",
        _ => $"{bytes / (1024.0 * 1024.0):F1}MiB",
    };

    private static string FormatDuration(double seconds)
    {
        var rounded = (long)Math.Ceiling(seconds);
        return rounded < 60 ? $"{rounded}秒" : $"{rounded / 60}分{rounded % 60:00}秒";
    }
}
