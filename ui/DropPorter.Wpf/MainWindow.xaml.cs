using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Navigation;
using System.Windows.Shell;
using System.Windows.Threading;
using Microsoft.Win32;

namespace DropPorter.Wpf;

public partial class MainWindow : Window
{
    public TransferModel Send { get; } = new();
    public TransferModel Receive { get; } = new();
    private nint session;
    private bool refreshing, invoking, allowClose, closeConfirmed, wasIncoming;
    private bool recoveringWifi, transferWasActive;
    private const long WifiCheckIntervalMs = 2000;
    private bool wifiConnected;
    private long nextWifiCheck;
    private string recoveryRequest = "", recoveryMessage = "";
    private (string Offer, OfferDecision Decision)? pendingReceiveDecision;
    private int resultRevision;
    private SavedWindowPlacement? placementOnClose;
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private readonly ReceiveNotifications receiveNotifications;
    public MainWindow()
    {
        InitializeComponent(); DataContext = this;
        AddHandler(Hyperlink.RequestNavigateEvent, new RequestNavigateEventHandler(OpenDriverSupport));
        receiveNotifications = new(Dispatcher, OnReceiveNotification);
        timer.Tick += (_, _) => Invoke(TransferMode.Send, BridgeCommand.Poll);
    }
    private void OpenDriverSupport(object sender, RequestNavigateEventArgs e)
    {
        e.Handled = true;
        try
        {
            using var browser = Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Win32Exception)
        {
            MessageBox.Show(this, "配布ページを開けませんでした。ブラウザーで「TP-Link」と使っているWi-Fi子機の製品名、「ドライバー」を検索してください。",
                "Drop Porter", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
    private void InitializeNative(object? sender, EventArgs e)
    {
        WindowPlacement.Restore(this);
        try
        {
            session = Native.DD_Create(new WindowInteropHelper(this).Handle);
            if (session == 0) throw new InvalidOperationException("送受信の準備を開始できませんでした。");
            receiveNotifications.Register();
            recoveryRequest = Native.Text(session, TransferMode.Send, TextField.RecoveryRequestPath);
            Refresh(); timer.Start();
        }
        catch (Exception error) when (error is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException or InvalidOperationException)
        {
            MessageBox.Show(this, "Drop Porterを起動できませんでした。配布ファイルをすべて展開し直してから開いてください。",
                "Drop Porter", MessageBoxButton.OK, MessageBoxImage.Error); Close();
        }
    }
    private void Refresh()
    {
        if (session == 0) return;
        refreshing = true;
        try { Send.Refresh(session, TransferMode.Send); Receive.Refresh(session, TransferMode.Receive); }
        finally { refreshing = false; }
        if (Receive.IsIncoming && !wasIncoming)
        {
            TransferTabs.SelectedIndex = (int)TransferMode.Receive;
            if (!IsActive) FlashTaskbar();
        }
        wasIncoming = Receive.IsIncoming;
        var offer = Receive.IsIncoming && !closeConfirmed ? Native.Text(session, TransferMode.Receive, TextField.OfferToken) : "";
        DateTimeOffset? expiration = offer.Length != 0 && DateTimeOffset.TryParseExact(Native.Text(session, TransferMode.Receive, TextField.OfferExpiration),
            "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var deadline)
            ? deadline : null;
        receiveNotifications.Update(offer, expiration, Receive.Peer, Receive.OfferNotificationText);
        var transferActive = Native.DD_Value(session, TransferMode.Send, ValueKind.TransferActive) == 1;
        if (transferWasActive && !transferActive)
        {
            recoveryRequest = Native.Text(session, TransferMode.Send, TextField.RecoveryRequestPath);
            recoveryMessage = "";
            nextWifiCheck = 0;
            RecoveryDriverHelp.Visibility = Visibility.Collapsed;
        }
        transferWasActive = transferActive;
        UpdateRecoveryNotice();
        if (Native.DD_Value(session, TransferMode.Send, ValueKind.ConfirmClose) != 1) closeConfirmed = false;
        if (!invoking)
        {
            int revision = Native.DD_Value(session, TransferMode.Send, ValueKind.ResultRevision);
            if (revision != resultRevision)
            {
                resultRevision = revision;
                TransferTabs.SelectedIndex = Native.DD_Value(session, TransferMode.Send, ValueKind.ResultTab);
                Activate();
            }
        }
        if (!invoking && Native.DD_Value(session, TransferMode.Send, ValueKind.CloseReady) == 1)
        {
            allowClose = true;
            Close();
            return;
        }
        if (!invoking && !recoveringWifi && pendingReceiveDecision is { } queued)
        {
            pendingReceiveDecision = null;
            if (!closeConfirmed && queued.Offer == offer && expiration > DateTimeOffset.UtcNow)
                Invoke(TransferMode.Receive, BridgeCommand.RespondToOffer, offer, (int)queued.Decision);
        }
    }
    private void Invoke(TransferMode mode, BridgeCommand command, string? path = null, int index = -1)
    {
        if (session == 0 || invoking || recoveringWifi) return;
        invoking = true;
        try { Native.DD_Command(session, mode, command, path, index); }
        finally { invoking = false; Refresh(); }
    }
    private void CheckWifiConnection()
    {
        wifiConnected = Native.DD_Value(session, TransferMode.Send, ValueKind.WifiConnected) == 1;
        nextWifiCheck = Environment.TickCount64 + WifiCheckIntervalMs;
    }

    private void UpdateRecoveryNotice()
    {
        var hasRequest = recoveryRequest.Length != 0;
        if (session != 0 && hasRequest && !recoveringWifi && !transferWasActive &&
            Environment.TickCount64 >= nextWifiCheck)
            CheckWifiConnection();
        RecoveryNotice.Visibility = hasRequest && (!wifiConnected || recoveringWifi)
            ? Visibility.Visible : Visibility.Collapsed;
        RecoveryButton.Visibility = hasRequest ? Visibility.Visible : Visibility.Collapsed;
        RecoveryButton.IsEnabled = hasRequest && !recoveringWifi && !transferWasActive;
        DismissRecoveryButton.Visibility = RecoveryButton.Visibility;
        DismissRecoveryButton.IsEnabled = RecoveryButton.IsEnabled;
        RecoveryButton.Content = RecoveryDriverHelp.Visibility == Visibility.Visible ? "もう一度試す" : "Wi-Fiを元に戻す";
        RecoveryStatus.Text = recoveryMessage.Length != 0 ? recoveryMessage :
            "前回の送受信後、Wi-Fiが元の接続に戻っていない可能性があります。";
        RecoveryStatusLine.IsBusy = recoveringWifi;
        UpdateTaskbar();
        TransferTabs.IsEnabled = !recoveringWifi;
    }

    private bool CanResolveRecovery()
    {
        if (session == 0 || invoking || recoveringWifi || recoveryRequest.Length == 0 ||
            Native.DD_Value(session, TransferMode.Send, ValueKind.TransferActive) != 0) return false;
        CheckWifiConnection();
        if (!wifiConnected) return true;
        UpdateRecoveryNotice();
        return false;
    }

    private void DismissRecovery(object sender, RoutedEventArgs e)
    {
        if (!CanResolveRecovery()) return;
        if (Native.DD_Command(session, TransferMode.Send, BridgeCommand.DismissRecovery, recoveryRequest, -1) != 1)
        {
            recoveryMessage = "この案内を閉じられませんでした。もう一度お試しください。";
        }
        else
        {
            recoveryRequest = Native.Text(session, TransferMode.Send, TextField.RecoveryRequestPath);
            recoveryMessage = "";
            RecoveryDriverHelp.Visibility = Visibility.Collapsed;
        }
        UpdateRecoveryNotice();
    }

    private async void RestoreWifi(object sender, RoutedEventArgs e)
    {
        if (!CanResolveRecovery()) return;
        var request = recoveryRequest;
        var runtime = Native.Text(session, TransferMode.Send, TextField.RuntimePath);
        RecoveryDriverHelp.Visibility = Visibility.Collapsed;
        if (runtime.Length == 0)
        {
            recoveryMessage = "Wi-Fiの復旧を開始できませんでした。配布ファイルをすべて展開し直してください。";
            UpdateRecoveryNotice();
            return;
        }

        recoveringWifi = true;
        recoveryMessage = "Wi-Fiを元の状態に戻しています。";
        UpdateRecoveryNotice();
        var failed = Native.Text(session, TransferMode.Send, TextField.RecoveryFailureMessage);
        try
        {
            var start = new ProcessStartInfo(runtime) { UseShellExecute = true, Verb = "runas" };
            start.ArgumentList.Add("--recover");
            start.ArgumentList.Add(request);
            using var process = Process.Start(start);
            if (process is null) { recoveryMessage = failed; return; }
            await process.WaitForExitAsync();
            var exitCode = process.ExitCode;
            if (exitCode != 0)
            {
                Native.DD_Command(session, TransferMode.Send, BridgeCommand.RecordRecoveryFailure, request, exitCode);
                recoveryRequest = Native.Text(session, TransferMode.Send, TextField.RecoveryRequestPath);
                if (recoveryRequest != request)
                {
                    recoveryMessage = "";
                    return;
                }
                recoveryMessage = Native.Text(session, TransferMode.Send, TextField.RecoveryFailureMessage, exitCode);
                RecoveryDriverHelp.Visibility = Native.DD_Value(session, TransferMode.Send,
                    ValueKind.ShowRecoveryDriverHelp, exitCode) == 1 ? Visibility.Visible : Visibility.Collapsed;
                return;
            }

            Native.DD_Command(session, TransferMode.Send, BridgeCommand.RecordRecoveryCompleted, request, -1);
            recoveryRequest = Native.Text(session, TransferMode.Send, TextField.RecoveryRequestPath);
            recoveryMessage = recoveryRequest == request
                ? "Wi-Fiは元に戻りました。接続を確認したら「接続済み」でこの案内を閉じてください。"
                : "";
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            recoveryMessage = "復旧を開始しませんでした。";
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException)
        {
            recoveryMessage = failed;
        }
        finally
        {
            recoveringWifi = false;
            nextWifiCheck = 0;
            Refresh();
        }
    }
    private void ChooseSendFile(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Multiselect = true, CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) SetSendFiles(dialog.FileNames);
    }
    private void SetSendFiles(IEnumerable<string> paths) => Invoke(TransferMode.Send, BridgeCommand.SelectSendFiles, string.Join("\n", paths));
    private void RemoveSendFile(object sender, RoutedEventArgs e)
    {
        if (!Send.CanChoose || sender is not FrameworkElement { DataContext: string path }) return;
        var files = Send.SendFiles.ToList();
        if (files.Remove(path)) SetSendFiles(files);
    }
    private void ChooseReceiveFolder(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Multiselect = false, InitialDirectory = Receive.FilePath };
        if (dialog.ShowDialog(this) == true) Invoke(TransferMode.Receive, BridgeCommand.SelectPath, dialog.FolderName);
    }
    private void TargetChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!refreshing) Invoke(TransferMode.Send, BridgeCommand.SelectItem, index: ((ListBox)sender).SelectedIndex);
    }
    private void TargetDoubleClick(object sender, MouseButtonEventArgs e)
    {
        var list = (ListBox)sender;
        if (ItemsControl.ContainerFromElement(list, (DependencyObject)e.OriginalSource) is ListBoxItem && Send.CanAct) SendAction(sender, e);
    }
    private void UpdateTaskbar()
    {
        var measured = Send.HasProgress ? Send : Receive.HasProgress ? Receive : null;
        Taskbar.ProgressState = recoveringWifi || Send.ShowBusyRing || Receive.ShowBusyRing
            ? TaskbarItemProgressState.Indeterminate
            : measured is null ? TaskbarItemProgressState.None : TaskbarItemProgressState.Normal;
        Taskbar.ProgressValue = measured?.ProgressValue / 100 ?? 0;
    }
    private void FlashTaskbar()
    {
        // Flash until the user brings the window forward; do not steal focus.
        var info = new FlashInfo { Size = (uint)Marshal.SizeOf<FlashInfo>(), Window = new WindowInteropHelper(this).Handle, Flags = FlashAll | FlashUntilForeground };
        FlashWindowEx(ref info);
    }
    private const uint FlashAll = 3, FlashUntilForeground = 12;
    [StructLayout(LayoutKind.Sequential)]
    private struct FlashInfo { public uint Size; public nint Window; public uint Flags; public uint Count; public uint Timeout; }
    [DllImport("user32.dll")] private static extern bool FlashWindowEx(ref FlashInfo info);
    private void SavedFileChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!refreshing) Invoke(TransferMode.Receive, BridgeCommand.SelectItem, index: ((ListBox)sender).SelectedIndex);
    }
    private void SendAction(object sender, RoutedEventArgs e) => Invoke(TransferMode.Send, BridgeCommand.Start);
    private void RefreshTargets(object sender, RoutedEventArgs e) => Invoke(TransferMode.Send, BridgeCommand.RefreshTargets);
    private void SendCancel(object sender, RoutedEventArgs e) => Invoke(TransferMode.Send, BridgeCommand.Cancel);
    private void ReceiveAction(object sender, RoutedEventArgs e) => Invoke(TransferMode.Receive, BridgeCommand.Start);
    private void ReceiveCancel(object sender, RoutedEventArgs e) => Invoke(TransferMode.Receive, BridgeCommand.Cancel);
    private void OnReceiveNotification(string offer, string action)
    {
        if (session == 0 || closeConfirmed || offer != Native.Text(session, TransferMode.Receive, TextField.OfferToken)) return;
        switch (action)
        {
            case "open":
                TransferTabs.SelectedIndex = (int)TransferMode.Receive;
                if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
                Activate();
                break;
            case "accept":
            case "reject":
                var decision = action == "accept" ? OfferDecision.Accept : OfferDecision.Reject;
                if (invoking || refreshing || recoveringWifi)
                {
                    if (pendingReceiveDecision?.Offer != offer) pendingReceiveDecision = (offer, decision);
                }
                else Invoke(TransferMode.Receive, BridgeCommand.RespondToOffer, offer, (int)decision);
                break;
        }
    }
    private void OpenFile(object sender, RoutedEventArgs e) => Invoke(TransferMode.Receive, BridgeCommand.OpenFile);
    private void ShowInFolder(object sender, RoutedEventArgs e) => Invoke(TransferMode.Receive, BridgeCommand.ShowInFolder);
    private void SavedFileDoubleClick(object sender, MouseButtonEventArgs e)
    {
        var list = (ListBox)sender;
        if (ItemsControl.ContainerFromElement(list, (DependencyObject)e.OriginalSource) is ListBoxItem && Receive.CanOpenFile) OpenFile(sender, e);
    }
    private static string[]? DroppedFiles(DragEventArgs e) =>
        e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths ? paths : null;
    private void FileDragOver(object sender, DragEventArgs e)
    {
        e.Effects = !recoveringWifi && Send.CanChoose && DroppedFiles(e) is not null ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }
    private void FileDrop(object sender, DragEventArgs e)
    {
        e.Handled = true;
        if (recoveringWifi || !Send.CanChoose || DroppedFiles(e) is not { } paths) return;
        TransferTabs.SelectedIndex = (int)TransferMode.Send;
        SetSendFiles(paths);
    }
    private void OpenFolder(object sender, RoutedEventArgs e) => Invoke(TransferMode.Receive, BridgeCommand.OpenFolder);
    private void WindowClosing(object? sender, CancelEventArgs e)
    {
        if (recoveringWifi) { e.Cancel = true; return; }
        placementOnClose = WindowPlacement.Capture(this);
        if (session == 0 || allowClose) return;
        if (!closeConfirmed && Native.DD_Value(session, TransferMode.Send, ValueKind.ConfirmClose) == 1)
        {
            var answer = MessageBox.Show(this, "進行中の送受信を中止して閉じますか？\n中止後、Wi-Fi接続を元に戻してから閉じます。",
                "Drop Porter", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes) { e.Cancel = true; return; }
            closeConfirmed = true;
        }
        e.Cancel = Native.DD_Command(session, TransferMode.Send, BridgeCommand.RequestClose, null, -1) != 1;
        Refresh();
    }
    private void WindowClosed(object? sender, EventArgs e)
    {
        WindowPlacement.Save(placementOnClose);
        timer.Stop();
        receiveNotifications.Dispose();
        if (session != 0 && Native.DD_Destroy(session) == 1) session = 0;
    }
}
