using System.Diagnostics;
using System.Windows.Threading;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace DropPorter.Wpf;

internal sealed class ReceiveNotifications(Dispatcher dispatcher, Action<string, string> invoke) : IDisposable
{
    private AppNotificationManager? manager;
    private string lastOffer = "";
    private DateTimeOffset expiration;
    private uint notificationId;

    public void Register()
    {
        if (manager is not null) return;
        try
        {
            if (!AppNotificationManager.IsSupported()) return;
            var notifications = AppNotificationManager.Default;
            notifications.NotificationInvoked += OnInvoked;
            try { notifications.Register(); }
            catch { notifications.NotificationInvoked -= OnInvoked; throw; }
            manager = notifications;
        }
        catch (Exception error)
        {
            Trace.TraceWarning("Windows receive notification registration failed ({0:X8}).", error.HResult);
        }
    }

    public void Update(string offer, DateTimeOffset? expiresAt, string sender, string summary)
    {
        if (manager is not { } notifications) return;
        var now = DateTimeOffset.UtcNow;
        if (notificationId != 0 && (offer != lastOffer || expiration <= now)) Clear();
        if (offer.Length == 0 || offer == lastOffer || expiresAt is not { } deadline || deadline <= now) return;

        lastOffer = offer;
        expiration = deadline;
        try
        {
            var toast = new AppNotificationBuilder()
                .AddText("AirDrop の受信依頼")
                .AddText(sender)
                .AddText(summary)
                .SetDuration(AppNotificationDuration.Long)
                .AddArgument("action", "open")
                .AddArgument("offer", offer)
                .AddButton(new AppNotificationButton("受信").AddArgument("action", "accept").AddArgument("offer", offer))
                .AddButton(new AppNotificationButton("拒否").AddArgument("action", "reject").AddArgument("offer", offer))
                .BuildNotification();
            toast.Expiration = deadline;
            toast.ExpiresOnReboot = true;
            notifications.Show(toast);
            notificationId = toast.Id;
        }
        catch (Exception error)
        {
            Trace.TraceWarning("Windows receive notification failed ({0:X8}).", error.HResult);
            Clear();
        }
    }

    private void OnInvoked(AppNotificationManager sender, AppNotificationActivatedEventArgs args)
    {
        if (!args.Arguments.TryGetValue("offer", out var offer) ||
            !args.Arguments.TryGetValue("action", out var action)) return;
        _ = dispatcher.InvokeAsync(() => HandleInvocation(offer, action));
    }

    private void HandleInvocation(string offer, string action)
    {
        if (notificationId != 0 && offer == lastOffer && expiration > DateTimeOffset.UtcNow)
            invoke(offer, action);
    }

    private void Clear()
    {
        var retiredId = notificationId;
        notificationId = 0;
        if (retiredId != 0 && manager is { } notifications) _ = RemoveAsync(notifications, retiredId);
    }

    public void Dispose()
    {
        Clear();
        if (manager is not { } notifications) return;
        manager = null;
        try
        {
            notifications.NotificationInvoked -= OnInvoked;
            notifications.Unregister();
        }
        catch (Exception error)
        {
            Trace.TraceWarning("Windows receive notification unregister failed ({0:X8}).", error.HResult);
        }
    }

    private static async Task RemoveAsync(AppNotificationManager notifications, uint id)
    {
        try { await notifications.RemoveByIdAsync(id); }
        catch (Exception error)
        {
            Trace.TraceWarning("Windows receive notification removal failed ({0:X8}).", error.HResult);
        }
    }
}
