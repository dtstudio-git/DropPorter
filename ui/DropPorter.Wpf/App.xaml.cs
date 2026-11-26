using System.Windows;
namespace DropPorter.Wpf;
public partial class App : Application
{
    private Mutex? windowInstance;

    protected override void OnStartup(StartupEventArgs e)
    {
        // A notification can launch a new process after the previous window has closed.
        // A new process does not own that receive request.
        if (e.Args.Any(arg => arg.StartsWith("----AppNotificationActivated:", StringComparison.Ordinal)))
        {
            Shutdown();
            return;
        }

        if (e.Args.FirstOrDefault() == "--send")
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            base.OnStartup(e);
            RunSend(e.Args);
            return;
        }

        if (!AcquireWindowInstance())
        {
            Shutdown();
            return;
        }

        // ThemeMode has already merged the Fluent theme; load ours after it so its styles can build on Fluent's.
        Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("pack://application:,,,/DropPorter;component/Theme.xaml", UriKind.Absolute) });
        base.OnStartup(e);
        new MainWindow().Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            base.OnExit(e);
        }
        finally
        {
            if (windowInstance is { } instance)
            {
                instance.ReleaseMutex();
                instance.Dispose();
            }
        }
    }

    private bool AcquireWindowInstance()
    {
        var instance = new Mutex(false, "DropPorter.MainWindow", new NamedWaitHandleOptions
        {
            CurrentUserOnly = true,
            CurrentSessionOnly = true
        });

        try
        {
            if (!instance.WaitOne(0))
            {
                instance.Dispose();
                return false;
            }
        }
        catch (AbandonedMutexException)
        {
            // The previous UI thread exited without releasing the mutex. This thread now owns it.
        }

        windowInstance = instance;
        return true;
    }

    private async void RunSend(string[] args)
    {
        try { Shutdown(await CommandLineSend.RunAsync(args)); }
        catch (Exception error) { Console.Error.WriteLine(error.Message); Shutdown(1); }
    }
}
