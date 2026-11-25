using System.Windows;
namespace DropPorter.Wpf;
public partial class App : Application
{
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

        // ThemeMode has already merged the Fluent theme; load ours after it so its styles can build on Fluent's.
        Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("pack://application:,,,/DropPorter;component/Theme.xaml", UriKind.Absolute) });
        base.OnStartup(e);
        new MainWindow().Show();
    }

    private async void RunSend(string[] args)
    {
        try { Shutdown(await CommandLineSend.RunAsync(args)); }
        catch (Exception error) { Console.Error.WriteLine(error.Message); Shutdown(1); }
    }
}
