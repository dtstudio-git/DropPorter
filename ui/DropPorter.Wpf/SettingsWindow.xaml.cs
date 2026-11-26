using System.Windows;

namespace DropPorter.Wpf;

public partial class SettingsWindow : Window
{
    private readonly nint session;

    internal SettingsWindow(nint session)
    {
        this.session = session;
        InitializeComponent();
        KeepRadio.IsChecked = Native.DD_Value(session, TransferMode.Send, ValueKind.KeepRadio) == 1;
    }

    private void KeepRadioClicked(object sender, RoutedEventArgs e)
    {
        var enabled = KeepRadio.IsChecked == true;
        var saved = Native.DD_Command(session, TransferMode.Send, BridgeCommand.SetKeepRadio, null, enabled ? 1 : 0) == 1;
        // Show what is actually stored, not what was clicked.
        KeepRadio.IsChecked = Native.DD_Value(session, TransferMode.Send, ValueKind.KeepRadio) == 1;
        SaveError.Visibility = saved ? Visibility.Collapsed : Visibility.Visible;
    }

    private void CloseClicked(object sender, RoutedEventArgs e) => Close();
}
