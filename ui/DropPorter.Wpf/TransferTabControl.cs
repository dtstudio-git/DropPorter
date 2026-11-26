using System.Windows;
using System.Windows.Controls;

namespace DropPorter.Wpf;

public sealed class TransferTabControl : TabControl
{
    public static readonly DependencyProperty RecoveryContentProperty =
        DependencyProperty.Register(nameof(RecoveryContent), typeof(UIElement), typeof(TransferTabControl));

    public UIElement? RecoveryContent
    {
        get => (UIElement?)GetValue(RecoveryContentProperty);
        set => SetValue(RecoveryContentProperty, value);
    }

    // Shown at the right end of the tab header row.
    public static readonly DependencyProperty HeaderContentProperty =
        DependencyProperty.Register(nameof(HeaderContent), typeof(UIElement), typeof(TransferTabControl));

    public UIElement? HeaderContent
    {
        get => (UIElement?)GetValue(HeaderContentProperty);
        set => SetValue(HeaderContentProperty, value);
    }
}
