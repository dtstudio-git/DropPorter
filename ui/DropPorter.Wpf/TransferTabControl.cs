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
}
