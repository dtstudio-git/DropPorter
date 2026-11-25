using System.Globalization;
using System.IO;
using System.Windows.Data;

namespace DropPorter.Wpf;

// Shows a full path as its file name ("Name") or containing folder ("Folder").
public sealed class PathPartConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var path = value as string ?? "";
        try { return parameter as string == "Folder" ? Path.GetDirectoryName(path) ?? "" : Path.GetFileName(path); }
        catch (ArgumentException) { return path; }
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
