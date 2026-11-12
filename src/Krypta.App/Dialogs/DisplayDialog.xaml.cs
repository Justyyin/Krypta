using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Krypta.App.Services;
using Krypta.Core;

namespace Krypta.App;

/// <summary>Shows a QR code, or a password in large, colour-coded letters for reading it off the screen.</summary>
public partial class DisplayDialog : Window
{
    private static readonly Brush DigitBrush = Frozen("#4CC2FF"), SymbolBrush = Frozen("#FFB454");

    private static Brush Frozen(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }

    private DisplayDialog(Window owner, string title)
    {
        Owner = owner;
        InitializeComponent();
        Hardening.Protect(this);
        Title = title;
    }

    internal static DisplayDialog ForQr(Window owner, string title, string caption, string content)
    {
        var dialog = new DisplayDialog(owner, title);
        const int size = 280;
        byte[] pixels = QrDecoder.Encode(content, size);
        dialog.QrImage.Source = BitmapSource.Create(size, size, 96, 96, PixelFormats.Bgra32, null, pixels, size * 4);
        dialog.QrFrame.Visibility = Visibility.Visible;
        dialog.CaptionText.Text = caption;
        dialog.CaptionText.Visibility = Visibility.Visible;
        return dialog;
    }

    internal static DisplayDialog ForText(Window owner, string title, string secret)
    {
        var dialog = new DisplayDialog(owner, title);
        Colorize(dialog.LargeText, secret);
        dialog.LargeText.Visibility = Visibility.Visible;
        return dialog;
    }

    /// <summary>Digits and symbols get their own colour so that 0/O and 1/l are easy to tell apart.</summary>
    internal static void Colorize(TextBlock target, string secret)
    {
        target.Inlines.Clear();
        foreach (char c in secret)
        {
            var run = new Run(c.ToString());
            if (char.IsDigit(c)) run.Foreground = DigitBrush;
            else if (!char.IsLetter(c)) run.Foreground = SymbolBrush;
            target.Inlines.Add(run);
        }
    }
}
