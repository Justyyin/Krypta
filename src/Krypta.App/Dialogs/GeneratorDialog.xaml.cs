using System.Windows;
using Krypta.App.Services;
using Krypta.Core;

namespace Krypta.App;

public partial class GeneratorDialog : Window
{
    private readonly ClipboardService _clipboard;
    private readonly AppSettings _settings;
    private readonly bool _ready;

    public string Password { get; private set; } = "";

    internal GeneratorDialog(Window owner, bool forEntry, ClipboardService clipboard, AppSettings settings)
    {
        _clipboard = clipboard;
        _settings = settings;
        Owner = owner;
        InitializeComponent();
        Hardening.Protect(this);

        UseButton.Visibility = forEntry ? Visibility.Visible : Visibility.Collapsed;
        CloseButton.Content = Loc.T(forEntry ? "Common.Cancel" : "Common.Close");
        _ready = true;
        Generate();
    }

    private PasswordOptions Options => new()
    {
        Length = (int)LengthSlider.Value,
        Upper = UpperCheck.IsChecked == true,
        Lower = LowerCheck.IsChecked == true,
        Digits = DigitsCheck.IsChecked == true,
        Symbols = SymbolsCheck.IsChecked == true,
        ExcludeAmbiguous = AmbiguousCheck.IsChecked == true,
    };

    private void Generate()
    {
        if (!_ready) return;
        // At least one kind of character has to stay selected.
        if (UpperCheck.IsChecked != true && LowerCheck.IsChecked != true && DigitsCheck.IsChecked != true && SymbolsCheck.IsChecked != true)
            LowerCheck.IsChecked = true;

        var options = Options;
        Password = PasswordGenerator.Generate(options);
        PasswordText.Text = Password;
        LengthLabel.Text = Loc.F("Gen.Length", options.Length);

        double bits = PasswordGenerator.EntropyBits(options);
        int level = bits switch { < 40 => 0, < 60 => 1, < 80 => 2, < 100 => 3, _ => 4 };
        EntropyText.Text = Loc.F("Gen.Entropy", Loc.T("Strength." + level), Math.Round(bits));
        CopiedText.Visibility = Visibility.Collapsed;
    }

    private void Option_Changed(object sender, RoutedEventArgs e) => Generate();

    private void Regenerate_Click(object sender, RoutedEventArgs e) => Generate();

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        int seconds = _settings.ClipboardClearSeconds;
        bool copied = _clipboard.Copy(Password, seconds);
        CopiedText.Text = !copied ? Loc.T("Toast.CopyFailed")
            : seconds > 0 ? Loc.F("Toast.Copied", seconds) : Loc.T("Toast.CopiedNoClear");
        CopiedText.Visibility = Visibility.Visible;
    }

    private void Use_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
