using System.ComponentModel;
using System.Windows;
using Krypta.App.Services;

namespace Krypta.App;

/// <summary>Shows the recovery key of a device-bound vault once, right after it was created.</summary>
public partial class RecoveryKeyDialog : Window
{
    private readonly ClipboardService _clipboard;
    private readonly AppSettings _settings;
    private bool _confirmed;

    internal RecoveryKeyDialog(Window owner, string recoveryKey, ClipboardService clipboard, AppSettings settings)
    {
        _clipboard = clipboard;
        _settings = settings;
        Owner = owner;
        InitializeComponent();
        Hardening.Protect(this);
        KeyText.Text = recoveryKey;
    }

    private void Copy_Click(object sender, RoutedEventArgs e) => _clipboard.Copy(KeyText.Text, _settings.ClipboardClearSeconds);

    private void Confirm_Changed(object sender, RoutedEventArgs e) => CloseButton.IsEnabled = ConfirmCheck.IsChecked == true;

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        _confirmed = true;
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // The key cannot be shown again, so the dialog only closes after the user confirmed.
        // It also stays open when the vault locks: the key alone does not open the vault.
        if (!_confirmed) e.Cancel = true;
        base.OnClosing(e);
    }
}
