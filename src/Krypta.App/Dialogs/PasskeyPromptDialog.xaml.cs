using System.Windows;
using Krypta.App.Services;

namespace Krypta.App;

/// <summary>
/// Asks the user to approve a passkey request from a website. The confirm button is not the
/// default button on purpose, so a stray Enter key press cannot approve a request.
/// </summary>
public partial class PasskeyPromptDialog : Window
{
    public int SelectedIndex => Math.Max(0, AccountList.SelectedIndex);

    internal PasskeyPromptDialog(Window owner, string message, IReadOnlyList<string>? accounts, string confirmText)
    {
        Owner = owner;
        InitializeComponent();
        Hardening.Protect(this);
        MessageText.Text = message;
        ConfirmButton.Content = confirmText;
        if (accounts is { Count: > 1 })
        {
            AccountList.ItemsSource = accounts;
            AccountList.SelectedIndex = 0;
            AccountList.Visibility = Visibility.Visible;
        }
    }

    private void Confirm_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
