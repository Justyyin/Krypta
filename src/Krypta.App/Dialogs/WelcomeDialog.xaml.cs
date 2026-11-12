using System.Windows;
using Krypta.App.Services;

namespace Krypta.App;

/// <summary>First steps, shown once after a new vault was created.</summary>
public partial class WelcomeDialog : Window
{
    internal WelcomeDialog(Window owner)
    {
        Owner = owner;
        InitializeComponent();
        Hardening.Protect(this);
    }

    private void Settings_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
