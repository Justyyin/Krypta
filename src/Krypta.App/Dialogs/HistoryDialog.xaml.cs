using System.Windows;
using Krypta.App.Services;
using Krypta.Core;

namespace Krypta.App;

/// <summary>Shows the earlier passwords of an entry.</summary>
public partial class HistoryDialog : Window
{
    private readonly Entry _entry;
    private readonly ClipboardService _clipboard;
    private readonly AppSettings _settings;

    internal HistoryDialog(Window owner, Entry entry, ClipboardService clipboard, AppSettings settings)
    {
        _entry = entry;
        _clipboard = clipboard;
        _settings = settings;
        Owner = owner;
        InitializeComponent();
        Hardening.Protect(this);
        PasswordList.ItemsSource = entry.History
            .Select(old => Loc.F("History.Item", old.Password, old.Replaced.ToLocalTime().ToString("g")))
            .ToList();
        PasswordList.SelectedIndex = 0;
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        int index = PasswordList.SelectedIndex;
        if (index >= 0 && index < _entry.History.Count)
            _clipboard.Copy(_entry.History[index].Password, _settings.ClipboardClearSeconds);
    }
}
