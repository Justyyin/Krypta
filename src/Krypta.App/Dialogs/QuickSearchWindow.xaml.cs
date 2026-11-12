using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Krypta.App.Services;
using Krypta.Core;

namespace Krypta.App;

/// <summary>Small search box opened with Ctrl+Alt+K: find an entry and copy its password.</summary>
public partial class QuickSearchWindow : Window
{
    private readonly IReadOnlyList<Entry> _entries;

    /// <summary>The entry the user picked, with Enter (copy) or Ctrl+Enter (open in Krypta).</summary>
    public Entry? Chosen { get; private set; }
    public bool OpenInApp { get; private set; }

    internal QuickSearchWindow(IReadOnlyList<Entry> entries)
    {
        _entries = entries;
        InitializeComponent();
        Hardening.Protect(this);
        Refresh();
        Loaded += (_, _) => { Activate(); QueryBox.Focus(); };
        Deactivated += (_, _) => { if (IsVisible && Chosen is null) Close(); };
    }

    private void Refresh()
    {
        string query = QueryBox.Text.Trim();
        ResultList.ItemsSource = _entries
            .Where(entry => EntrySearch.Matches(entry, query))
            .OrderByDescending(entry => entry.Favorite)
            .ThenBy(entry => entry.Title, StringComparer.CurrentCultureIgnoreCase)
            .Take(30)
            .Select(entry => new EntryRow(entry))
            .ToList();
        ResultList.SelectedIndex = ResultList.Items.Count > 0 ? 0 : -1;
    }

    private void Query_Changed(object sender, TextChangedEventArgs e)
    {
        if (IsInitialized && ResultList is not null) Refresh();
    }

    private void Query_KeyDown(object sender, KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.Down when ResultList.SelectedIndex < ResultList.Items.Count - 1:
                ResultList.SelectedIndex++;
                ResultList.ScrollIntoView(ResultList.SelectedItem);
                e.Handled = true;
                break;
            case Key.Up when ResultList.SelectedIndex > 0:
                ResultList.SelectedIndex--;
                ResultList.ScrollIntoView(ResultList.SelectedItem);
                e.Handled = true;
                break;
            case Key.Enter:
                Choose(openInApp: Keyboard.Modifiers.HasFlag(ModifierKeys.Control));
                e.Handled = true;
                break;
            case Key.Escape:
                Close();
                e.Handled = true;
                break;
        }
    }

    private void Result_DoubleClick(object sender, MouseButtonEventArgs e) => Choose(openInApp: false);

    private void Choose(bool openInApp)
    {
        if (ResultList.SelectedItem is not EntryRow row) return;
        Chosen = row.Entry;
        OpenInApp = openInApp;
        Close();
    }
}
