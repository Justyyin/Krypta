using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Krypta.App.Services;
using Krypta.Core;

namespace Krypta.App;

/// <summary>One line in the entry list.</summary>
internal sealed class EntryRow(Entry entry) : INotifyPropertyChanged
{
    public Entry Entry { get; } = entry;
    public string Title => string.IsNullOrWhiteSpace(Entry.Title) ? "—" : Entry.Title;
    public string Subtitle => Entry.Kind switch
    {
        EntryKind.Note => Loc.T("Kind.Note"),
        EntryKind.Wifi => Loc.T("Kind.Wifi"),
        EntryKind.Card => Entry.CardNumber.Length >= 4 ? "•••• " + Entry.CardNumber[^4..] : Loc.T("Kind.Card"),
        _ => Entry.Username.Length > 0 ? Entry.Username :
            Entry.Passkey is { } passkey ? passkey.RpId :
            Entry.Totp is { Account.Length: > 0 } totp ? totp.Account : Entry.Url,
    };
    public Visibility PasskeyVisibility => Entry.Passkey is null ? Visibility.Collapsed : Visibility.Visible;
    public string Code { get; private set; } = "";

    /// <summary>The website's own icon, when the user turned website icons on.</summary>
    public ImageSource? Icon { get; init; }
    public Visibility IconVisibility => Icon is null ? Visibility.Collapsed : Visibility.Visible;

    private static readonly Brush[] Palette = new[] { "#E5484D", "#F76B15", "#D6A100", "#30A46C", "#12A594", "#3E63DD", "#8E4EC6", "#D6409F" }
        .Select(hex => { var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); brush.Freeze(); return (Brush)brush; })
        .ToArray();

    /// <summary>First letter of the name, shown on a coloured tile in front of the entry.</summary>
    public string Initial => Title.Trim() is { Length: > 0 } title && char.IsLetterOrDigit(title[0]) ? char.ToUpper(title[0]).ToString() : "•";

    /// <summary>The same name always gets the same colour.</summary>
    public Brush AvatarBrush => Palette[Title.ToUpperInvariant().Aggregate(0, (sum, c) => (sum * 31 + c) & 0xFFFF) % Palette.Length];

    /// <summary>Section header in the list: the first letter, or # for everything else.</summary>
    public string Group => Initial.Length == 1 && char.IsLetter(Initial[0]) ? Initial : "#";

    public event PropertyChangedEventHandler? PropertyChanged;

    public void Tick(DateTimeOffset now)
    {
        string code = Entry.Totp is null ? "" : MainWindow.FormatCode(Entry.Totp, now);
        if (code == Code) return;
        Code = code;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Code)));
    }
}

public partial class MainWindow : Window
{
    private const int MinMasterPasswordLength = 10;
    private const string Mask = "••••••••••••";

    private readonly AppSettings _settings;
    private readonly TpmDeviceKeyProvider _deviceKey = new();
    private readonly ClipboardService _clipboard = new();
    private readonly DispatcherTimer _clock = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DispatcherTimer _toastTimer = new() { Interval = TimeSpan.FromSeconds(4) };
    private readonly ObservableCollection<EntryRow> _rows = [];
    private readonly SemaphoreSlim _passkeyGate = new(1, 1);
    private readonly PasskeyBridge _bridge;

    private Vault? _vault;
    private Entry? _selected;
    private string _vaultPath;
    private bool _createMode;
    private bool _needRecovery;
    private bool _passwordShown;
    private bool _busy;
    private TaskCompletionSource<bool>? _unlockWaiter;

    // Notification area icon, global shortcuts, quick search, typing a password into another window.
    private TrayIcon? _tray;
    private QuickSearchWindow? _quickSearch;
    private byte[]? _keyFile;
    private bool _autoTyping;
    private bool _exiting;
    private bool _fillingVaults;
    private bool _needKeyFile;

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr window);

    // Smart filter "by website" and the security check page.
    private readonly HibpClient _hibp = new();
    private readonly FaviconService _favicons = new();
    private bool _fetchingIcons;
    private readonly Dictionary<Entry, long> _leaks = [];
    private List<string> _filterKeys = [];
    private string _smartFilter = "";
    private bool _fillingWebsites;
    private bool _leaksChecked;

    private sealed record FindingRow(Entry Entry, string Title, string Detail);

    internal MainWindow(AppSettings settings)
    {
        _settings = settings;
        _vaultPath = settings.EffectiveVaultPath;
        InitializeComponent();
        Hardening.Protect(this);

        EntryList.ItemsSource = _rows;
        CollectionViewSource.GetDefaultView(_rows).GroupDescriptions.Add(new PropertyGroupDescription(nameof(EntryRow.Group)));
        _clock.Tick += (_, _) => OnClockTick();
        _clock.Start();
        _toastTimer.Tick += (_, _) => { _toastTimer.Stop(); Toast.Visibility = Visibility.Collapsed; };

        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        Closed += OnClosed;
        StateChanged += (_, _) =>
        {
            if (WindowState == WindowState.Minimized && _settings.LockOnMinimize && !_autoTyping) LockVault();
        };

        _bridge = new PasskeyBridge(HandlePasskeyRequestAsync);
        _bridge.Start();

        SetMode(create: !File.Exists(_vaultPath));
        Loaded += (_, _) => PasswordInput.Focus();
    }

    // ---------------------------------------------------------------- tray icon and shortcuts

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        IntPtr handle = new WindowInteropHelper(this).Handle;
        HwndSource.FromHwnd(handle)?.AddHook(WindowMessage);
        if (App.SkipStartup) return;
        GlobalHotkeys.Register(handle);
        _tray = new TrayIcon(handle, "Krypta");
    }

    private IntPtr WindowMessage(IntPtr window, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (message == GlobalHotkeys.Message)
        {
            if ((int)wParam == GlobalHotkeys.QuickSearch) OpenQuickSearch();
            else if ((int)wParam == GlobalHotkeys.PanicLock) LockVault();
            handled = true;
        }
        else if (message == TrayIcon.CallbackMessage)
        {
            int mouse = (int)lParam & 0xFFFF;
            if (mouse == 0x0202) BringToFront();          // left button released
            else if (mouse == 0x0205) ShowTrayMenu();      // right button released
            handled = true;
        }
        return IntPtr.Zero;
    }

    private void ShowTrayMenu()
    {
        MenuItem Item(string key, Action action)
        {
            var item = new MenuItem { Header = Loc.T(key) };
            item.Click += (_, _) => action();
            return item;
        }
        var menu = new ContextMenu { Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint };
        menu.Items.Add(Item("Tray.Open", BringToFront));
        menu.Items.Add(Item("Tray.Quick", OpenQuickSearch));
        menu.Items.Add(Item("Tray.Lock", LockVault));
        menu.Items.Add(new Separator());
        menu.Items.Add(Item("Tray.Exit", () => { _exiting = true; Close(); }));
        SetForegroundWindow(new WindowInteropHelper(this).Handle); // lets the menu close on a click elsewhere
        menu.IsOpen = true;
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // With "keep running" the close button only hides the window; the vault still locks as usual.
        if (_settings.CloseToTray && !_exiting && _tray is not null)
        {
            e.Cancel = true;
            Hide();
        }
        base.OnClosing(e);
    }

    private void OpenQuickSearch()
    {
        if (_vault is null)
        {
            BringToFront();
            PasswordInput.Focus();
            return;
        }
        if (_quickSearch is not null)
        {
            _quickSearch.Activate();
            return;
        }
        var window = new QuickSearchWindow(_vault.Data.Active.ToList());
        _quickSearch = window;
        window.Closed += (_, _) =>
        {
            _quickSearch = null;
            if (window.Chosen is not { } entry || _vault is null) return;
            if (window.OpenInApp)
            {
                BringToFront();
                _smartFilter = "";
                SearchBox.Clear();
                NavList.SelectedIndex = 0;
                RefreshList(entry);
                return;
            }
            string secret = entry.Password.Length > 0 ? entry.Password
                : entry.Totp is { } totp ? FormatCode(totp, DateTimeOffset.UtcNow).Replace(" ", "")
                : entry.CardNumber.Replace(" ", "");
            if (secret.Length > 0) _clipboard.Copy(secret, _settings.ClipboardClearSeconds);
        };
        window.Show();
    }

    /// <summary>
    /// Types user name, Tab and password into the window that was used before Krypta, so the
    /// password never passes through the clipboard.
    /// </summary>
    private async void AutoType_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not { } entry || _autoTyping) return;
        _autoTyping = true;
        try
        {
            WindowState = WindowState.Minimized; // gives the focus back to the previous window
            await Task.Delay(700);
            if (!AutoType.ForeignWindowHasFocus())
            {
                BringToFront();
                ShowToast(Loc.T("Toast.TypeFailed"));
                return;
            }
            bool withUser = entry.Kind == EntryKind.Login && entry.Username.Length > 0;
            AutoType.Type(withUser ? entry.Username + "\t" + entry.Password : entry.Password);
        }
        finally
        {
            _autoTyping = false;
        }
    }

    private void LargeView_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not null) DisplayDialog.ForText(this, _selected.Title, _selected.Password).ShowDialog();
    }

    private void WifiQr_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not null)
            DisplayDialog.ForQr(this, _selected.Title, Loc.T("Qr.Wifi"), Transfer.WifiQrText(_selected)).ShowDialog();
    }

    private void TotpQr_Click(object sender, RoutedEventArgs e)
    {
        if (_selected?.Totp is { } totp)
            DisplayDialog.ForQr(this, _selected.Title, Loc.T("Qr.Totp"), Transfer.OtpAuthUri(totp, _selected)).ShowDialog();
    }

    // ---------------------------------------------------------------- locking and unlocking

    private void SetMode(bool create)
    {
        _createMode = create;
        _needRecovery = false;
        PasswordInput.Clear();
        ConfirmInput.Clear();
        RecoveryInput.Clear();
        _keyFile = null;
        _needKeyFile = false;
        KeyFileCheck.IsChecked = false;
        ShowUnlockError(null);
        RefreshUnlockTexts();
    }

    private void RefreshUnlockTexts()
    {
        UnlockSubtitle.Text = Loc.T(_createMode ? "Unlock.SubtitleCreate" : "Unlock.SubtitleOpen");
        UnlockButton.Content = Loc.T(_createMode ? "Unlock.Button.Create" : "Unlock.Button.Open");
        CreateFields.Visibility = _createMode ? Visibility.Visible : Visibility.Collapsed;
        RecoveryFields.Visibility = _needRecovery && !_createMode ? Visibility.Visible : Visibility.Collapsed;
        VaultPathText.Text = Loc.F("Unlock.VaultFile", _vaultPath);
        KeyFileFields.Visibility = _needKeyFile && !_createMode ? Visibility.Visible : Visibility.Collapsed;
        KeyFileText.Text = _keyFile is null ? Loc.T("Unlock.KeyFileNeeded") : "\u2022\u2022\u2022";

        // Several vaults (for example private and work): pick one from the list.
        var vaults = _settings.RecentVaults.Where(File.Exists).ToList();
        if (File.Exists(_vaultPath) && !vaults.Contains(_vaultPath, StringComparer.OrdinalIgnoreCase)) vaults.Insert(0, _vaultPath);
        _fillingVaults = true;
        VaultBox.ItemsSource = vaults;
        VaultBox.SelectedItem = vaults.FirstOrDefault(path => string.Equals(path, _vaultPath, StringComparison.OrdinalIgnoreCase));
        VaultBox.Visibility = vaults.Count > 1 && !_createMode ? Visibility.Visible : Visibility.Collapsed;
        _fillingVaults = false;

        bool tpm = _deviceKey.IsAvailable;
        DeviceBindCheck.IsEnabled = tpm;
        if (!tpm) DeviceBindCheck.IsChecked = false;
        DeviceBindHint.Text = Loc.T(tpm ? "Unlock.BindDeviceHint" : "Unlock.BindUnavailable");
        UpdateStrength();
    }

    private void UpdateStrength()
    {
        int strength = PasswordGenerator.EstimateStrength(PasswordInput.Password);
        StrengthBar.Value = PasswordInput.Password.Length == 0 ? 0 : Math.Max(strength, 0.4);
        StrengthText.Text = PasswordInput.Password.Length == 0 ? "" : Loc.T("Strength." + strength);
    }

    private void ShowUnlockError(string? message)
    {
        UnlockError.Text = message ?? "";
        UnlockError.Visibility = message is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private void PasswordInput_Changed(object sender, RoutedEventArgs e) => UpdateStrength();

    private void VaultBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_fillingVaults || VaultBox.SelectedItem is not string path) return;
        _vaultPath = path;
        SetMode(create: false);
    }

    private void ChooseKeyFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = Loc.T("Unlock.KeyFileFilter") };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var info = new FileInfo(dialog.FileName);
            if (info.Length is < 16 or > 1024 * 1024) throw new IOException(Loc.T("Unlock.KeyFileNeeded"));
            _keyFile = File.ReadAllBytes(dialog.FileName);
            RefreshUnlockTexts();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowUnlockError(Loc.F("Unlock.Error.Generic", ex.Message));
        }
    }

    private async void UnlockButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        string password = PasswordInput.Password;
        ShowUnlockError(null);

        bool create = _createMode;
        if (create)
        {
            if (password.Length < MinMasterPasswordLength) { ShowUnlockError(Loc.T("Unlock.Error.TooShort")); return; }
            if (password != ConfirmInput.Password) { ShowUnlockError(Loc.T("Unlock.Error.Mismatch")); return; }
        }
        else if (password.Length == 0)
        {
            return;
        }

        bool bind = create && DeviceBindCheck.IsChecked == true;
        byte[]? keyFile = _keyFile;
        if (create && KeyFileCheck.IsChecked == true)
        {
            // The key file is written before the vault, so a vault never exists without its key file.
            var saveKey = new SaveFileDialog { Filter = Loc.T("Unlock.KeyFileFilter"), FileName = "krypta.key" };
            if (saveKey.ShowDialog(this) != true) return;
            try
            {
                keyFile = Vault.NewKeyFile();
                File.WriteAllBytes(saveKey.FileName, keyFile);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                ShowUnlockError(Loc.F("Unlock.Error.Generic", ex.Message));
                return;
            }
        }
        string? recoveryInput = _needRecovery ? RecoveryInput.Text : null;
        string path = _vaultPath;
        IDeviceKeyProvider? device = _deviceKey.IsAvailable ? _deviceKey : null;

        SetBusy(true);
        try
        {
            string? recoveryKey = null;
            Vault vault = await Task.Run(() => create
                ? Vault.Create(path, password, out recoveryKey, bind ? device : null, keyFile: keyFile)
                : Vault.Open(path, password, device, recoveryInput, keyFile));

            _settings.RememberVault(path);
            _settings.Save();
            _keyFile = null;
            PasswordInput.Clear();
            ConfirmInput.Clear();
            RecoveryInput.Clear();
            ShowVault(vault);
            if (recoveryKey is not null) new RecoveryKeyDialog(this, recoveryKey, _clipboard, _settings).ShowDialog();
            if (create && _vault is not null && new WelcomeDialog(this).ShowDialog() == true) Settings_Click(this, new RoutedEventArgs());
        }
        catch (KeyFileRequiredException)
        {
            _needKeyFile = true;
            RefreshUnlockTexts();
        }
        catch (WrongPasswordException)
        {
            ShowUnlockError(Loc.T("Unlock.Error.Wrong"));
        }
        catch (DeviceKeyUnavailableException)
        {
            _needRecovery = true;
            RefreshUnlockTexts();
            RecoveryInput.Focus();
        }
        catch (VaultException ex) when (_needRecovery && recoveryInput is not null && ex.Message.Contains("recovery", StringComparison.OrdinalIgnoreCase))
        {
            ShowUnlockError(Loc.T("Unlock.Error.Recovery"));
        }
        catch (Exception ex) when (ex is VaultException or IOException or UnauthorizedAccessException or CryptographicException)
        {
            ShowUnlockError(Loc.F("Unlock.Error.Generic", ex.Message));
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        UnlockButton.IsEnabled = !busy;
        PasswordInput.IsEnabled = !busy;
        ConfirmInput.IsEnabled = !busy;
        UnlockProgress.Visibility = busy ? Visibility.Visible : Visibility.Hidden;
    }

    internal void ShowVault(Vault vault)
    {
        _vault = vault;
        _selected = null;
        if (VaultOps.PurgeTrash(vault.Data, DateTimeOffset.UtcNow) > 0) SaveVault();
        UnlockPanel.Visibility = Visibility.Collapsed;
        VaultPanel.Visibility = Visibility.Visible;
        PasskeyBanner.Visibility = Visibility.Collapsed;
        SearchBox.Clear();
        NavList.SelectedIndex = 0;
        RefreshList();
        _unlockWaiter?.TrySetResult(true);

        var lastCheck = vault.Data.LastLeakCheck;
        if (_settings.LeakMonitor && (lastCheck is null || DateTimeOffset.UtcNow - lastCheck > TimeSpan.FromDays(7)))
            _ = RunLeakCheckAsync(silent: true);
    }

    internal void LockVault()
    {
        if (_vault is null) return;
        _quickSearch?.Close();
        foreach (Window dialog in OwnedWindows.Cast<Window>().Where(w => w is not RecoveryKeyDialog).ToList()) dialog.Close();

        _vault.Dispose();
        _vault = null;
        _selected = null;
        _rows.Clear();
        ShowDetail(null);
        _clipboard.ClearIfOurs();
        _leaks.Clear();
        _leaksChecked = false;
        _smartFilter = "";
        FindingList.ItemsSource = null;
        EmailBox.ItemsSource = null;
        EmailBox.Text = "";
        ApiKeyBox.Clear();
        EmailResult.Text = "";
        LeakStatus.Text = "";
        Toast.Visibility = Visibility.Collapsed;

        VaultPanel.Visibility = Visibility.Collapsed;
        UnlockPanel.Visibility = Visibility.Visible;
        SetMode(create: false);
        PasswordInput.Focus();
    }

    private void OnClockTick()
    {
        if (_vault is null) return;
        if (_settings.AutoLockMinutes > 0 && Hardening.IdleTime() >= TimeSpan.FromMinutes(_settings.AutoLockMinutes))
        {
            LockVault();
            return;
        }
        var now = DateTimeOffset.UtcNow;
        foreach (var row in _rows) row.Tick(now);
        UpdateDetailCode(now);
    }

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff or SessionSwitchReason.ConsoleDisconnect)
            Dispatcher.BeginInvoke(LockVault);
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend) Dispatcher.BeginInvoke(LockVault);
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        _bridge.Dispose();
        _quickSearch?.Close();
        _tray?.Dispose();
        GlobalHotkeys.Unregister(new WindowInteropHelper(this).Handle);
        _clipboard.ClearIfOurs();
        _vault?.Dispose();
        _vault = null;
    }

    private void OpenOther_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = Loc.T("Unlock.FileFilter"), CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        _vaultPath = dialog.FileName;
        SetMode(create: false);
    }

    private void CreateNew_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = Loc.T("Unlock.FileFilter"), FileName = "vault.krypta", OverwritePrompt = false };
        if (dialog.ShowDialog(this) != true) return;
        _vaultPath = dialog.FileName;
        SetMode(create: !File.Exists(_vaultPath));
    }

    private void LanguageDe_Click(object sender, RoutedEventArgs e) => SetLanguage("de");

    private void LanguageEn_Click(object sender, RoutedEventArgs e) => SetLanguage("en");

    private void SetLanguage(string language)
    {
        _settings.Language = language;
        _settings.Save();
        Loc.Apply(language);
        RefreshUnlockTexts();
    }

    // ---------------------------------------------------------------- list and details

    private string Filter => (NavList.SelectedItem as ListBoxItem)?.Tag as string ?? "all";

    private static bool InCategory(Entry entry, string filter) => filter switch
    {
        "favorites" => entry.Favorite,
        "passwords" => entry.Kind == EntryKind.Login && entry.Password.Length > 0,
        "passkeys" => entry.Passkey is not null,
        "authenticator" => entry.Totp is not null,
        "notes" => entry.Kind == EntryKind.Note,
        "cards" => entry.Kind == EntryKind.Card,
        "wifi" => entry.Kind == EntryKind.Wifi,
        _ => true,
    };

    private static string CountText(int count) => count == 0 ? "" : count.ToString();

    private void RefreshList(Entry? select = null)
    {
        if (_vault is null) return;
        select ??= _selected;
        string filter = Filter;
        string search = SearchBox.Text.Trim();
        var active = _vault.Data.Active.ToList();
        var trash = _vault.Data.Entries.Where(entry => entry.Deleted is not null).ToList();

        CountAll.Text = active.Count.ToString();
        CountFavorites.Text = CountText(active.Count(entry => InCategory(entry, "favorites")));
        CountPasswords.Text = CountText(active.Count(entry => InCategory(entry, "passwords")));
        CountPasskeys.Text = CountText(active.Count(entry => InCategory(entry, "passkeys")));
        CountCodes.Text = CountText(active.Count(entry => InCategory(entry, "authenticator")));
        CountNotes.Text = CountText(active.Count(entry => InCategory(entry, "notes")));
        CountCards.Text = CountText(active.Count(entry => InCategory(entry, "cards")));
        CountWifi.Text = CountText(active.Count(entry => InCategory(entry, "wifi")));
        CountTrash.Text = CountText(trash.Count);
        CountSecurity.Text = CountText(SecurityAudit.Local(active).Select(finding => finding.Entry)
            .Concat(_leaks.Where(pair => pair.Value > 0 && pair.Key.Deleted is null).Select(pair => pair.Key))
            .Distinct().Count());

        // "Security check" and "Credits" are pages that replace the list and the details.
        bool page = filter is "security" or "credits";
        ListColumn.Visibility = VisibleIf(!page);
        DetailColumn.Visibility = VisibleIf(!page);
        SecurityPage.Visibility = VisibleIf(filter == "security");
        CreditsPage.Visibility = VisibleIf(filter == "credits");
        if (filter == "security") RefreshSecurityPage();
        if (filter == "credits")
            CreditsAbout.Text = Loc.F("Credits.About", typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "");
        if (page) return;

        var inCategory = filter == "trash" ? trash : active.Where(entry => InCategory(entry, filter)).ToList();

        // Smart filter: every website and every tag in this category, with the number of entries.
        var sites = EntrySearch.Websites(inCategory);
        var tags = VaultOps.Tags(inCategory);
        _fillingWebsites = true;
        _filterKeys = sites.Select(site => "w:" + site.Domain).Concat(tags.Select(tag => "t:" + tag.Tag)).ToList();
        if (!_filterKeys.Contains(_smartFilter)) _smartFilter = "";
        WebsiteBox.ItemsSource = new[] { Loc.T("List.AllFilter") }
            .Concat(sites.Select(site => $"{site.Domain} ({site.Count})"))
            .Concat(tags.Select(tag => $"#{tag.Tag} ({tag.Count})")).ToList();
        WebsiteBox.SelectedIndex = _filterKeys.IndexOf(_smartFilter) + 1;
        WebsiteBox.Visibility = VisibleIf(_filterKeys.Count > 1);
        _fillingWebsites = false;

        bool Smart(Entry entry) =>
            _smartFilter.Length == 0 ||
            (_smartFilter[0] == 'w'
                ? EntrySearch.Domain(entry) == _smartFilter[2..]
                : entry.Tags.Contains(_smartFilter[2..], StringComparer.CurrentCultureIgnoreCase));

        _rows.Clear();
        var now = DateTimeOffset.UtcNow;
        foreach (var entry in inCategory.Where(entry => Smart(entry) && EntrySearch.Matches(entry, search))
                     .OrderBy(entry => entry.Title, StringComparer.CurrentCultureIgnoreCase))
        {
            var row = new EntryRow(entry)
            {
                Icon = _settings.Favicons ? _favicons.Get(_vault.Data, EntrySearch.Domain(entry)) : null,
            };
            row.Tick(now);
            _rows.Add(row);
        }
        if (_settings.Favicons) _ = FetchIconsAsync();

        bool unfiltered = search.Length == 0 && _smartFilter.Length == 0;
        EmptyListText.Visibility = _rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyListText.Text = Loc.T(filter switch
        {
            "passkeys" when unfiltered => "List.EmptyPasskeys",
            "authenticator" when unfiltered => "List.EmptyAuthenticator",
            "trash" when unfiltered => "List.EmptyTrash",
            _ => "List.Empty",
        });

        EntryList.SelectedItem = _rows.FirstOrDefault(row => row.Entry == select);
        if (EntryList.SelectedItem is null) ShowDetail(null);
    }

    /// <summary>Loads icons for websites that have none yet, then stores them in the vault.</summary>
    private async Task FetchIconsAsync()
    {
        if (_fetchingIcons || _vault is not { } vault) return;
        var domains = vault.Data.Active.Select(EntrySearch.Domain).Where(domain => domain.Length > 0 && !vault.Data.Icons.ContainsKey(domain)).Distinct().ToList();
        if (domains.Count == 0) return;
        _fetchingIcons = true;
        try
        {
            bool changed = await _favicons.FetchMissingAsync(vault.Data, domains, CancellationToken.None);
            if (!changed || _vault != vault) return;
            SaveVault();
        }
        finally
        {
            _fetchingIcons = false;
        }
        RefreshList();
    }

    private void WebsiteBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_fillingWebsites) return;
        int index = WebsiteBox.SelectedIndex;
        _smartFilter = index <= 0 || index > _filterKeys.Count ? "" : _filterKeys[index - 1];
        RefreshList();
    }

    private void NavList_SelectionChanged(object sender, SelectionChangedEventArgs e) => RefreshList();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => RefreshList();

    private void EntryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (EntryList.SelectedItem is EntryRow row) ShowDetail(row.Entry);
    }

    private static Visibility VisibleIf(bool condition) => condition ? Visibility.Visible : Visibility.Collapsed;

    private void ShowDetail(Entry? entry)
    {
        if (_selected != entry) _passwordShown = false;
        _selected = entry;
        DetailScroll.Visibility = VisibleIf(entry is not null);
        NoSelectionText.Visibility = VisibleIf(entry is null);
        if (entry is null)
        {
            DetailPassword.Text = "";
            DetailCode.Text = "";
            return;
        }

        DetailTitle.Text = string.IsNullOrWhiteSpace(entry.Title) ? "—" : entry.Title;
        DetailModified.Text = Loc.F("Detail.Modified", entry.Modified.ToLocalTime().ToString("g"));

        bool trashed = entry.Deleted is not null;
        FavoriteButton.Content = entry.Favorite ? "\uE735" : "\uE734";
        FavoriteButton.Visibility = VisibleIf(!trashed);
        DetailTags.Visibility = VisibleIf(entry.Tags.Count > 0);
        DetailTags.Text = Loc.F("Detail.Tags", string.Join(", ", entry.Tags));
        TrashInfo.Visibility = VisibleIf(trashed);
        if (entry.Deleted is { } deleted) TrashInfo.Text = Loc.F("Detail.InTrash", deleted.ToLocalTime().ToString("d"));
        EditButton.Visibility = DeleteButton.Visibility = VisibleIf(!trashed);
        RestoreButton.Visibility = PurgeButton.Visibility = VisibleIf(trashed);

        UsernameRow.Visibility = VisibleIf(entry.Username.Length > 0);
        UsernameLabel.Text = Loc.T(entry.Kind == EntryKind.Card ? "Card.Holder" : "Detail.Username");
        DetailUsername.Text = entry.Username;

        HistoryButton.Visibility = VisibleIf(entry.History.Count > 0);
        HistoryButton.Content = Loc.F("Detail.History", entry.History.Count);

        CardNumberRow.Visibility = VisibleIf(entry.CardNumber.Length > 0);
        DetailCardNumber.Text = _passwordShown ? entry.CardNumber
            : entry.CardNumber.Length >= 4 ? "•••• •••• •••• " + entry.CardNumber[^4..] : Mask;
        ShowCardButton.Content = Loc.T(_passwordShown ? "Detail.Hide" : "Detail.Show");
        CardExpiryRow.Visibility = VisibleIf(entry.CardExpiry.Length > 0);
        DetailCardExpiry.Text = entry.CardExpiry;
        CardCodeRow.Visibility = VisibleIf(entry.CardCode.Length > 0);
        DetailCardCode.Text = _passwordShown ? entry.CardCode : "•••";

        PasswordRow.Visibility = VisibleIf(entry.Password.Length > 0);
        if (_passwordShown) DisplayDialog.Colorize(DetailPassword, entry.Password);
        else DetailPassword.Text = Mask;
        WifiQrButton.Visibility = VisibleIf(entry.Kind == EntryKind.Wifi);
        ShowPasswordButton.Content = Loc.T(_passwordShown ? "Detail.Hide" : "Detail.Show");

        WebsiteRow.Visibility = VisibleIf(entry.Url.Length > 0);
        DetailWebsite.Text = entry.Url;
        OpenWebsiteButton.IsEnabled = WebUri(entry.Url) is not null;

        CodeRow.Visibility = VisibleIf(entry.Totp is not null);
        UpdateDetailCode(DateTimeOffset.UtcNow);

        PasskeyRow.Visibility = VisibleIf(entry.Passkey is not null);
        if (entry.Passkey is { } passkey)
        {
            string account = passkey.UserName.Length > 0 ? passkey.UserName : passkey.UserDisplayName;
            DetailPasskey.Text = Loc.F("Detail.PasskeyInfo", passkey.RpId, account, passkey.Created.ToLocalTime().ToString("d"));
        }

        NotesRow.Visibility = VisibleIf(entry.Notes.Length > 0);
        DetailNotes.Text = entry.Notes;
    }

    internal static string FormatCode(TotpConfig config, DateTimeOffset now)
    {
        try
        {
            string code = Totp.Compute(config, now);
            return code.Insert(code.Length / 2, " ");
        }
        catch (FormatException)
        {
            return "";
        }
    }

    private void UpdateDetailCode(DateTimeOffset now)
    {
        if (_selected?.Totp is not { } totp) return;
        int remaining = Totp.SecondsRemaining(totp, now);
        DetailCode.Text = FormatCode(totp, now);
        DetailCodeSeconds.Text = remaining + " s";
        DetailCodeProgress.Maximum = totp.Period > 0 ? totp.Period : 30;
        DetailCodeProgress.Value = remaining;
    }

    private static Uri? WebUri(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        string candidate = url.Contains("://", StringComparison.Ordinal) ? url : "https://" + url;
        return Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http" ? uri : null;
    }

    private void CopySecret(string text)
    {
        int seconds = _settings.ClipboardClearSeconds;
        if (!_clipboard.Copy(text, seconds)) ShowToast(Loc.T("Toast.CopyFailed"));
        else ShowToast(seconds > 0 ? Loc.F("Toast.Copied", seconds) : Loc.T("Toast.CopiedNoClear"));
    }

    private void ShowToast(string message)
    {
        ToastText.Text = message;
        Toast.Visibility = Visibility.Visible;
        _toastTimer.Stop();
        _toastTimer.Start();
    }

    private void CopyUsername_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not null) CopySecret(_selected.Username);
    }

    private void CopyPassword_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not null) CopySecret(_selected.Password);
    }

    private void CopyCardNumber_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not null) CopySecret(_selected.CardNumber.Replace(" ", ""));
    }

    private void CopyCardCode_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not null) CopySecret(_selected.CardCode);
    }

    private void History_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not null) new HistoryDialog(this, _selected, _clipboard, _settings).ShowDialog();
    }

    private void Favorite_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null || _vault is null) return;
        _selected.Favorite = !_selected.Favorite;
        SaveVault();
        RefreshList(_selected);
        ShowDetail(_selected);
    }

    private void CopyCode_Click(object sender, RoutedEventArgs e)
    {
        if (_selected?.Totp is { } totp) CopySecret(FormatCode(totp, DateTimeOffset.UtcNow).Replace(" ", ""));
    }

    private void ShowPassword_Click(object sender, RoutedEventArgs e)
    {
        _passwordShown = !_passwordShown;
        ShowDetail(_selected);
    }

    private void OpenWebsite_Click(object sender, RoutedEventArgs e)
    {
        // Only http(s) addresses are handed to the system, never arbitrary commands or files.
        if (_selected is null || WebUri(_selected.Url) is not { } uri) return;
        try
        {
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Win32Exception)
        {
        }
    }

    // ---------------------------------------------------------------- security check

    private void RefreshSecurityPage()
    {
        if (_vault is null) return;
        var entries = _vault.Data.Active.ToList();
        var local = SecurityAudit.Local(entries);
        var leaked = _leaks.Where(pair => pair.Value > 0 && entries.Contains(pair.Key)).ToList();

        var rows = new List<FindingRow>();
        rows.AddRange(leaked.Select(pair => new FindingRow(pair.Key, pair.Key.Title, Loc.F("Sec.Issue.Leaked", pair.Value.ToString("N0")))));
        rows.AddRange(local.Select(finding => new FindingRow(finding.Entry, finding.Entry.Title,
            finding.Issue == PasswordIssue.Reused ? Loc.F("Sec.Issue.Reused", finding.Count) : Loc.T("Sec.Issue.Weak"))));
        FindingList.ItemsSource = rows;
        FindingList.Visibility = VisibleIf(rows.Count > 0);

        int weak = local.Count(finding => finding.Issue == PasswordIssue.Weak);
        int reused = local.Count(finding => finding.Issue == PasswordIssue.Reused);
        SecuritySummary.Text =
            rows.Count == 0 ? Loc.T("Sec.AllGood") :
            _leaksChecked ? Loc.F("Sec.Summary", weak, reused, leaked.Count) : Loc.F("Sec.SummaryLocal", weak, reused);

        string typed = EmailBox.Text;
        var emails = EntrySearch.Emails(entries);
        EmailBox.ItemsSource = emails;
        EmailBox.Text = typed.Length > 0 ? typed : emails.FirstOrDefault() ?? "";
        if (ApiKeyBox.Password.Length == 0) ApiKeyBox.Password = _vault.Data.HibpApiKey;
    }

    private static string HibpMessage(HibpException error) => error.Code switch
    {
        "api-key" => Loc.T("Sec.Error.ApiKey"),
        "rate-limit" => Loc.T("Sec.Error.RateLimit"),
        _ => Loc.T("Sec.Error.Network"),
    };

    private async void CheckLeaks_Click(object sender, RoutedEventArgs e) => await RunLeakCheckAsync(silent: false);

    /// <summary>
    /// Asks Have I Been Pwned about every distinct password; only a hash prefix is sent.
    /// The weekly monitor runs this silently and only speaks up when it finds something.
    /// </summary>
    private async Task RunLeakCheckAsync(bool silent)
    {
        if (_vault is not { } vault || !CheckLeaksButton.IsEnabled) return;
        var groups = vault.Data.Active.Where(entry => entry.Password.Length > 0)
            .GroupBy(entry => entry.Password, StringComparer.Ordinal).ToList();

        CheckLeaksButton.IsEnabled = false;
        _leaks.Clear();
        _leaksChecked = false;
        try
        {
            int done = 0;
            foreach (var group in groups)
            {
                LeakStatus.Text = Loc.F("Sec.Checking", ++done, groups.Count);
                long count = await _hibp.PasswordLeakCountAsync(group.Key);
                if (_vault != vault) return;
                foreach (var entry in group) _leaks[entry] = count;
            }
            _leaksChecked = true;
            LeakStatus.Text = "";
            vault.Data.LastLeakCheck = DateTimeOffset.UtcNow;
            SaveVault();
            int leaked = _leaks.Count(pair => pair.Value > 0);
            if (silent && leaked > 0) ShowToast(Loc.F("Toast.LeaksFound", leaked));
        }
        catch (HibpException error)
        {
            if (_vault == vault) LeakStatus.Text = silent ? "" : HibpMessage(error);
        }
        finally
        {
            CheckLeaksButton.IsEnabled = true;
            if (_vault == vault) RefreshList();
        }
    }

    private async void CheckEmail_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is not { } vault) return;
        string email = EmailBox.Text.Trim(), key = ApiKeyBox.Password.Trim();
        if (!EntrySearch.LooksLikeEmail(email)) { EmailResult.Text = Loc.T("Sec.Email.Invalid"); return; }
        if (key.Length == 0) { EmailResult.Text = Loc.T("Sec.Email.NeedKey"); return; }

        CheckEmailButton.IsEnabled = false;
        EmailResult.Text = "";
        try
        {
            var breaches = await _hibp.BreachesForEmailAsync(email, key);
            if (_vault != vault) return;
            if (vault.Data.HibpApiKey != key)
            {
                // The key worked, so remember it (encrypted, inside the vault).
                vault.Data.HibpApiKey = key;
                SaveVault();
            }
            EmailResult.Text = breaches.Count == 0
                ? Loc.F("Sec.Email.Clean", email)
                : Loc.F("Sec.Email.Found", email, breaches.Count, string.Join(", ", breaches));
        }
        catch (HibpException error)
        {
            if (_vault == vault) EmailResult.Text = HibpMessage(error);
        }
        finally
        {
            CheckEmailButton.IsEnabled = true;
        }
    }

    private void OpenHibp_Click(object sender, RoutedEventArgs e) => OpenInBrowser("https://haveibeenpwned.com/");

    private void CreatorWebsite_Click(object sender, RoutedEventArgs e) => OpenInBrowser("http://justyin-dev.de/");

    private static void OpenInBrowser(string address)
    {
        try
        {
            Process.Start(new ProcessStartInfo(address) { UseShellExecute = true });
        }
        catch (Win32Exception)
        {
        }
    }

    /// <summary>Choosing a finding jumps to that entry so it can be fixed.</summary>
    private void FindingList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FindingList.SelectedItem is not FindingRow row) return;
        FindingList.SelectedItem = null;
        _smartFilter = "";
        SearchBox.Clear();
        NavList.SelectedIndex = 0;
        RefreshList(row.Entry);
    }

    // ---------------------------------------------------------------- editing

    private bool SaveVault()
    {
        if (_vault is null) return false;
        try
        {
            _vault.Save();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, Loc.F("Detail.SaveFailed", ex.Message), "Krypta", MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
    }

    private void NewEntry_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new EntryDialog(this, null, _clipboard, _settings);
        if (dialog.ShowDialog() != true || _vault is null) return;
        _vault.Data.Entries.Add(dialog.Entry);
        SaveVault();
        RefreshList(dialog.Entry);
    }

    private void EditEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null) return;
        var dialog = new EntryDialog(this, _selected, _clipboard, _settings);
        if (dialog.ShowDialog() != true || _vault is null) return;
        SaveVault();
        RefreshList(dialog.Entry);
        ShowDetail(dialog.Entry);
    }

    /// <summary>Deleting moves an entry to the trash, where it stays for 30 days.</summary>
    private void DeleteEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null || _vault is null) return;
        VaultOps.MoveToTrash(_selected, DateTimeOffset.UtcNow);
        _selected = null;
        SaveVault();
        RefreshList();
        ShowToast(Loc.T("Toast.Trashed"));
    }

    private void RestoreEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null || _vault is null) return;
        VaultOps.Restore(_selected);
        _selected = null;
        SaveVault();
        RefreshList();
        ShowToast(Loc.T("Toast.Restored"));
    }

    private void PurgeEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null || _vault is null) return;
        string message = Loc.F("Detail.DeleteConfirm", _selected.Title);
        if (_selected.Passkey is not null) message += "\n\n" + Loc.T("Detail.DeletePasskeyWarn");
        var answer = MessageBox.Show(this, message, "Krypta", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);
        if (answer != MessageBoxResult.OK || _vault is null || _selected is null) return;
        _vault.Data.Entries.Remove(_selected);
        _selected = null;
        SaveVault();
        RefreshList();
    }

    private void Generator_Click(object sender, RoutedEventArgs e) =>
        new GeneratorDialog(this, forEntry: false, _clipboard, _settings).ShowDialog();

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null) return;
        new SettingsDialog(this, _settings, _vault, _deviceKey, _clipboard).ShowDialog();
        Hardening.SetCaptureExcluded(this, false);
        if (_vault is not null)
        {
            RefreshList();
            ShowDetail(_selected);
        }
    }

    private void Lock_Click(object sender, RoutedEventArgs e) => LockVault();

    // ---------------------------------------------------------------- passkeys (browser extension)

    private static JsonObject Fallback(string reason) =>
        new() { ["ok"] = false, ["fallback"] = true, ["error"] = reason };

    private void BringToFront()
    {
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Show();
        Topmost = true;
        Activate();
        Topmost = false;
    }

    /// <summary>
    /// Answers one request from the browser extension. Nothing is created or signed without the
    /// user confirming it in a Krypta window, and only while the vault is unlocked.
    /// </summary>
    private async Task<JsonObject> HandlePasskeyRequestAsync(JsonElement request)
    {
        string type = request.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";
        if (type == "status") return new JsonObject { ["ok"] = true, ["locked"] = _vault is null };
        if (type is "logins" or "fill") return await HandleAutofillAsync(type, request);
        if (type is not ("create" or "get")) return Fallback("bad-request");
        if (!request.TryGetProperty("origin", out var o) || o.GetString() is not { Length: > 0 } origin ||
            !request.TryGetProperty("options", out var options) || options.ValueKind != JsonValueKind.Object)
            return Fallback("bad-request");

        if (!await _passkeyGate.WaitAsync(0)) return Fallback("busy");
        try
        {
            // Refuse requests that do not belong to the site before bothering the user.
            string? requestedRpId = type == "create"
                ? (options.TryGetProperty("rp", out var rp) && rp.ValueKind == JsonValueKind.Object && rp.TryGetProperty("id", out var id) ? id.GetString() : null)
                : (options.TryGetProperty("rpId", out var rpId) ? rpId.GetString() : null);
            string site = WebAuthn.ResolveRpId(requestedRpId, origin);

            if (_vault is null && !await WaitForUnlockAsync()) return Fallback("locked");
            var vault = _vault!;
            var passkeys = vault.Data.Active.Where(entry => entry.Passkey is not null).ToList();

            if (type == "create")
            {
                string account = options.TryGetProperty("user", out var user) && user.TryGetProperty("name", out var name) ? name.GetString() ?? "" : "";
                // Run the checks (ES256 support, duplicates) before asking; the key made here is discarded.
                WebAuthn.CreateCredential(options, origin, passkeys.Select(entry => entry.Passkey!));

                BringToFront();
                var prompt = new PasskeyPromptDialog(this, Loc.F("Passkey.Create", site, account), null, Loc.T("Passkey.Confirm.Create"));
                if (prompt.ShowDialog() != true || _vault != vault) return Fallback("declined");

                var (response, passkey) = WebAuthn.CreateCredential(options, origin, passkeys.Select(entry => entry.Passkey!));
                var entry = new Entry
                {
                    Title = passkey.RpName.Length > 0 ? passkey.RpName : passkey.RpId,
                    Username = passkey.UserName,
                    Url = origin,
                    Passkey = passkey,
                };
                vault.Data.Entries.Add(entry);
                if (!SaveVault())
                {
                    vault.Data.Entries.Remove(entry);
                    return Fallback("save-failed");
                }
                RefreshList(entry);
                ShowToast(Loc.F("Toast.PasskeySaved", passkey.RpId));
                return new JsonObject { ["ok"] = true, ["credential"] = response };
            }
            else
            {
                var candidates = WebAuthn.FindCandidates(options, origin, passkeys.Select(entry => entry.Passkey!));
                if (candidates.Count == 0) return Fallback("no-passkey");

                BringToFront();
                var labels = candidates.Select(p => p.UserName.Length > 0 ? p.UserName : p.UserDisplayName.Length > 0 ? p.UserDisplayName : p.RpId).ToList();
                var prompt = new PasskeyPromptDialog(this, Loc.F("Passkey.Get", site), labels, Loc.T("Passkey.Confirm.Get"));
                if (prompt.ShowDialog() != true || _vault != vault) return Fallback("declined");

                var response = WebAuthn.GetAssertion(options, origin, candidates[prompt.SelectedIndex]);
                return new JsonObject { ["ok"] = true, ["credential"] = response };
            }
        }
        catch (WebAuthnException ex)
        {
            return new JsonObject { ["ok"] = false, ["domError"] = ex.Name, ["message"] = ex.Message };
        }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or CryptographicException or JsonException)
        {
            return Fallback("bad-request");
        }
        finally
        {
            _passkeyGate.Release();
        }
    }

    /// <summary>
    /// The browser popup asks which logins belong to the open website ("logins") and for one of
    /// them to be filled in ("fill"). A password is only handed out for a matching website and
    /// after a confirmation click in a Krypta window.
    /// </summary>
    private async Task<JsonObject> HandleAutofillAsync(string type, JsonElement request)
    {
        if (!request.TryGetProperty("origin", out var o) || o.GetString() is not { Length: > 0 } origin) return Fallback("bad-request");
        if (_vault is not { } vault) return Fallback("locked");

        var matches = vault.Data.Active
            .Where(entry => entry.Kind == EntryKind.Login && entry.Password.Length > 0 && EntrySearch.MatchesOrigin(entry, origin))
            .OrderBy(entry => entry.Title, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        if (type == "logins")
        {
            var logins = new JsonArray();
            foreach (var entry in matches)
                logins.Add(new JsonObject { ["id"] = entry.Id.ToString(), ["title"] = entry.Title, ["username"] = entry.Username });
            return new JsonObject { ["ok"] = true, ["logins"] = logins };
        }

        string id = request.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "";
        var chosen = matches.FirstOrDefault(entry => entry.Id.ToString() == id);
        if (chosen is null) return Fallback("no-match");

        if (!await _passkeyGate.WaitAsync(0)) return Fallback("busy");
        try
        {
            BringToFront();
            string site = new Uri(origin).Host;
            var prompt = new PasskeyPromptDialog(this, Loc.F("Fill.Confirm", site, chosen.Username), null, Loc.T("Fill.Button"));
            if (prompt.ShowDialog() != true || _vault != vault) return Fallback("declined");
            return new JsonObject { ["ok"] = true, ["username"] = chosen.Username, ["password"] = chosen.Password };
        }
        finally
        {
            _passkeyGate.Release();
        }
    }

    private async Task<bool> WaitForUnlockAsync()
    {
        _unlockWaiter = new TaskCompletionSource<bool>();
        PasskeyBanner.Visibility = Visibility.Visible;
        BringToFront();
        PasswordInput.Focus();
        try
        {
            await Task.WhenAny(_unlockWaiter.Task, Task.Delay(TimeSpan.FromSeconds(90)));
            return _vault is not null;
        }
        finally
        {
            _unlockWaiter = null;
            PasskeyBanner.Visibility = Visibility.Collapsed;
        }
    }
}
