using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Krypta.App.Services;
using Krypta.Core;
using Microsoft.Win32;

namespace Krypta.App;

public partial class SettingsDialog : Window
{
    private static readonly int[] AutoLockChoices = [1, 5, 15, 30, 0];
    private static readonly int[] ClipboardChoices = [10, 20, 30, 60];
    private static readonly string[] LanguageChoices = ["system", "de", "en"];
    private static readonly string[] ThemeChoices = ["system", "light", "dark"];

    private readonly AppSettings _settings;
    private readonly Vault _vault;
    private readonly IDeviceKeyProvider _deviceKey;
    private readonly ClipboardService _clipboard;
    private bool _ready;

    internal SettingsDialog(Window owner, AppSettings settings, Vault vault, IDeviceKeyProvider deviceKey, ClipboardService clipboard)
    {
        _settings = settings;
        _vault = vault;
        _deviceKey = deviceKey;
        _clipboard = clipboard;
        Owner = owner;
        InitializeComponent();
        Hardening.Protect(this);
        FillChoices();
        CaptureCheck.IsChecked = settings.BlockScreenCapture;
        MinimizeCheck.IsChecked = settings.LockOnMinimize;
        TrayCheck.IsChecked = settings.CloseToTray;
        MonitorCheck.IsChecked = settings.LeakMonitor;
        IconsCheck.IsChecked = settings.Favicons;
        RefreshBrowserStatus();
        _ready = true;
    }

    private void FillChoices()
    {
        _ready = false;
        LanguageBox.ItemsSource = new[] { Loc.T("Settings.Language.System"), "Deutsch", "English" };
        LanguageBox.SelectedIndex = Math.Max(0, Array.IndexOf(LanguageChoices, _settings.Language));

        ThemeBox.ItemsSource = new[] { Loc.T("Settings.Theme.System"), Loc.T("Settings.Theme.Light"), Loc.T("Settings.Theme.Dark") };
        ThemeBox.SelectedIndex = Math.Max(0, Array.IndexOf(ThemeChoices, _settings.Theme));
        AccentBox.ItemsSource = Appearance.Accents.Select(accent => Loc.T("Accent." + accent.Key)).ToList();
        AccentBox.SelectedIndex = Math.Max(0, Array.FindIndex(Appearance.Accents, accent => accent.Key == _settings.Accent));

        AutoLockBox.ItemsSource = AutoLockChoices.Select(m => m == 0 ? Loc.T("Settings.Never") : Loc.F("Settings.Minutes", m)).ToList();
        int autoLock = Array.IndexOf(AutoLockChoices, _settings.AutoLockMinutes);
        AutoLockBox.SelectedIndex = autoLock < 0 ? 1 : autoLock;

        ClipboardBox.ItemsSource = ClipboardChoices.Select(s => Loc.F("Settings.Seconds", s)).ToList();
        int clipboard = Array.IndexOf(ClipboardChoices, _settings.ClipboardClearSeconds);
        ClipboardBox.SelectedIndex = clipboard < 0 ? 1 : clipboard;

        RefreshDevice();
        _ready = true;
    }

    private void Language_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || LanguageBox.SelectedIndex < 0) return;
        _settings.Language = LanguageChoices[LanguageBox.SelectedIndex];
        _settings.Save();
        Loc.Apply(_settings.Language);
        FillChoices();
        RefreshBrowserStatus();
    }

    private void Appearance_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || ThemeBox.SelectedIndex < 0 || AccentBox.SelectedIndex < 0) return;
        _settings.Theme = ThemeChoices[ThemeBox.SelectedIndex];
        _settings.Accent = Appearance.Accents[AccentBox.SelectedIndex].Key;
        _settings.Save();
        Appearance.Apply(_settings.Theme, _settings.Accent);
    }

    private void Option_Changed(object sender, RoutedEventArgs e)
    {
        _settings.LockOnMinimize = MinimizeCheck.IsChecked == true;
        _settings.CloseToTray = TrayCheck.IsChecked == true;
        _settings.LeakMonitor = MonitorCheck.IsChecked == true;
        _settings.Favicons = IconsCheck.IsChecked == true;
        _settings.Save();
    }

    private void AutoLock_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || AutoLockBox.SelectedIndex < 0) return;
        _settings.AutoLockMinutes = AutoLockChoices[AutoLockBox.SelectedIndex];
        _settings.Save();
    }

    private void Clipboard_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || ClipboardBox.SelectedIndex < 0) return;
        _settings.ClipboardClearSeconds = ClipboardChoices[ClipboardBox.SelectedIndex];
        _settings.Save();
    }

    private void Capture_Changed(object sender, RoutedEventArgs e)
    {
        _settings.BlockScreenCapture = CaptureCheck.IsChecked == true;
        _settings.Save();
        Hardening.BlockScreenCapture = _settings.BlockScreenCapture;
        Hardening.SetCaptureExcluded(this, false);
    }

    // ---------------------------------------------------------------- device binding

    private void RefreshDevice()
    {
        bool bound = _vault.IsDeviceBound;
        DeviceText.Text = Loc.T(bound ? "Settings.Device.On" : "Settings.Device.Off");
        DeviceButton.Content = Loc.T(bound ? "Settings.Device.Unbind" : "Settings.Device.Bind");
        DeviceButton.IsEnabled = bound || _deviceKey.IsAvailable;
        RecoveryButton.Visibility = bound ? Visibility.Visible : Visibility.Collapsed;

        bool keyFile = _vault.UsesKeyFile;
        KeyFileText.Text = Loc.T(keyFile ? "Settings.KeyFile.On" : "Settings.KeyFile.Off");
        KeyFileButton.Content = Loc.T(keyFile ? "Settings.KeyFile.Disable" : "Settings.KeyFile.Enable");
    }

    private void ShowDeviceStatus(string? message, bool error = true)
    {
        DeviceStatus.Text = message ?? "";
        DeviceStatus.Visibility = message is null ? Visibility.Collapsed : Visibility.Visible;
        DeviceStatus.SetResourceReference(TextBlock.ForegroundProperty, error ? "SystemFillColorCriticalBrush" : "TextFillColorPrimaryBrush");
    }

    /// <summary>
    /// Makes a key file a required second factor, or stops requiring it. Needs the master password.
    /// A new key file is written first and removed again if the vault could not be changed.
    /// </summary>
    private async void KeyFile_Click(object sender, RoutedEventArgs e)
    {
        string password = DevicePassword.Password;
        bool enable = !_vault.UsesKeyFile;
        ShowDeviceStatus(null);

        byte[]? keyFile = null;
        string? keyFilePath = null;
        if (enable)
        {
            // Check the password before a file is written anywhere.
            bool correct;
            try { correct = await Task.Run(() => _vault.VerifyPassword(password)); }
            catch (ObjectDisposedException) { return; }
            if (!correct) { ShowDeviceStatus(Loc.T("Settings.CurrentWrong")); return; }

            var dialog = new SaveFileDialog { Filter = Loc.T("Unlock.KeyFileFilter"), FileName = "krypta.key" };
            if (dialog.ShowDialog(this) != true) return;
            keyFilePath = dialog.FileName;
            keyFile = Vault.NewKeyFile();
        }

        KeyFileButton.IsEnabled = false;
        bool written = false;
        try
        {
            if (keyFilePath is not null)
            {
                File.WriteAllBytes(keyFilePath, keyFile!);
                written = true;
            }
            await Task.Run(() => _vault.SetKeyFile(password, keyFile));
            written = false; // the vault now depends on the file: keep it
            DevicePassword.Clear();
            if (keyFilePath is not null) ShowDeviceStatus(Loc.F("Settings.KeyFile.Created", keyFilePath), error: false);
        }
        catch (WrongPasswordException)
        {
            ShowDeviceStatus(Loc.T("Settings.CurrentWrong"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            ShowDeviceStatus(Loc.F("Detail.SaveFailed", ex.Message));
        }
        finally
        {
            if (written && keyFilePath is not null)
            {
                try { File.Delete(keyFilePath); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
            KeyFileButton.IsEnabled = true;
            RefreshDevice();
        }
    }

    /// <summary>Binds the vault to this device's TPM, or removes the binding. Needs the master password.</summary>
    private async void Device_Click(object sender, RoutedEventArgs e)
    {
        string password = DevicePassword.Password;
        bool bind = !_vault.IsDeviceBound;
        if (bind && !_deviceKey.IsAvailable) { ShowDeviceStatus(Loc.T("Unlock.BindUnavailable")); return; }
        var previous = _vault.Header.Device;

        ShowDeviceStatus(null);
        DeviceButton.IsEnabled = false;
        try
        {
            string? recoveryKey = await Task.Run(() => _vault.SetDeviceBinding(password, bind ? _deviceKey : null));
            DevicePassword.Clear();
            if (previous is not null) _deviceKey.Delete(previous);
            RefreshDevice();
            if (recoveryKey is not null) new RecoveryKeyDialog(this, recoveryKey, _clipboard, _settings).ShowDialog();
        }
        catch (WrongPasswordException)
        {
            ShowDeviceStatus(Loc.T("Settings.CurrentWrong"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or ObjectDisposedException)
        {
            ShowDeviceStatus(Loc.F("Detail.SaveFailed", ex.Message));
        }
        finally
        {
            RefreshDevice();
        }
    }

    private async void ShowRecovery_Click(object sender, RoutedEventArgs e)
    {
        string password = DevicePassword.Password;
        ShowDeviceStatus(null);
        bool correct;
        try
        {
            correct = await Task.Run(() => _vault.VerifyPassword(password));
        }
        catch (ObjectDisposedException)
        {
            return;
        }
        if (!correct || _vault.RecoveryKey is not { } recoveryKey) { ShowDeviceStatus(Loc.T("Settings.CurrentWrong")); return; }
        DevicePassword.Clear();
        new RecoveryKeyDialog(this, recoveryKey, _clipboard, _settings).ShowDialog();
    }

    // ---------------------------------------------------------------- backup, import, export

    private void ShowDataStatus(string message, bool error = false)
    {
        DataStatus.Text = message;
        DataStatus.Visibility = Visibility.Visible;
        DataStatus.SetResourceReference(TextBlock.ForegroundProperty, error ? "SystemFillColorCriticalBrush" : "TextFillColorPrimaryBrush");
    }

    /// <summary>A backup is a copy of the already encrypted vault file.</summary>
    private void Backup_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Filter = Loc.T("Data.BackupFilter"),
            FileName = $"krypta-backup-{DateTime.Now:yyyy-MM-dd}.krypta",
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            if (string.Equals(Path.GetFullPath(dialog.FileName), Path.GetFullPath(_vault.Path), StringComparison.OrdinalIgnoreCase)) return;
            _vault.Save();
            File.Copy(_vault.Path, dialog.FileName, overwrite: true);
            ShowDataStatus(Loc.F("Data.BackupDone", dialog.FileName));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            ShowDataStatus(Loc.F("Detail.SaveFailed", ex.Message), error: true);
        }
    }

    private void Import_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = Loc.T("Data.CsvFilter") };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var imported = Transfer.ImportCsv(File.ReadAllText(dialog.FileName, Encoding.UTF8), _vault.Data.Entries);
            if (imported.Count == 0) { ShowDataStatus(Loc.T("Data.ImportNone")); return; }
            _vault.Data.Entries.AddRange(imported);
            _vault.Save();
            ShowDataStatus(Loc.F("Data.ImportDone", imported.Count));
        }
        catch (FormatException ex)
        {
            ShowDataStatus(Loc.F("Data.ImportFailed", ex.Message), error: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            ShowDataStatus(Loc.F("Data.ImportFailed", ex.Message), error: true);
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var answer = MessageBox.Show(this, Loc.T("Data.ExportWarn"), "Krypta", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);
        if (answer != MessageBoxResult.OK) return;
        var dialog = new SaveFileDialog { Filter = Loc.T("Data.CsvFilter"), FileName = "krypta-export.csv" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var entries = _vault.Data.Active.ToList();
            string csv = Transfer.ExportCsv(entries);
            File.WriteAllText(dialog.FileName, csv, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            ShowDataStatus(Loc.F("Data.ExportDone", Csv.Parse(csv).Count - 1, dialog.FileName));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowDataStatus(Loc.F("Detail.SaveFailed", ex.Message), error: true);
        }
    }

    // ---------------------------------------------------------------- browser integration

    private void RefreshBrowserStatus()
    {
        bool installed = BrowserIntegration.IsInstalled;
        BrowserStatus.Text = Loc.T(installed ? "Settings.Browser.On" : "Settings.Browser.Off");
        BrowserButton.Content = Loc.T(installed ? "Settings.Browser.Remove" : "Settings.Browser.Install");
    }

    private void Browser_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (BrowserIntegration.IsInstalled) BrowserIntegration.Uninstall();
            else BrowserIntegration.Install();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            MessageBox.Show(this, ex.Message, "Krypta", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        RefreshBrowserStatus();
    }

    // ---------------------------------------------------------------- master password

    private void ShowPasswordStatus(string message, bool error)
    {
        PasswordStatus.Text = message;
        PasswordStatus.Visibility = Visibility.Visible;
        PasswordStatus.SetResourceReference(TextBlock.ForegroundProperty,
            error ? "SystemFillColorCriticalBrush" : "SystemFillColorSuccessBrush");
    }

    private async void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        string current = CurrentPassword.Password, next = NewPassword.Password;
        if (next.Length < 10) { ShowPasswordStatus(Loc.T("Unlock.Error.TooShort"), true); return; }
        if (next != ConfirmPassword.Password) { ShowPasswordStatus(Loc.T("Unlock.Error.Mismatch"), true); return; }

        ChangeButton.IsEnabled = false;
        try
        {
            bool changed = await Task.Run(() =>
            {
                if (!_vault.VerifyPassword(current)) return false;
                _vault.ChangePassword(next);
                return true;
            });
            if (!changed)
            {
                ShowPasswordStatus(Loc.T("Settings.CurrentWrong"), true);
                return;
            }
            CurrentPassword.Clear();
            NewPassword.Clear();
            ConfirmPassword.Clear();
            ShowPasswordStatus(Loc.T("Settings.Changed"), false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            ShowPasswordStatus(Loc.F("Detail.SaveFailed", ex.Message), true);
        }
        finally
        {
            ChangeButton.IsEnabled = true;
        }
    }
}
