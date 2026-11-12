using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using Krypta.App.Services;
using Krypta.Core;

namespace Krypta.App;

/// <summary>Creates or edits an entry, including scanning a two-factor QR code.</summary>
public partial class EntryDialog : Window
{
    private readonly ClipboardService _clipboard;
    private readonly AppSettings _settings;
    private readonly bool _isNew;
    private static readonly EntryKind[] Kinds = [EntryKind.Login, EntryKind.Note, EntryKind.Card, EntryKind.Wifi];
    private TotpConfig? _scanned;

    /// <summary>The entry being edited. It is only changed when the user saves.</summary>
    public Entry Entry { get; }

    internal EntryDialog(Window owner, Entry? existing, ClipboardService clipboard, AppSettings settings)
    {
        _clipboard = clipboard;
        _settings = settings;
        _isNew = existing is null;
        Entry = existing ?? new Entry();
        Owner = owner;
        InitializeComponent();
        Hardening.Protect(this);

        Title = Loc.T(_isNew ? "Entry.TitleNew" : "Entry.TitleEdit");
        KindBox.ItemsSource = new[] { Loc.T("Kind.Login"), Loc.T("Kind.Note"), Loc.T("Kind.Card"), Loc.T("Kind.Wifi") };
        KindBox.SelectedIndex = Array.IndexOf(Kinds, Entry.Kind);
        CardNumberInput.Text = Entry.CardNumber;
        CardExpiryInput.Text = Entry.CardExpiry;
        CardCodeInput.Text = Entry.CardCode;
        TagsInput.Text = string.Join(", ", Entry.Tags);
        FavoriteCheck.IsChecked = Entry.Favorite;
        ApplyKind();
        TitleInput.Text = Entry.Title;
        UsernameInput.Text = Entry.Username;
        PasswordInput.Text = Entry.Password;
        UrlInput.Text = Entry.Url;
        NotesInput.Text = Entry.Notes;
        _scanned = Entry.Totp;
        SecretInput.Text = Entry.Totp?.Secret ?? "";
        if (Entry.Passkey is { } passkey)
        {
            PasskeyInfo.Text = Loc.F("Entry.HasPasskey", passkey.RpId);
            PasskeyInfo.Visibility = Visibility.Visible;
        }
        Loaded += (_, _) => TitleInput.Focus();
    }

    private EntryKind Kind => KindBox.SelectedIndex >= 0 ? Kinds[KindBox.SelectedIndex] : EntryKind.Login;

    private void Kind_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (IsInitialized && TitleLabel is not null) ApplyKind();
    }

    /// <summary>Shows only the fields that make sense for the chosen type.</summary>
    private void ApplyKind()
    {
        var kind = Kind;
        static Visibility If(bool visible) => visible ? Visibility.Visible : Visibility.Collapsed;
        TitleLabel.Text = Loc.T(kind == EntryKind.Wifi ? "Entry.NetworkName" : "Entry.Name");
        UsernameLabel.Text = Loc.T(kind == EntryKind.Card ? "Card.Holder" : "Detail.Username");
        UsernamePanel.Visibility = If(kind is EntryKind.Login or EntryKind.Card);
        CardPanel.Visibility = If(kind == EntryKind.Card);
        PasswordPanel.Visibility = If(kind is EntryKind.Login or EntryKind.Wifi);
        LoginPanel.Visibility = If(kind == EntryKind.Login);
    }

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        var generator = new GeneratorDialog(this, forEntry: true, _clipboard, _settings);
        if (generator.ShowDialog() == true) PasswordInput.Text = generator.Password;
    }

    // ---------------------------------------------------------------- QR code scanning

    private async void ScanScreen_Click(object sender, RoutedEventArgs e)
    {
        // Krypta's own windows are taken out of the capture, so they never cover the QR code
        // and the vault is never part of the screenshot.
        Window[] windows = Owner is null ? [this] : [this, Owner];
        foreach (var window in windows) Hardening.SetCaptureExcluded(window, true);
        IsEnabled = false;
        try
        {
            await Task.Delay(250);
            var (pixels, width, height) = ScreenCapture.CaptureAllScreens();
            var texts = await Task.Run(() => QrDecoder.Decode(pixels, width, height));
            Array.Clear(pixels);
            ApplyScan(texts);
        }
        finally
        {
            IsEnabled = true;
            foreach (var window in windows) Hardening.SetCaptureExcluded(window, false);
        }
    }

    private async void ScanFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = Loc.T("Entry.ImageFilter") };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var image = new BitmapImage();
            image.BeginInit();
            image.CacheOption = BitmapCacheOption.OnLoad;
            image.UriSource = new Uri(dialog.FileName);
            image.EndInit();
            image.Freeze();
            await ScanImageAsync(image);
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException or FileFormatException or COMException or UnauthorizedAccessException)
        {
            ShowScanStatus(Loc.T("Entry.Scan.BadImage"));
        }
    }

    private async void ScanClipboard_Click(object sender, RoutedEventArgs e)
    {
        BitmapSource? image = null;
        try
        {
            if (Clipboard.ContainsImage()) image = Clipboard.GetImage();
        }
        catch (COMException)
        {
        }
        if (image is null)
        {
            ShowScanStatus(Loc.T("Entry.Scan.NoImage"));
            return;
        }
        image.Freeze();
        await ScanImageAsync(image);
    }

    private async Task ScanImageAsync(BitmapSource image)
    {
        var (pixels, width, height) = ScreenCapture.FromBitmap(image);
        ApplyScan(await Task.Run(() => QrDecoder.Decode(pixels, width, height)));
    }

    private void ApplyScan(List<string> texts)
    {
        foreach (string text in texts.Where(t => t.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                var config = Totp.ParseUri(text);
                _scanned = config;
                SecretInput.Text = config.Secret;
                if (TitleInput.Text.Trim().Length == 0) TitleInput.Text = config.Issuer.Length > 0 ? config.Issuer : config.Account;
                if (UsernameInput.Text.Trim().Length == 0) UsernameInput.Text = config.Account;
                string label = config.Issuer.Length > 0 && config.Account.Length > 0 ? $"{config.Issuer} ({config.Account})"
                    : config.Issuer.Length > 0 ? config.Issuer : config.Account;
                ShowScanStatus(Loc.F("Entry.Scan.Found", label));
                return;
            }
            catch (Exception ex) when (ex is FormatException or NotSupportedException)
            {
            }
        }
        ShowScanStatus(Loc.T(texts.Count > 0 ? "Entry.Scan.Unsupported" : "Entry.Scan.None"));
    }

    private void ShowScanStatus(string message)
    {
        ScanStatus.Text = message;
        ScanStatus.Visibility = Visibility.Visible;
    }

    // ---------------------------------------------------------------- saving

    private bool TryReadTotp(out TotpConfig? totp)
    {
        totp = null;
        string text = SecretInput.Text.Trim();
        if (text.Length == 0) return true;
        try
        {
            if (text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                totp = Totp.ParseUri(text);
                return true;
            }
            string secret = text.Replace(" ", "").Replace("-", "").TrimEnd('=').ToUpperInvariant();
            if (!Base32.TryDecode(secret, out byte[] key) || key.Length == 0) return false;
            Array.Clear(key);
            // Keep issuer, digits and period from a scan as long as the secret was not retyped.
            totp = _scanned is not null && _scanned.Secret == secret ? _scanned : new TotpConfig { Secret = secret };
            return true;
        }
        catch (Exception ex) when (ex is FormatException or NotSupportedException)
        {
            return false;
        }
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        string title = TitleInput.Text.Trim();
        if (title.Length == 0)
        {
            ShowError(Loc.T("Entry.Error.Name"));
            TitleInput.Focus();
            return;
        }
        var kind = Kind;
        TotpConfig? totp = null;
        if (kind == EntryKind.Login && !TryReadTotp(out totp))
        {
            ShowError(Loc.T("Entry.Error.Secret"));
            SecretInput.Focus();
            return;
        }

        var now = DateTimeOffset.UtcNow;
        bool login = kind == EntryKind.Login, card = kind == EntryKind.Card;
        Entry.Kind = kind;
        Entry.Title = title;
        Entry.Username = login || card ? UsernameInput.Text.Trim() : "";
        // Fields that do not belong to the type are cleared, except a passkey, which is never dropped silently.
        VaultOps.SetPassword(Entry, login || kind == EntryKind.Wifi ? PasswordInput.Text : "", now);
        Entry.Url = login ? UrlInput.Text.Trim() : "";
        Entry.Totp = login ? totp : null;
        Entry.CardNumber = card ? CardNumberInput.Text.Trim() : "";
        Entry.CardExpiry = card ? CardExpiryInput.Text.Trim() : "";
        Entry.CardCode = card ? CardCodeInput.Text.Trim() : "";
        Entry.Notes = NotesInput.Text.Trim();
        Entry.Tags = VaultOps.ParseTags(TagsInput.Text);
        Entry.Favorite = FavoriteCheck.IsChecked == true;
        Entry.Modified = now;
        DialogResult = true;
    }
}
