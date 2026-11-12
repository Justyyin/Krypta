using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Xml.Linq;
using Krypta.App;
using Krypta.App.Services;
using Krypta.Core;

namespace Krypta.Tests;

internal static class Repo
{
    public static string Root
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Krypta.slnx"))) dir = dir.Parent;
            return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
        }
    }
}

public class LocalizationTests
{
    private static Dictionary<string, string> Load(string language)
    {
        XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
        var document = XDocument.Load(Path.Combine(Repo.Root, "src", "Krypta.App", "Resources", $"Strings.{language}.xaml"));
        return document.Root!.Elements().ToDictionary(e => e.Attribute(x + "Key")!.Value, e => e.Value);
    }

    [Fact]
    public void German_and_English_have_the_same_texts()
    {
        var en = Load("en");
        var de = Load("de");
        Assert.Empty(en.Keys.Except(de.Keys));
        Assert.Empty(de.Keys.Except(en.Keys));
        Assert.All(en.Concat(de), pair => Assert.False(string.IsNullOrWhiteSpace(pair.Value), pair.Key));

        // The same placeholders ({0}, {1}, …) must appear in both languages.
        static string Placeholders(string text) =>
            string.Concat(System.Text.RegularExpressions.Regex.Matches(text, @"\{\d\}").Select(m => m.Value).Order());
        Assert.All(en.Keys, key => Assert.Equal(Placeholders(en[key]), Placeholders(de[key])));
    }

    [Fact]
    public void Every_text_used_in_code_or_xaml_exists()
    {
        var keys = Load("en").Keys.ToHashSet();
        var used = new HashSet<string>();
        foreach (string file in Directory.EnumerateFiles(Path.Combine(Repo.Root, "src", "Krypta.App"), "*.*", SearchOption.AllDirectories)
                     .Where(f => (f.EndsWith(".cs") || f.EndsWith(".xaml")) && !f.Contains("Strings.")))
        {
            string text = File.ReadAllText(file);
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(
                         text, @"(?:Loc\.[TF]\(|DynamicResource )""?([A-Z][A-Za-z]+(?:\.[A-Za-z0-9]+)+)"))
                used.Add(m.Groups[1].Value);
        }
        Assert.NotEmpty(used);
        Assert.Empty(used.Except(keys));
    }
}

public class FaviconTests
{
    [Fact]
    public void Icons_are_decoded_and_bad_data_is_rejected()
    {
        byte[] icon = File.ReadAllBytes(Path.Combine(Repo.Root, "src", "Krypta.App", "Resources", "krypta.ico"));
        Assert.NotNull(FaviconService.Decode(icon));
        Assert.Null(FaviconService.Decode([]));
        Assert.Null(FaviconService.Decode(Encoding.UTF8.GetBytes("<html>not an icon</html>")));
        Assert.Null(FaviconService.Decode(new byte[200 * 1024]));

        var data = new VaultData { Icons = { ["example.com"] = Convert.ToBase64String(icon), ["none.example"] = "", ["bad.example"] = "%%%" } };
        var service = new FaviconService();
        Assert.NotNull(service.Get(data, "example.com"));
        Assert.Null(service.Get(data, "none.example"));
        Assert.Null(service.Get(data, "bad.example"));
        Assert.Null(service.Get(data, "unknown.example"));
    }
}

public class DeviceKeyTests
{
    [Fact]
    public void Tpm_key_wraps_and_unwraps_when_a_tpm_is_present()
    {
        var provider = new TpmDeviceKeyProvider();
        if (!provider.IsAvailable) return; // No TPM on this machine (for example a CI runner).

        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var info = provider.Wrap(secret);
        try
        {
            Assert.StartsWith("Krypta-Device-", info.KeyName);
            Assert.DoesNotContain(Convert.ToBase64String(secret), info.WrappedSecret);
            Assert.Equal(secret, provider.Unwrap(info));

            // A blob wrapped for a key that does not exist here cannot be opened.
            var missing = new DeviceBindingInfo { Provider = info.Provider, Padding = info.Padding, KeyName = "Krypta-Device-missing", WrappedSecret = info.WrappedSecret };
            Assert.ThrowsAny<CryptographicException>(() => provider.Unwrap(missing));
        }
        finally
        {
            provider.Delete(info);
        }
        Assert.ThrowsAny<CryptographicException>(() => provider.Unwrap(info));
    }
}

/// <summary>
/// Opens every window in both languages and renders it to a PNG under artifacts/ui.
/// This catches XAML errors that only show up at run time and gives pictures to review.
/// </summary>
public class UiSmokeTests
{
    private static void Pump(int milliseconds = 150)
    {
        var frame = new DispatcherFrame();
        var timer = new DispatcherTimer(DispatcherPriority.ApplicationIdle) { Interval = TimeSpan.FromMilliseconds(milliseconds) };
        timer.Tick += (_, _) => { timer.Stop(); frame.Continue = false; };
        timer.Start();
        Dispatcher.PushFrame(frame);
    }

    private static void Capture(Window window, string name)
    {
        Pump();
        var root = (FrameworkElement)window.Content;
        int width = (int)Math.Ceiling(root.ActualWidth), height = (int)Math.Ceiling(root.ActualHeight);
        Assert.True(width > 100 && height > 50, $"{name} has no size");

        // Dialogs are rendered without their window frame, so give them a margin.
        int pad = window is MainWindow ? 0 : 24;
        var background = window.TryFindResource("ApplicationBackgroundBrush") as Brush ?? new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20));
        var visual = new DrawingVisual();
        using (var context = visual.RenderOpen())
        {
            context.DrawRectangle(background, null, new Rect(0, 0, width + 2 * pad, height + 2 * pad));
            context.DrawRectangle(new VisualBrush(root) { Stretch = Stretch.None }, null, new Rect(pad, pad, width, height));
        }
        var bitmap = new RenderTargetBitmap(width + 2 * pad, height + 2 * pad, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);

        string directory = Path.Combine(Repo.Root, "artifacts", "ui");
        Directory.CreateDirectory(directory);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(Path.Combine(directory, name + ".png"));
        encoder.Save(stream);
    }

    /// <summary>
    /// Sends one request the way a browser would: through Krypta.NativeHost.exe (native
    /// messaging framing on stdin/stdout), the named pipe, and the app's request handler.
    /// </summary>
    private static JsonElement AskThroughNativeHost(string json)
    {
        string pivot = new DirectoryInfo(AppContext.BaseDirectory).Name;
        string exe = Path.Combine(Repo.Root, "artifacts", "bin", "Krypta.NativeHost", pivot, "Krypta.NativeHost.exe");
        using var process = Process.Start(new ProcessStartInfo(exe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;

        byte[] body = Encoding.UTF8.GetBytes(json);
        byte[] length = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(length, body.Length);
        var input = process.StandardInput.BaseStream;
        input.Write(length);
        input.Write(body);
        input.Flush();

        var read = Task.Run(() =>
        {
            var output = process.StandardOutput.BaseStream;
            byte[] header = new byte[4];
            output.ReadExactly(header);
            byte[] response = new byte[BinaryPrimitives.ReadInt32LittleEndian(header)];
            output.ReadExactly(response);
            return Encoding.UTF8.GetString(response);
        });
        // The app answers on this (UI) thread, so keep it running while waiting.
        var watch = Stopwatch.StartNew();
        while (!read.IsCompleted && watch.Elapsed < TimeSpan.FromSeconds(20)) Pump(20);
        Assert.True(read.IsCompleted, "No answer from the native host.");

        process.StandardInput.Close();
        Assert.True(process.WaitForExit(5000));
        Assert.Equal(0, process.ExitCode);
        return JsonDocument.Parse(read.Result).RootElement;
    }

    private static void CheckBrowserBridge(bool locked)
    {
        var status = AskThroughNativeHost("""{"type":"status"}""");
        Assert.True(status.GetProperty("ok").GetBoolean(), status.ToString());
        Assert.Equal(locked, status.GetProperty("locked").GetBoolean());
        if (locked) return;

        // A site without a passkey in the vault falls back to the browser, without any dialog.
        var none = AskThroughNativeHost("""{"type":"get","origin":"https://nopasskey.example","options":{"challenge":"Yw","rpId":"nopasskey.example"}}""");
        Assert.False(none.GetProperty("ok").GetBoolean());
        Assert.True(none.GetProperty("fallback").GetBoolean());
        Assert.Equal("no-passkey", none.GetProperty("error").GetString());

        // A phishing site asking for another site's passkey is refused outright.
        var phishing = AskThroughNativeHost("""{"type":"get","origin":"https://examp1e.com","options":{"challenge":"Yw","rpId":"example.com"}}""");
        Assert.False(phishing.GetProperty("ok").GetBoolean());
        Assert.Equal("SecurityError", phishing.GetProperty("domError").GetString());

        // The browser popup: logins are listed only for their own website.
        var logins = AskThroughNativeHost("""{"type":"logins","origin":"https://github.com"}""").GetProperty("logins");
        Assert.Equal(["GitHub", "Shop"], logins.EnumerateArray().Select(login => login.GetProperty("title").GetString()));
        Assert.False(logins[0].TryGetProperty("password", out _));
        Assert.Equal(0, AskThroughNativeHost("""{"type":"logins","origin":"https://github.com.evil.net"}""").GetProperty("logins").GetArrayLength());
        var wrongSite = AskThroughNativeHost($$"""{"type":"fill","origin":"https://mail.example","id":"{{logins[0].GetProperty("id").GetString()}}"}""");
        Assert.Equal("no-match", wrongSite.GetProperty("error").GetString());

        var garbage = AskThroughNativeHost("""{"type":"create","origin":"https://example.com"}""");
        Assert.Equal("bad-request", garbage.GetProperty("error").GetString());
    }

    private static void OffScreen(Window window)
    {
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = -20000;
        window.Top = -20000;
        window.ShowActivated = false;
        window.ShowInTaskbar = false;
    }

    private static void RunAll(string dataDir)
    {
        Environment.SetEnvironmentVariable("KRYPTA_DATA_DIR", dataDir);
        App.App.SkipStartup = true; // WPF raises Startup as soon as messages are pumped.
        var app = new App.App();
        app.InitializeComponent();
        app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        app.ThemeMode = ThemeMode.Dark;
        Hardening.BlockScreenCapture = false;

        string vaultPath = Path.Combine(dataDir, "vault.krypta");
        var settings = new AppSettings { VaultPath = vaultPath, AutoLockMinutes = 0 };
        var clipboard = new ClipboardService();

        foreach (string language in new[] { "de", "en" })
        {
            Loc.Apply(language);
            var window = new MainWindow(settings);
            OffScreen(window);
            window.Show();
            Capture(window, $"{language}-1-create");

            if (File.Exists(vaultPath)) File.Delete(vaultPath);
            var vault = Vault.Create(vaultPath, "test master password", out _,
                kdf: new KdfParams { MemoryKiB = 8 * 1024, Iterations = 1, Parallelism = 1 });
            var (_, passkey) = WebAuthn.CreateCredential(
                JsonDocument.Parse("""{"rp":{"id":"example.com","name":"Example"},"user":{"id":"dQ","name":"alice@example.com","displayName":"Alice"},"challenge":"Yw","pubKeyCredParams":[{"type":"public-key","alg":-7}]}""").RootElement,
                "https://example.com", []);
            var login = new Entry
            {
                Title = "GitHub", Username = "alice", Password = "correct-horse-battery-staple", Url = "https://github.com",
                Notes = language == "de" ? "Wiederherstellungscodes liegen im Safe." : "Recovery codes are in the safe.", Totp = new TotpConfig { Secret = "JBSWY3DPEHPK3PXP", Issuer = "GitHub", Account = "alice" },
            };
            vault.Data.Entries.AddRange([
                login,
                new Entry { Title = "Example", Username = "alice@example.com", Url = "https://example.com", Passkey = passkey },
                new Entry { Title = "Mail", Username = "alice@mail.example", Password = "sommer2024", Url = "mail.example" },
                new Entry { Title = "Shop", Username = "alice@mail.example", Password = "sommer2024", Url = "https://github.com/shop" },
                new Entry { Title = "Visa", Kind = EntryKind.Card, Username = "Alice Example", CardNumber = "4111 1111 1111 1111", CardExpiry = "12/29", CardCode = "123", Favorite = true, Tags = ["bank"] },
            ]);
            vault.Save();

            window.ShowVault(vault);
            Pump();
            var list = (System.Windows.Controls.ListBox)window.FindName("EntryList");
            list.SelectedIndex = 1; // GitHub (sorted by title)
            Capture(window, $"{language}-2-vault");
            list.SelectedIndex = 0; // Example (passkey)
            Capture(window, $"{language}-3-passkey");
            CheckBrowserBridge(locked: false);

            // Smart filters: several words, and "by website" (two accounts on github.com).
            var search = (System.Windows.Controls.TextBox)window.FindName("SearchBox");
            search.Text = "git alice";
            Pump(50);
            Assert.Equal(2, list.Items.Count);
            search.Text = "";
            var websites = (System.Windows.Controls.ComboBox)window.FindName("WebsiteBox");
            Assert.Equal("github.com (2)", websites.Items[1]);
            websites.SelectedIndex = 1;
            Pump(50);
            Assert.Equal(2, list.Items.Count);
            websites.SelectedIndex = 0;
            Pump(50);
            Assert.Equal(5, list.Items.Count);

            // Pages: security check (weak + reused are found locally) and credits.
            var nav = (System.Windows.Controls.ListBox)window.FindName("NavList");
            void Go(string tag) => nav.SelectedItem = nav.Items.Cast<System.Windows.Controls.ListBoxItem>().Single(item => (string)item.Tag == tag);
            Go("security");
            var findings = (System.Windows.Controls.ListBox)window.FindName("FindingList");
            Assert.Equal(4, findings.Items.Count); // 2 reused + 2 weak
            Capture(window, $"{language}-10-security");
            Go("credits");
            Capture(window, $"{language}-11-credits");

            // Trash: deleting moves an entry there, restoring brings it back.
            Go("all");
            list.SelectedIndex = 3; // Shop (Example, GitHub, Mail, Shop, Visa)
            var delete = (System.Windows.Controls.Button)window.FindName("DeleteButton");
            delete.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Assert.Equal(4, list.Items.Count);
            Assert.Equal(5, vault.Data.Entries.Count);
            Go("trash");
            Assert.Single(list.Items);
            list.SelectedIndex = 0;
            Capture(window, $"{language}-12-trash");
            var restore = (System.Windows.Controls.Button)window.FindName("RestoreButton");
            restore.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Assert.Empty(list.Items);
            Go("cards");
            Assert.Single(list.Items);
            list.SelectedIndex = 0;
            Capture(window, $"{language}-13-card");
            Go("all");
            Pump(50);
            Assert.Equal(5, list.Items.Count);

            Window[] dialogs =
            [
                new EntryDialog(window, login, clipboard, settings),
                new GeneratorDialog(window, forEntry: true, clipboard, settings),
                new SettingsDialog(window, settings, vault, new TpmDeviceKeyProvider(), clipboard),
                new PasskeyPromptDialog(window, Loc.F("Passkey.Get", "example.com"), ["alice@example.com", "bob@example.com"], Loc.T("Passkey.Confirm.Get")),
                DisplayDialog.ForQr(window, "GitHub", Loc.T("Qr.Totp"), Transfer.OtpAuthUri(login.Totp!, login)),
                DisplayDialog.ForText(window, "GitHub", "aB3$kL9!0OIl1"),
                new WelcomeDialog(window),
                new HistoryDialog(window, new Entry { History = [new OldPassword { Password = "old-one", Replaced = DateTimeOffset.UtcNow }] }, clipboard, settings),
            ];
            string[] names = ["entry", "generator", "settings", "passkey-prompt", "qr", "large", "welcome", "history"];
            for (int i = 0; i < dialogs.Length; i++)
            {
                OffScreen(dialogs[i]);
                dialogs[i].Show();
                Capture(dialogs[i], $"{language}-d{i}-{names[i]}");
                dialogs[i].Close();
            }

            // The recovery dialog refuses to close until the key is confirmed.
            // The QR code shown for another device can be read back by the scanner.
            var qrPixels = QrDecoder.Encode(Transfer.OtpAuthUri(login.Totp!, login), 280);
            Assert.Equal("JBSWY3DPEHPK3PXP", Totp.ParseUri(Assert.Single(QrDecoder.Decode(qrPixels, 280, 280))).Secret);

            // Quick search finds entries by several words.
            var quick = new QuickSearchWindow(vault.Data.Active.ToList());
            OffScreen(quick);
            quick.ShowActivated = false;
            quick.Show();
            ((System.Windows.Controls.TextBox)quick.FindName("QueryBox")).Text = "git alice";
            Pump(50);
            Assert.Equal(2, ((System.Windows.Controls.ListBox)quick.FindName("ResultList")).Items.Count);
            quick.Close();

            // Accent colour and light theme can be switched while the app runs.
            Appearance.Apply("light", "green");
            Capture(window, $"{language}-14-light-green");
            Appearance.Apply("dark", "system");

            var recovery = new RecoveryKeyDialog(window, Vault.FormatRecoveryKey(new byte[32]), clipboard, settings);
            OffScreen(recovery);
            recovery.Show();
            Capture(recovery, $"{language}-d8-recovery");
            recovery.Close();
            Assert.True(recovery.IsVisible);
            ((System.Windows.Controls.CheckBox)recovery.FindName("ConfirmCheck")).IsChecked = true;
            var close = (System.Windows.Controls.Button)recovery.FindName("CloseButton");
            close.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Pump(50);
            Assert.False(recovery.IsVisible);

            // Locking wipes the list and returns to the unlock screen.
            window.LockVault();
            Pump();
            Assert.Empty(list.Items);
            Assert.Empty(vault.Data.Entries);
            ((System.Windows.Controls.TextBlock)window.FindName("VaultPathText")).Text = "";
            Capture(window, $"{language}-9-locked");
            CheckBrowserBridge(locked: true);
            window.Close();
        }
        app.Shutdown();
    }

    [Fact]
    public void All_windows_open_and_render_in_both_languages()
    {
        string dataDir = Directory.CreateTempSubdirectory("krypta-ui-").FullName;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { RunAll(dataDir); }
            catch (Exception e) { failure = e; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        Directory.Delete(dataDir, recursive: true);
        if (failure is not null) throw new Xunit.Sdk.XunitException(failure.ToString());
    }
}
