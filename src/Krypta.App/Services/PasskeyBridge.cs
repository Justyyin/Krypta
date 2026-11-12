using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using Microsoft.Win32;

namespace Krypta.App.Services;

/// <summary>
/// Local endpoint for passkey requests coming from the browser extension (through
/// Krypta.NativeHost). It is a named pipe that only the current Windows user can open.
/// Nothing is listening on the network.
/// </summary>
internal sealed class PasskeyBridge(Func<JsonElement, Task<JsonObject>> handler) : IDisposable
{
    private const int MaxMessageSize = 1024 * 1024;
    private readonly CancellationTokenSource _stop = new();

    public static string PipeName => "Krypta.Passkeys.v1." + WindowsIdentity.GetCurrent().User!.Value;

    public void Start() => Task.Run(AcceptLoopAsync);

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            NamedPipeServerStream server;
            try
            {
                server = new NamedPipeServerStream(PipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return; // The pipe name is taken by something else; passkey integration stays off.
            }

            try
            {
                await server.WaitForConnectionAsync(_stop.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or IOException)
            {
                server.Dispose();
                continue;
            }
            _ = Task.Run(() => ServeAsync(server));
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe)
    {
        await using var _ = pipe;
        try
        {
            using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            readTimeout.CancelAfter(TimeSpan.FromSeconds(10));
            byte[]? line = await ReadLineAsync(pipe, readTimeout.Token);
            if (line is null) return;

            JsonObject response;
            try
            {
                using var document = JsonDocument.Parse(line);
                var request = document.RootElement.Clone();
                response = await Application.Current.Dispatcher.InvokeAsync(() => handler(request)).Task.Unwrap();
            }
            catch (JsonException)
            {
                response = new JsonObject { ["ok"] = false, ["fallback"] = true, ["error"] = "bad-request" };
            }

            byte[] bytes = Encoding.UTF8.GetBytes(response.ToJsonString() + "\n");
            await pipe.WriteAsync(bytes, _stop.Token);
            await pipe.FlushAsync(_stop.Token);
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException)
        {
        }
    }


    private static async Task<byte[]?> ReadLineAsync(Stream stream, CancellationToken cancel)
    {
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        while (true)
        {
            int read = await stream.ReadAsync(chunk, cancel);
            if (read == 0) return null;
            int newline = Array.IndexOf(chunk, (byte)'\n', 0, read);
            buffer.Write(chunk, 0, newline >= 0 ? newline : read);
            if (newline >= 0) return buffer.ToArray();
            if (buffer.Length > MaxMessageSize) return null;
        }
    }

    public void Dispose() => _stop.Cancel();
}

/// <summary>
/// Tells Chromium-based browsers where to find Krypta.NativeHost so that the Krypta browser
/// extension is allowed to start it. Only writes below HKEY_CURRENT_USER.
/// </summary>
internal static class BrowserIntegration
{
    public const string HostName = "com.krypta.passkeys";
    public const string ExtensionId = "eahfeamfgjaopgnjfcinblccfgajlhme";
    public const string FirefoxExtensionId = "krypta@justyin-dev.de";
    private const string FirefoxKey = @"Software\Mozilla\NativeMessagingHosts\" + HostName;

    private static string FirefoxManifestPath => Path.Combine(Path.GetDirectoryName(ManifestPath)!, HostName + ".firefox.json");

    private static readonly string[] Browsers =
    [
        @"Software\Google\Chrome",
        @"Software\Microsoft\Edge",
        @"Software\BraveSoftware\Brave-Browser",
        @"Software\Chromium",
    ];

    private static string ManifestPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Krypta", "native-host", HostName + ".json");

    public static string HostPath => Path.Combine(AppContext.BaseDirectory, "Krypta.NativeHost.exe");

    public static bool IsInstalled
    {
        get
        {
            if (!File.Exists(ManifestPath)) return false;
            foreach (string browser in Browsers)
            {
                using var key = Registry.CurrentUser.OpenSubKey($@"{browser}\NativeMessagingHosts\{HostName}");
                if (key?.GetValue(null) as string == ManifestPath) return true;
            }
            return false;
        }
    }

    public static void Install()
    {
        if (!File.Exists(HostPath)) throw new FileNotFoundException("Krypta.NativeHost.exe is missing.", HostPath);
        var manifest = new JsonObject
        {
            ["name"] = HostName,
            ["description"] = "Krypta passkey bridge",
            ["path"] = HostPath,
            ["type"] = "stdio",
            ["allowed_origins"] = new JsonArray($"chrome-extension://{ExtensionId}/"),
        };
        Directory.CreateDirectory(Path.GetDirectoryName(ManifestPath)!);
        File.WriteAllText(ManifestPath, manifest.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        foreach (string browser in Browsers)
        {
            // Only for browsers that are actually installed for this user.
            using var installed = Registry.CurrentUser.OpenSubKey(browser);
            if (installed is null) continue;
            using var key = Registry.CurrentUser.CreateSubKey($@"{browser}\NativeMessagingHosts\{HostName}");
            key.SetValue(null, ManifestPath);
        }
        InstallFirefox();
    }

    /// <summary>Firefox uses its own manifest format and registry location.</summary>
    private static void InstallFirefox()
    {
        using var mozilla = Registry.CurrentUser.OpenSubKey(@"Software\Mozilla");
        if (mozilla is null) return;
        var manifest = new JsonObject
        {
            ["name"] = HostName,
            ["description"] = "Krypta passkey bridge",
            ["path"] = HostPath,
            ["type"] = "stdio",
            ["allowed_extensions"] = new JsonArray(FirefoxExtensionId),
        };
        File.WriteAllText(FirefoxManifestPath, manifest.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        using var key = Registry.CurrentUser.CreateSubKey(FirefoxKey);
        key.SetValue(null, FirefoxManifestPath);
    }

    public static void Uninstall()
    {
        Registry.CurrentUser.DeleteSubKey(FirefoxKey, throwOnMissingSubKey: false);
        if (File.Exists(FirefoxManifestPath)) File.Delete(FirefoxManifestPath);
        foreach (string browser in Browsers)
            Registry.CurrentUser.DeleteSubKey($@"{browser}\NativeMessagingHosts\{HostName}", throwOnMissingSubKey: false);
        if (File.Exists(ManifestPath)) File.Delete(ManifestPath);
    }
}
