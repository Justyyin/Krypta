using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace Krypta.App.Services;

/// <summary>
/// Copies secrets so that Windows keeps them out of the clipboard history and cloud sync,
/// and removes them again after a short time.
/// </summary>
internal sealed class ClipboardService
{
    private readonly DispatcherTimer _timer = new();
    private byte[]? _copiedHash;

    public ClipboardService()
    {
        _timer.Tick += (_, _) => ClearIfOurs();
    }

    public bool Copy(string text, int clearAfterSeconds)
    {
        var data = new DataObject();
        data.SetData(DataFormats.UnicodeText, text);
        // Documented clipboard formats that opt out of history, cloud sync and clipboard monitors.
        data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream([0, 0, 0, 0]));
        data.SetData("CanIncludeInClipboardHistory", new MemoryStream([0, 0, 0, 0]));
        data.SetData("CanUploadToCloudClipboard", new MemoryStream([0, 0, 0, 0]));

        if (!Retry(() => Clipboard.SetDataObject(data, copy: true))) return false;

        _copiedHash = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        _timer.Stop();
        if (clearAfterSeconds > 0)
        {
            _timer.Interval = TimeSpan.FromSeconds(clearAfterSeconds);
            _timer.Start();
        }
        return true;
    }

    /// <summary>Clears the clipboard, but only if it still holds what Krypta put there.</summary>
    public void ClearIfOurs()
    {
        _timer.Stop();
        if (_copiedHash is null) return;
        byte[] expected = _copiedHash;
        _copiedHash = null;
        Retry(() =>
        {
            if (!Clipboard.ContainsText()) return;
            byte[] current = SHA256.HashData(Encoding.UTF8.GetBytes(Clipboard.GetText()));
            if (CryptographicOperations.FixedTimeEquals(current, expected)) Clipboard.Clear();
        });
    }

    private static bool Retry(Action action)
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                action();
                return true;
            }
            catch (COMException)
            {
                // Another program has the clipboard open; try again shortly.
                Thread.Sleep(40);
            }
        }
        return false;
    }
}
