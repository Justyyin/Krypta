using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Krypta.Core;

namespace Krypta.App.Services;

/// <summary>
/// Optional website icons. An icon is fetched from the website itself (https://site/favicon.ico),
/// never from an icon service, and then kept inside the encrypted vault. Off by default, because
/// each request tells that website (and the network) that this computer asked for it.
/// </summary>
internal sealed class FaviconService
{
    private const int MaxBytes = 100 * 1024;

    private readonly HttpClient _http = new(new SocketsHttpHandler { MaxAutomaticRedirections = 3, UseCookies = false })
    {
        Timeout = TimeSpan.FromSeconds(6),
    };
    private readonly Dictionary<string, ImageSource?> _decoded = [];

    public FaviconService() => _http.DefaultRequestHeaders.UserAgent.ParseAdd("Krypta-Password-Manager");

    /// <summary>Decodes an icon or image file; null when it is not a usable picture.</summary>
    public static ImageSource? Decode(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaxBytes) return null;
        try
        {
            using var stream = new MemoryStream(bytes);
            var decoder = BitmapDecoder.Create(stream, BitmapCreateOptions.IgnoreColorProfile, BitmapCacheOption.OnLoad);
            var frame = decoder.Frames.Where(f => f.PixelWidth is > 0 and <= 512).OrderByDescending(f => f.PixelWidth).FirstOrDefault();
            if (frame is null) return null;
            frame.Freeze();
            return frame;
        }
        catch (Exception e) when (e is NotSupportedException or FileFormatException or IOException or COMException
                                      or ArgumentException or InvalidOperationException or OverflowException)
        {
            return null;
        }
    }

    /// <summary>The stored icon for a website, if the vault has one.</summary>
    public ImageSource? Get(VaultData data, string domain)
    {
        if (domain.Length == 0 || !data.Icons.TryGetValue(domain, out string? encoded) || encoded.Length == 0) return null;
        if (_decoded.TryGetValue(domain, out var known)) return known;
        ImageSource? image = null;
        try { image = Decode(Convert.FromBase64String(encoded)); }
        catch (FormatException) { }
        _decoded[domain] = image;
        return image;
    }

    private static bool IsPublicHostName(string domain) =>
        domain.Contains('.') && !IPAddress.TryParse(domain, out _) && Uri.CheckHostName(domain) == UriHostNameType.Dns &&
        !domain.EndsWith(".local", StringComparison.Ordinal) && !domain.EndsWith(".internal", StringComparison.Ordinal);

    /// <summary>
    /// Fetches icons the vault does not have yet. Sites without a usable icon are remembered too,
    /// so they are not asked again. Returns true when the vault data changed.
    /// </summary>
    public async Task<bool> FetchMissingAsync(VaultData data, IReadOnlyCollection<string> domains, CancellationToken cancel)
    {
        bool changed = false;
        foreach (string domain in domains.Where(d => d.Length > 0 && !data.Icons.ContainsKey(d)).Distinct().ToList())
        {
            if (cancel.IsCancellationRequested) break;
            string stored = "";
            if (IsPublicHostName(domain))
            {
                try
                {
                    using var response = await _http.GetAsync($"https://{domain}/favicon.ico", HttpCompletionOption.ResponseHeadersRead, cancel);
                    if (response.IsSuccessStatusCode && response.Content.Headers.ContentLength is null or <= MaxBytes)
                    {
                        byte[] bytes = await response.Content.ReadAsByteArrayAsync(cancel);
                        if (Decode(bytes) is not null) stored = Convert.ToBase64String(bytes);
                    }
                }
                catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
                {
                }
            }
            if (cancel.IsCancellationRequested) break;
            data.Icons[domain] = stored;
            changed = true;
        }
        return changed;
    }
}
