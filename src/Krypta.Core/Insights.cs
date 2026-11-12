using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Krypta.Core;

/// <summary>Smart filtering: find entries by several words and group them by website.</summary>
public static class EntrySearch
{
    /// <summary>The website an entry belongs to, such as "github.com" (no scheme, no "www.").</summary>
    public static string Domain(Entry entry)
    {
        string url = entry.Url.Trim();
        if (url.Length > 0)
        {
            string candidate = url.Contains("://", StringComparison.Ordinal) ? url : "https://" + url;
            if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
                return StripWww(uri.Host.ToLowerInvariant());
        }
        return entry.Passkey is { RpId.Length: > 0 } passkey ? StripWww(passkey.RpId.ToLowerInvariant()) : "";
    }

    /// <summary>
    /// True when an entry may be offered on a page of this origin: the page's host is the entry's
    /// website or one of its subdomains. A look-alike domain never matches.
    /// </summary>
    public static bool MatchesOrigin(Entry entry, string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.Host.Length == 0) return false;
        string host = StripWww(uri.IdnHost.ToLowerInvariant());
        string domain = Domain(entry);
        return domain.Length > 0 && (host == domain || host.EndsWith("." + domain, StringComparison.Ordinal));
    }

    private static string StripWww(string host) => host.StartsWith("www.", StringComparison.Ordinal) ? host[4..] : host;

    /// <summary>
    /// True when every word of the query appears somewhere in the entry (name, user name,
    /// website, notes, 2FA issuer). Secrets are never searched. "git alice" finds Alice's GitHub login.
    /// </summary>
    public static bool Matches(Entry entry, string query)
    {
        string[] words = query.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length == 0) return true;
        string[] fields =
        [
            entry.Title, entry.Username, entry.Url, Domain(entry), entry.Notes,
            entry.Totp?.Issuer ?? "", entry.Totp?.Account ?? "", entry.Passkey?.UserName ?? "", string.Join(' ', entry.Tags),
        ];
        return words.All(word => fields.Any(field => field.Contains(word, StringComparison.CurrentCultureIgnoreCase)));
    }

    /// <summary>All websites in the vault with the number of accounts on each, most used first.</summary>
    public static List<(string Domain, int Count)> Websites(IEnumerable<Entry> entries) =>
        entries.Select(Domain).Where(domain => domain.Length > 0)
            .GroupBy(domain => domain)
            .Select(group => (group.Key, group.Count()))
            .OrderByDescending(site => site.Item2).ThenBy(site => site.Key, StringComparer.Ordinal)
            .ToList();

    /// <summary>User names in the vault that look like e-mail addresses.</summary>
    public static List<string> Emails(IEnumerable<Entry> entries) =>
        entries.SelectMany(entry => new[] { entry.Username, entry.Passkey?.UserName ?? "", entry.Totp?.Account ?? "" })
            .Select(name => name.Trim())
            .Where(LooksLikeEmail)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();

    public static bool LooksLikeEmail(string text)
    {
        int at = text.IndexOf('@');
        return at > 0 && at == text.LastIndexOf('@') && text.IndexOf('.', at) > at + 1 && !text.EndsWith('.') && !text.Contains(' ');
    }
}

public enum PasswordIssue
{
    Weak,
    Reused,
    Leaked,
}

public sealed record PasswordFinding(Entry Entry, PasswordIssue Issue, long Count);

/// <summary>Checks done on this computer only: weak and reused passwords.</summary>
public static class SecurityAudit
{
    public static List<PasswordFinding> Local(IEnumerable<Entry> entries)
    {
        var withPassword = entries.Where(entry => entry.Password.Length > 0).ToList();
        var findings = new List<PasswordFinding>();
        foreach (var group in withPassword.GroupBy(entry => entry.Password, StringComparer.Ordinal).Where(group => group.Count() > 1))
            findings.AddRange(group.Select(entry => new PasswordFinding(entry, PasswordIssue.Reused, group.Count())));
        findings.AddRange(withPassword
            .Where(entry => PasswordGenerator.EstimateStrength(entry.Password) <= 1)
            .Select(entry => new PasswordFinding(entry, PasswordIssue.Weak, 0)));
        return findings;
    }
}

public sealed class HibpException(string code, string message) : Exception(message)
{
    /// <summary>"api-key", "rate-limit" or "network".</summary>
    public string Code { get; } = code;
}

/// <summary>
/// Client for Have I Been Pwned (haveibeenpwned.com, by Troy Hunt). These are the only
/// network requests Krypta ever makes, and only when the user starts a check.
/// </summary>
public sealed class HibpClient(HttpMessageHandler? handler = null)
{
    private readonly HttpClient _http = CreateClient(handler);

    private static HttpClient CreateClient(HttpMessageHandler? handler)
    {
        var http = handler is null ? new HttpClient() : new HttpClient(handler);
        http.Timeout = TimeSpan.FromSeconds(15);
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Krypta-Password-Manager");
        return http;
    }

    /// <summary>
    /// How often a password appears in known leaks (0 = not found). Uses k-anonymity: only the
    /// first 5 characters of the password's SHA-1 hash leave this computer, never the password.
    /// </summary>
    public async Task<long> PasswordLeakCountAsync(string password, CancellationToken cancel = default)
    {
        string hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        string prefix = hash[..5], suffix = hash[5..];

        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.pwnedpasswords.com/range/" + prefix);
        request.Headers.Add("Add-Padding", "true"); // hides the size of the answer from observers
        string body = await SendAsync(request, cancel);

        foreach (string line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int colon = line.IndexOf(':');
            if (colon == suffix.Length && line.AsSpan(0, colon).Equals(suffix, StringComparison.OrdinalIgnoreCase))
                return long.TryParse(line.AsSpan(colon + 1), out long count) ? count : 0;
        }
        return 0;
    }

    /// <summary>
    /// Names of the known data breaches that contain this e-mail address (empty = none found).
    /// Have I Been Pwned requires a personal API key for this search.
    /// </summary>
    public async Task<List<string>> BreachesForEmailAsync(string email, string apiKey, CancellationToken cancel = default)
    {
        string url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + Uri.EscapeDataString(email.Trim()) + "?truncateResponse=true";
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("hibp-api-key", apiKey.Trim());
        string? body = await SendAsync(request, cancel, notFoundIsEmpty: true);
        if (string.IsNullOrWhiteSpace(body)) return [];
        try
        {
            using var document = JsonDocument.Parse(body);
            return document.RootElement.EnumerateArray()
                .Select(breach => breach.TryGetProperty("Name", out var name) ? name.GetString() ?? "" : "")
                .Where(name => name.Length > 0)
                .ToList();
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            throw new HibpException("network", "Unexpected answer from Have I Been Pwned.");
        }
    }

    private async Task<string> SendAsync(HttpRequestMessage request, CancellationToken cancel, bool notFoundIsEmpty = false)
    {
        try
        {
            using var response = await _http.SendAsync(request, cancel);
            if (notFoundIsEmpty && response.StatusCode == HttpStatusCode.NotFound) return "";
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new HibpException("api-key", "The API key was not accepted.");
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                throw new HibpException("rate-limit", "Too many requests. Try again in a moment.");
            if (!response.IsSuccessStatusCode)
                throw new HibpException("network", $"Have I Been Pwned answered with status {(int)response.StatusCode}.");
            return await response.Content.ReadAsStringAsync(cancel);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            throw new HibpException("network", "Have I Been Pwned could not be reached.");
        }
    }
}
