using System.Text;

namespace Krypta.Core;

/// <summary>Trash, password history and tags.</summary>
public static class VaultOps
{
    /// <summary>Entries stay in the trash this long before they are removed for good.</summary>
    public static readonly TimeSpan TrashRetention = TimeSpan.FromDays(30);
    public const int MaxHistory = 10;

    /// <summary>Changes the password and keeps the old one in the entry's history.</summary>
    public static void SetPassword(Entry entry, string newPassword, DateTimeOffset now)
    {
        if (entry.Password == newPassword) return;
        if (entry.Password.Length > 0)
        {
            entry.History.Insert(0, new OldPassword { Password = entry.Password, Replaced = now });
            if (entry.History.Count > MaxHistory) entry.History.RemoveRange(MaxHistory, entry.History.Count - MaxHistory);
        }
        entry.Password = newPassword;
    }

    public static void MoveToTrash(Entry entry, DateTimeOffset now) => entry.Deleted = now;

    public static void Restore(Entry entry) => entry.Deleted = null;

    /// <summary>Removes entries that have been in the trash longer than the retention time.</summary>
    public static int PurgeTrash(VaultData data, DateTimeOffset now) =>
        data.Entries.RemoveAll(entry => entry.Deleted is { } deleted && now - deleted > TrashRetention);

    /// <summary>Splits "work, bank  private" style input into clean, unique tags.</summary>
    public static List<string> ParseTags(string text) =>
        text.Split([',', ';', '#'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(tag => tag.Length > 0)
            .Distinct(StringComparer.CurrentCultureIgnoreCase)
            .ToList();

    /// <summary>All tags in use with the number of entries, most used first.</summary>
    public static List<(string Tag, int Count)> Tags(IEnumerable<Entry> entries) =>
        entries.SelectMany(entry => entry.Tags.Distinct(StringComparer.CurrentCultureIgnoreCase))
            .GroupBy(tag => tag, StringComparer.CurrentCultureIgnoreCase)
            .Select(group => (group.First(), group.Count()))
            .OrderByDescending(tag => tag.Item2).ThenBy(tag => tag.Item1, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
}

/// <summary>Minimal RFC 4180 CSV reader and writer (quotes, doubled quotes, line breaks in fields).</summary>
public static class Csv
{
    public static List<string[]> Parse(string text)
    {
        var rows = new List<string[]>();
        var row = new List<string>();
        var field = new StringBuilder();
        bool quoted = false, any = false;
        if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..];

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else field.Append(c);
                continue;
            }
            switch (c)
            {
                case '"':
                    quoted = true;
                    any = true;
                    break;
                case ',':
                    row.Add(field.ToString());
                    field.Clear();
                    any = true;
                    break;
                case '\r':
                    break;
                case '\n':
                    if (any || field.Length > 0)
                    {
                        row.Add(field.ToString());
                        rows.Add(row.ToArray());
                    }
                    row.Clear();
                    field.Clear();
                    any = false;
                    break;
                default:
                    field.Append(c);
                    break;
            }
        }
        if (any || field.Length > 0)
        {
            row.Add(field.ToString());
            rows.Add(row.ToArray());
        }
        return rows;
    }

    public static string Write(IEnumerable<IEnumerable<string>> rows)
    {
        var sb = new StringBuilder();
        foreach (var row in rows)
        {
            sb.AppendJoin(',', row.Select(Escape));
            sb.Append("\r\n");
        }
        return sb.ToString();
    }

    private static string Escape(string field) =>
        field.AsSpan().IndexOfAny(",\"\r\n") >= 0 || field.StartsWith(' ') || field.EndsWith(' ')
            ? "\"" + field.Replace("\"", "\"\"") + "\""
            : field;
}

/// <summary>
/// Import from and export to CSV. The importer recognises the column names used by Chrome, Edge,
/// Firefox, Bitwarden, KeePass and KeePassXC, so one reader handles all of them.
/// </summary>
public static class Transfer
{
    private static readonly Dictionary<string, string[]> Columns = new()
    {
        ["title"] = ["name", "title", "account"],
        ["username"] = ["username", "login_username", "login name", "user name", "user", "login"],
        ["password"] = ["password", "login_password"],
        ["url"] = ["url", "login_uri", "web site", "website", "uri"],
        ["notes"] = ["notes", "note", "comments", "comment"],
        ["totp"] = ["totp", "login_totp", "otpauth", "otp"],
        ["tag"] = ["folder", "group", "tags"],
        ["favorite"] = ["favorite", "favourite"],
    };

    /// <summary>
    /// Reads logins from a CSV export. Rows that already exist in <paramref name="existing"/>
    /// (same name, user name, password and website) are skipped.
    /// </summary>
    public static List<Entry> ImportCsv(string csv, IEnumerable<Entry> existing)
    {
        var rows = Csv.Parse(csv);
        if (rows.Count < 1) throw new FormatException("The file is empty.");

        string[] header = rows[0].Select(name => name.Trim().ToLowerInvariant()).ToArray();
        int Find(string field) => Array.FindIndex(header, name => Columns[field].Contains(name));
        var index = Columns.Keys.ToDictionary(field => field, Find);
        if (index["password"] < 0 || (index["title"] < 0 && index["url"] < 0 && index["username"] < 0))
            throw new FormatException("This does not look like a password export (no password column).");

        static string Key(Entry e) => string.Join('\u0001', e.Title, e.Username, e.Password, e.Url);
        var seen = existing.Select(Key).ToHashSet();
        var imported = new List<Entry>();
        foreach (string[] row in rows.Skip(1))
        {
            string Cell(string field) => index[field] >= 0 && index[field] < row.Length ? row[index[field]].Trim() : "";

            var entry = new Entry
            {
                Title = Cell("title"),
                Username = Cell("username"),
                Password = index["password"] < row.Length ? row[index["password"]] : "",
                Url = Cell("url"),
                Notes = Cell("notes"),
                Favorite = Cell("favorite") is "1" or "true" or "True",
            };
            if (entry.Title.Length == 0) entry.Title = EntrySearch.Domain(entry) is { Length: > 0 } domain ? domain : entry.Username;
            if (entry.Title.Length == 0 && entry.Password.Length == 0) continue;
            if (entry.Password.Length == 0 && entry.Notes.Length > 0 && entry.Username.Length == 0) entry.Kind = EntryKind.Note;

            // "Work/Dev" becomes two tags; KeePass puts everything below a group called "Root".
            var folders = Cell("tag").Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            if (folders.Count > 0 && folders[0].Equals("root", StringComparison.OrdinalIgnoreCase)) folders.RemoveAt(0);
            if (folders.Count > 0) entry.Tags = VaultOps.ParseTags(string.Join(',', folders));

            string totp = Cell("totp");
            if (totp.Length > 0)
            {
                try
                {
                    entry.Totp = totp.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)
                        ? Totp.ParseUri(totp)
                        : Base32.TryDecode(totp, out byte[] key) && key.Length > 0
                            ? new TotpConfig { Secret = totp.Replace(" ", "").ToUpperInvariant() }
                            : null;
                }
                catch (Exception e) when (e is FormatException or NotSupportedException)
                {
                }
            }

            if (seen.Add(Key(entry))) imported.Add(entry);
        }
        return imported;
    }

    /// <summary>
    /// Writes logins as CSV that Chrome, Bitwarden and KeePassXC can import. The result is NOT
    /// encrypted, and passkeys cannot be exported this way.
    /// </summary>
    public static string ExportCsv(IEnumerable<Entry> entries)
    {
        var rows = new List<string[]> { new[] { "name", "url", "username", "password", "totp", "notes", "tags", "favorite" } };
        rows.AddRange(entries.Where(entry => entry.Kind is EntryKind.Login or EntryKind.Wifi or EntryKind.Note).Select(entry => new[]
        {
            entry.Title, entry.Url, entry.Username, entry.Password,
            entry.Totp is { } totp ? OtpAuthUri(totp, entry) : "",
            entry.Notes, string.Join(", ", entry.Tags), entry.Favorite ? "1" : "",
        }));
        return Csv.Write(rows);
    }

    public static string OtpAuthUri(TotpConfig totp, Entry entry)
    {
        string issuer = totp.Issuer.Length > 0 ? totp.Issuer : entry.Title;
        string account = totp.Account.Length > 0 ? totp.Account : entry.Username;
        return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?secret={totp.Secret}" +
               $"&issuer={Uri.EscapeDataString(issuer)}&algorithm={totp.Algorithm}&digits={totp.Digits}&period={totp.Period}";
    }

    /// <summary>Text of the QR code that phones scan to join a Wi-Fi network.</summary>
    public static string WifiQrText(Entry entry)
    {
        static string Escape(string value) => value.Replace("\\", "\\\\").Replace(";", "\\;").Replace(",", "\\,").Replace(":", "\\:").Replace("\"", "\\\"");
        return entry.Password.Length == 0
            ? $"WIFI:T:nopass;S:{Escape(entry.Title)};;"
            : $"WIFI:T:WPA;S:{Escape(entry.Title)};P:{Escape(entry.Password)};;";
    }
}
