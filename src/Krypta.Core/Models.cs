using System.Text.Json.Serialization;

namespace Krypta.Core;

/// <summary>The decrypted content of a vault.</summary>
public sealed class VaultData
{
    public List<Entry> Entries { get; set; } = [];

    /// <summary>Optional personal API key for the e-mail breach search of Have I Been Pwned.</summary>
    public string HibpApiKey { get; set; } = "";

    /// <summary>When the automatic leak monitor last checked the passwords.</summary>
    public DateTimeOffset? LastLeakCheck { get; set; }

    /// <summary>Website icons by domain (Base64 image data; empty when the site has none).</summary>
    public Dictionary<string, string> Icons { get; set; } = [];

    /// <summary>Everything that is not in the trash.</summary>
    [JsonIgnore]
    public IEnumerable<Entry> Active => Entries.Where(entry => entry.Deleted is null);
}

public enum EntryKind
{
    Login,
    Note,
    Card,
    Wifi,
}

/// <summary>
/// One vault item. A login, a passkey and a TOTP secret can live on the same entry,
/// because they usually belong to the same account.
/// </summary>
public sealed class Entry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public EntryKind Kind { get; set; } = EntryKind.Login;
    /// <summary>Name of the entry. For Wi-Fi entries this is the network name.</summary>
    public string Title { get; set; } = "";
    /// <summary>User name; for cards the card holder.</summary>
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Url { get; set; } = "";
    public string Notes { get; set; } = "";
    public TotpConfig? Totp { get; set; }
    public PasskeyData? Passkey { get; set; }

    public string CardNumber { get; set; } = "";
    public string CardExpiry { get; set; } = "";
    public string CardCode { get; set; } = "";

    public bool Favorite { get; set; }
    public List<string> Tags { get; set; } = [];
    /// <summary>Earlier passwords of this entry, newest first.</summary>
    public List<OldPassword> History { get; set; } = [];
    /// <summary>Set while the entry is in the trash.</summary>
    public DateTimeOffset? Deleted { get; set; }

    public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset Modified { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class OldPassword
{
    public string Password { get; set; } = "";
    /// <summary>When this password was replaced.</summary>
    public DateTimeOffset Replaced { get; set; }
}

public sealed class TotpConfig
{
    /// <summary>Base32 shared secret.</summary>
    public string Secret { get; set; } = "";
    public string Algorithm { get; set; } = "SHA1";
    public int Digits { get; set; } = 6;
    public int Period { get; set; } = 30;
    public string Issuer { get; set; } = "";
    public string Account { get; set; } = "";
}

public sealed class PasskeyData
{
    /// <summary>base64url credential id.</summary>
    public string CredentialId { get; set; } = "";
    public string RpId { get; set; } = "";
    public string RpName { get; set; } = "";
    /// <summary>base64url user handle (user.id).</summary>
    public string UserHandle { get; set; } = "";
    public string UserName { get; set; } = "";
    public string UserDisplayName { get; set; } = "";
    /// <summary>Base64 PKCS#8 P-256 private key.</summary>
    public string PrivateKeyPkcs8 { get; set; } = "";
    public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;
}
