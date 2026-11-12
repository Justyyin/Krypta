using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Krypta.Core;

/// <summary>Time-based one-time passwords (RFC 6238), as used by authenticator apps.</summary>
public static class Totp
{
    public static string Compute(TotpConfig config, DateTimeOffset now)
    {
        byte[] key = Base32.Decode(config.Secret);
        try
        {
            int period = config.Period > 0 ? config.Period : 30;
            int digits = Math.Clamp(config.Digits, 6, 8);
            long counter = now.ToUnixTimeSeconds() / period;

            Span<byte> message = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(message, counter);

            byte[] hash = config.Algorithm.ToUpperInvariant().Replace("-", "") switch
            {
                "SHA256" => HMACSHA256.HashData(key, message),
                "SHA512" => HMACSHA512.HashData(key, message),
                _ => HMACSHA1.HashData(key, message),
            };

            int offset = hash[^1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
            int modulus = 1;
            for (int i = 0; i < digits; i++) modulus *= 10;
            return (binary % modulus).ToString().PadLeft(digits, '0');
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static int SecondsRemaining(TotpConfig config, DateTimeOffset now)
    {
        int period = config.Period > 0 ? config.Period : 30;
        return period - (int)(now.ToUnixTimeSeconds() % period);
    }

    /// <summary>
    /// Parses an <c>otpauth://totp/…</c> URI — the content of the QR code a website shows
    /// when you set up two-factor authentication.
    /// </summary>
    public static TotpConfig ParseUri(string uri)
    {
        if (!Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var parsed) || parsed.Scheme != "otpauth")
            throw new FormatException("Not an otpauth:// URI.");
        if (!string.Equals(parsed.Host, "totp", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("Only time-based codes (TOTP) are supported.");

        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string pair in parsed.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            query[Uri.UnescapeDataString(pair[..eq])] = Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' '));
        }

        if (!query.TryGetValue("secret", out string? secret) || !Base32.TryDecode(secret, out byte[] key) || key.Length == 0)
            throw new FormatException("The otpauth URI has no valid secret.");
        CryptographicOperations.ZeroMemory(key);

        string label = Uri.UnescapeDataString(parsed.AbsolutePath.TrimStart('/'));
        string issuer = query.GetValueOrDefault("issuer", "");
        string account = label;
        int colon = label.IndexOf(':');
        if (colon >= 0)
        {
            if (issuer.Length == 0) issuer = label[..colon].Trim();
            account = label[(colon + 1)..].Trim();
        }

        var config = new TotpConfig
        {
            Secret = secret.Replace(" ", "").Replace("-", "").TrimEnd('=').ToUpperInvariant(),
            Issuer = issuer,
            Account = account,
        };
        if (query.TryGetValue("algorithm", out string? alg) && alg.ToUpperInvariant().Replace("-", "") is "SHA1" or "SHA256" or "SHA512")
            config.Algorithm = alg.ToUpperInvariant().Replace("-", "");
        if (query.TryGetValue("digits", out string? d) && int.TryParse(d, out int digits) && digits is >= 6 and <= 8)
            config.Digits = digits;
        if (query.TryGetValue("period", out string? p) && int.TryParse(p, out int period) && period is > 0 and <= 600)
            config.Period = period;
        return config;
    }
}
