using System.Buffers.Text;
using System.Text;

namespace Krypta.Core;

/// <summary>RFC 4648 Base32 (used for TOTP secrets and recovery keys).</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    /// <summary>Decodes Base32. Ignores spaces, dashes and padding; case-insensitive.</summary>
    public static byte[] Decode(string text)
    {
        var output = new List<byte>(text.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (char raw in text)
        {
            if (raw is ' ' or '-' or '=' or '\t' or '\r' or '\n') continue;
            int value = Alphabet.IndexOf(char.ToUpperInvariant(raw));
            if (value < 0) throw new FormatException("Invalid Base32 character.");
            buffer = ((buffer << 5) | value) & 0xFFFFFF;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return output.ToArray();
    }

    public static bool TryDecode(string text, out byte[] data)
    {
        try { data = Decode(text); return true; }
        catch (FormatException) { data = []; return false; }
    }
}

public static class B64Url
{
    public static string Encode(ReadOnlySpan<byte> data) => Base64Url.EncodeToString(data);
    public static byte[] Decode(string text) => Base64Url.DecodeFromChars(text.AsSpan().TrimEnd('='));
}
