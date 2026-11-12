using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;

namespace Krypta.Core;

public sealed class KdfParams
{
    public string Algorithm { get; set; } = "argon2id";
    public int MemoryKiB { get; set; } = 64 * 1024;
    public int Iterations { get; set; } = 3;
    public int Parallelism { get; set; } = 4;
}

/// <summary>How the device secret is wrapped by a key that cannot leave this computer.</summary>
public sealed class DeviceBindingInfo
{
    public string Provider { get; set; } = "";
    public string KeyName { get; set; } = "";
    public string Padding { get; set; } = "";
    /// <summary>Base64 of the device secret, encrypted with the device key.</summary>
    public string WrappedSecret { get; set; } = "";
}

/// <summary>Unencrypted but authenticated header of a vault file.</summary>
public sealed class VaultHeader
{
    public int Version { get; set; } = 1;
    public KdfParams Kdf { get; set; } = new();
    /// <summary>Base64 salt.</summary>
    public string Salt { get; set; } = "";
    public DeviceBindingInfo? Device { get; set; }
    /// <summary>True when a key file is required as a second factor.</summary>
    public bool KeyFile { get; set; }
}

public class VaultException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>The master password (or recovery key) is wrong, or the file was modified.</summary>
public sealed class WrongPasswordException() : VaultException("Wrong master password, or the vault file is damaged.");

/// <summary>The vault needs its key file, and none was given.</summary>
public sealed class KeyFileRequiredException() : VaultException("This vault needs its key file.");

/// <summary>The vault is bound to a device key that is not available here; a recovery key is needed.</summary>
public sealed class DeviceKeyUnavailableException(Exception? inner = null)
    : VaultException("This vault is bound to another device. The recovery key is required.", inner);

/// <summary>
/// File layout: magic (8) | header length (int32 LE) | header JSON | nonce (12) | tag (16) | ciphertext.
/// Everything before the nonce is authenticated as AES-GCM associated data.
/// </summary>
public static class VaultFormat
{
    private static readonly byte[] Magic = "KRYPTA\0\u0001"u8.ToArray();
    private const int NonceSize = 12;
    private const int TagSize = 16;
    public const int KeySize = 32;
    public const int DeviceSecretSize = 32;
    private const int MaxHeaderSize = 64 * 1024;

    internal static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    /// <summary>
    /// Derives the vault key: Argon2id over the master password, then HKDF mixing in the
    /// device secret (device binding) and the hash of the key file (second factor) when used.
    /// </summary>
    public static byte[] DeriveKey(string password, VaultHeader header, ReadOnlySpan<byte> deviceSecret,
        ReadOnlySpan<byte> keyFileHash = default)
    {
        var kdf = header.Kdf;
        if (kdf.Algorithm != "argon2id") throw new VaultException("Unsupported key derivation.");
        if (kdf.MemoryKiB is < 8 * 1024 or > 4 * 1024 * 1024 || kdf.Iterations is < 1 or > 100 || kdf.Parallelism is < 1 or > 64)
            throw new VaultException("Key derivation parameters are out of range.");

        byte[] salt = Convert.FromBase64String(header.Salt);
        if (salt.Length < 16) throw new VaultException("Invalid salt.");

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormC));
        byte[] stretched = [];
        byte[] ikm = [];
        try
        {
            using (var argon = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = kdf.MemoryKiB,
                Iterations = kdf.Iterations,
                DegreeOfParallelism = kdf.Parallelism,
            })
            {
                stretched = argon.GetBytes(KeySize);
            }

            ikm = new byte[stretched.Length + deviceSecret.Length + keyFileHash.Length];
            stretched.CopyTo(ikm, 0);
            deviceSecret.CopyTo(ikm.AsSpan(stretched.Length));
            keyFileHash.CopyTo(ikm.AsSpan(stretched.Length + deviceSecret.Length));
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, KeySize, salt, "Krypta vault key v1"u8.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(stretched);
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    public static byte[] Encrypt(VaultHeader header, ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext)
    {
        byte[] headerJson = JsonSerializer.SerializeToUtf8Bytes(header, Json);
        int prefix = Magic.Length + 4 + headerJson.Length;
        byte[] file = new byte[prefix + NonceSize + TagSize + plaintext.Length];

        Magic.CopyTo(file, 0);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(Magic.Length), headerJson.Length);
        headerJson.CopyTo(file, Magic.Length + 4);

        var nonce = file.AsSpan(prefix, NonceSize);
        var tag = file.AsSpan(prefix + NonceSize, TagSize);
        var ciphertext = file.AsSpan(prefix + NonceSize + TagSize);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, file.AsSpan(0, prefix));
        return file;
    }

    public static VaultHeader ReadHeader(ReadOnlySpan<byte> file, out int prefixLength)
    {
        if (file.Length < Magic.Length + 4 || !file[..Magic.Length].SequenceEqual(Magic))
            throw new VaultException("This is not a Krypta vault file.");
        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(file[Magic.Length..]);
        prefixLength = Magic.Length + 4 + headerLength;
        if (headerLength is <= 0 or > MaxHeaderSize || file.Length < prefixLength + NonceSize + TagSize)
            throw new VaultException("The vault file is damaged.");
        try
        {
            var header = JsonSerializer.Deserialize<VaultHeader>(file.Slice(Magic.Length + 4, headerLength), Json)
                ?? throw new VaultException("The vault file is damaged.");
            if (header.Version != 1) throw new VaultException("This vault was created by a newer version of Krypta.");
            return header;
        }
        catch (JsonException e)
        {
            throw new VaultException("The vault file is damaged.", e);
        }
    }

    public static byte[] Decrypt(ReadOnlySpan<byte> file, int prefixLength, ReadOnlySpan<byte> key)
    {
        var nonce = file.Slice(prefixLength, NonceSize);
        var tag = file.Slice(prefixLength + NonceSize, TagSize);
        var ciphertext = file[(prefixLength + NonceSize + TagSize)..];
        byte[] plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, file[..prefixLength]);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new WrongPasswordException();
        }
    }
}
