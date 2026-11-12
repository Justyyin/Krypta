using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Krypta.Core;

/// <summary>
/// Wraps a random secret with a key that cannot be copied off this computer (for example a TPM key).
/// A stolen vault file is then useless without the device or the recovery key.
/// </summary>
public interface IDeviceKeyProvider
{
    bool IsAvailable { get; }
    DeviceBindingInfo Wrap(ReadOnlySpan<byte> secret);
    /// <summary>Throws when the key is not present on this device.</summary>
    byte[] Unwrap(DeviceBindingInfo info);
    void Delete(DeviceBindingInfo info);
}

/// <summary>
/// Keeps key material encrypted while it sits in memory (Windows CryptProtectMemory, tied to this
/// process). A memory dump or a scan of the process then does not contain the plain vault key.
/// </summary>
internal sealed class GuardedBytes : IDisposable
{
    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptProtectMemory(byte[] data, uint size, uint flags);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectMemory(byte[] data, uint size, uint flags);

    private byte[] _data;
    private readonly bool _encrypted;

    public int Length => _data.Length;

    /// <summary>Takes ownership of <paramref name="plain"/>; the caller must not use the array afterwards.</summary>
    public GuardedBytes(byte[] plain)
    {
        _data = plain;
        _encrypted = OperatingSystem.IsWindows() && plain.Length > 0 && plain.Length % 16 == 0 &&
                     CryptProtectMemory(_data, (uint)_data.Length, 0);
    }

    /// <summary>Runs <paramref name="use"/> with a short-lived plain copy that is wiped afterwards.</summary>
    public T Use<T>(Func<byte[], T> use)
    {
        byte[] copy = (byte[])_data.Clone();
        try
        {
            if (_encrypted && !CryptUnprotectMemory(copy, (uint)copy.Length, 0))
                throw new CryptographicException("The protected key could not be read.");
            return use(copy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_data);
        _data = [];
    }
}

/// <summary>An unlocked vault. Dispose it to lock: the key is wiped from memory.</summary>
public sealed class Vault : IDisposable
{
    private GuardedBytes _key;
    private GuardedBytes _deviceSecret;
    private GuardedBytes _keyFileHash;

    public string Path { get; }
    public VaultHeader Header { get; private set; }
    public VaultData Data { get; private set; }
    public bool IsDeviceBound => Header.Device is not null;
    public bool UsesKeyFile => Header.KeyFile;

    private Vault(string path, VaultHeader header, VaultData data, byte[] key, byte[] deviceSecret, byte[] keyFileHash)
    {
        Path = path;
        Header = header;
        Data = data;
        _key = new GuardedBytes(key);
        _deviceSecret = new GuardedBytes(deviceSecret);
        _keyFileHash = new GuardedBytes(keyFileHash);
    }

    private static string NewSalt() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static byte[] HashKeyFile(byte[]? keyFile)
    {
        if (keyFile is null) return [];
        if (keyFile.Length < 16) throw new VaultException("The key file is too short to be a key file.");
        return SHA256.HashData(keyFile);
    }

    /// <summary>Random content for a new key file.</summary>
    public static byte[] NewKeyFile() => RandomNumberGenerator.GetBytes(64);

    /// <summary>
    /// Creates a new vault file. When <paramref name="device"/> is given the vault is bound to this
    /// device and <paramref name="recoveryKey"/> returns the key needed to open it anywhere else.
    /// With <paramref name="keyFile"/> the vault additionally needs that file every time it is opened.
    /// </summary>
    public static Vault Create(string path, string password, out string? recoveryKey,
        IDeviceKeyProvider? device = null, KdfParams? kdf = null, byte[]? keyFile = null)
    {
        if (File.Exists(path)) throw new VaultException("A file already exists at this location.");
        byte[] keyFileHash = HashKeyFile(keyFile);
        var header = new VaultHeader { Kdf = kdf ?? new KdfParams(), Salt = NewSalt(), KeyFile = keyFile is not null };
        byte[] deviceSecret = [];
        recoveryKey = null;
        if (device is not null)
        {
            deviceSecret = RandomNumberGenerator.GetBytes(VaultFormat.DeviceSecretSize);
            header.Device = device.Wrap(deviceSecret);
            recoveryKey = FormatRecoveryKey(deviceSecret);
        }

        byte[] key = VaultFormat.DeriveKey(password, header, deviceSecret, keyFileHash);
        var vault = new Vault(path, header, new VaultData(), key, deviceSecret, keyFileHash);
        vault.Save();
        return vault;
    }

    /// <summary>
    /// Opens a vault. For a device-bound vault the device key is tried first; if it is missing,
    /// <paramref name="recoveryKey"/> is used and the vault is re-bound to this device when possible.
    /// </summary>
    public static Vault Open(string path, string password, IDeviceKeyProvider? device = null,
        string? recoveryKey = null, byte[]? keyFile = null)
    {
        byte[] file = File.ReadAllBytes(path);
        var header = VaultFormat.ReadHeader(file, out int prefix);

        if (header.KeyFile && keyFile is null) throw new KeyFileRequiredException();
        byte[] keyFileHash = header.KeyFile ? HashKeyFile(keyFile) : [];

        byte[] deviceSecret = [];
        bool rebind = false;
        if (header.Device is not null)
        {
            if (!string.IsNullOrWhiteSpace(recoveryKey))
            {
                deviceSecret = ParseRecoveryKey(recoveryKey);
                rebind = true;
            }
            else
            {
                if (device is null) throw new DeviceKeyUnavailableException();
                try { deviceSecret = device.Unwrap(header.Device); }
                catch (Exception e) when (e is not VaultException) { throw new DeviceKeyUnavailableException(e); }
            }
        }

        byte[] key = VaultFormat.DeriveKey(password, header, deviceSecret, keyFileHash);
        byte[] plaintext;
        try
        {
            plaintext = VaultFormat.Decrypt(file, prefix, key);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(deviceSecret);
            throw;
        }

        VaultData data;
        try
        {
            data = JsonSerializer.Deserialize<VaultData>(plaintext, VaultFormat.Json) ?? new VaultData();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        DeviceBindingInfo? newBinding = null;
        if (rebind && device is { IsAvailable: true })
        {
            try { newBinding = device.Wrap(deviceSecret); }
            catch (CryptographicException) { } // stays usable with the recovery key
        }

        var vault = new Vault(path, header, data, key, deviceSecret, keyFileHash);
        if (newBinding is not null)
        {
            header.Device = newBinding;
            vault.Save();
        }
        return vault;
    }

    private void ThrowIfLocked() => ObjectDisposedException.ThrowIf(_key.Length == 0, this);

    /// <summary>Encrypts and writes the vault. The previous file is kept as <c>.bak</c>.</summary>
    public void Save()
    {
        ThrowIfLocked();
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(Data, VaultFormat.Json);
        try
        {
            byte[] file = _key.Use(key => VaultFormat.Encrypt(Header, key, plaintext));
            string directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path))!;
            Directory.CreateDirectory(directory);
            string temp = Path + ".tmp";
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.Write(file);
                stream.Flush(flushToDisk: true);
            }
            if (File.Exists(Path)) File.Replace(temp, Path, Path + ".bak");
            else File.Move(temp, Path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Derives a new key for a changed header (new password, device binding or key file) and saves.
    /// Everything is put back if saving fails.
    /// </summary>
    private void Rekey(string password, DeviceBindingInfo? binding, byte[] deviceSecret, bool usesKeyFile, byte[] keyFileHash)
    {
        var header = new VaultHeader { Kdf = Header.Kdf, Salt = NewSalt(), Device = binding, KeyFile = usesKeyFile };
        var newKey = new GuardedBytes(VaultFormat.DeriveKey(password, header, deviceSecret, keyFileHash));
        var newSecret = new GuardedBytes(deviceSecret);
        var newHash = new GuardedBytes(keyFileHash);

        var (oldKey, oldSecret, oldHash, oldHeader) = (_key, _deviceSecret, _keyFileHash, Header);
        (_key, _deviceSecret, _keyFileHash, Header) = (newKey, newSecret, newHash, header);
        try
        {
            Save();
        }
        catch
        {
            (_key, _deviceSecret, _keyFileHash, Header) = (oldKey, oldSecret, oldHash, oldHeader);
            newKey.Dispose();
            newSecret.Dispose();
            newHash.Dispose();
            throw;
        }
        oldKey.Dispose();
        oldSecret.Dispose();
        oldHash.Dispose();
    }

    public void ChangePassword(string newPassword)
    {
        ThrowIfLocked();
        Rekey(newPassword, Header.Device, _deviceSecret.Use(s => (byte[])s.Clone()), Header.KeyFile, _keyFileHash.Use(h => (byte[])h.Clone()));
    }

    /// <summary>The recovery key of a device-bound vault (the device secret in readable form).</summary>
    public string? RecoveryKey => IsDeviceBound ? _deviceSecret.Use(secret => FormatRecoveryKey(secret)) : null;

    /// <summary>
    /// Binds the vault to a device key, or removes the binding when <paramref name="device"/> is null.
    /// The master password is needed because the vault key is derived again. Returns the new recovery key.
    /// </summary>
    public string? SetDeviceBinding(string password, IDeviceKeyProvider? device)
    {
        ThrowIfLocked();
        if (!VerifyPassword(password)) throw new WrongPasswordException();
        byte[] secret = device is null ? [] : RandomNumberGenerator.GetBytes(VaultFormat.DeviceSecretSize);
        string? recoveryKey = device is null ? null : FormatRecoveryKey(secret);
        Rekey(password, device?.Wrap(secret), secret, Header.KeyFile, _keyFileHash.Use(h => (byte[])h.Clone()));
        return recoveryKey;
    }

    /// <summary>
    /// Makes a key file a required second factor, or removes that requirement when
    /// <paramref name="keyFile"/> is null. Needs the master password.
    /// </summary>
    public void SetKeyFile(string password, byte[]? keyFile)
    {
        ThrowIfLocked();
        if (!VerifyPassword(password)) throw new WrongPasswordException();
        Rekey(password, Header.Device, _deviceSecret.Use(s => (byte[])s.Clone()), keyFile is not null, HashKeyFile(keyFile));
    }

    /// <summary>Checks a password against this open vault without touching the file.</summary>
    public bool VerifyPassword(string password)
    {
        ThrowIfLocked();
        byte[] candidate = _deviceSecret.Use(secret => _keyFileHash.Use(hash => VaultFormat.DeriveKey(password, Header, secret, hash)));
        try { return _key.Use(key => CryptographicOperations.FixedTimeEquals(candidate, key)); }
        finally { CryptographicOperations.ZeroMemory(candidate); }
    }

    public void Dispose()
    {
        _key.Dispose();
        _deviceSecret.Dispose();
        _keyFileHash.Dispose();
        Data = new VaultData();
    }

    public static string FormatRecoveryKey(ReadOnlySpan<byte> secret)
    {
        string encoded = Base32.Encode(secret);
        return string.Join("-", Enumerable.Range(0, (encoded.Length + 3) / 4)
            .Select(i => encoded.Substring(i * 4, Math.Min(4, encoded.Length - i * 4))));
    }

    public static byte[] ParseRecoveryKey(string recoveryKey)
    {
        if (!Base32.TryDecode(recoveryKey, out byte[] secret) || secret.Length != VaultFormat.DeviceSecretSize)
            throw new VaultException("The recovery key is not valid.");
        return secret;
    }
}
