using System.Security.Cryptography;
using Krypta.Core;

namespace Krypta.App.Services;

/// <summary>
/// Binds a vault to this computer with an RSA key that lives inside the TPM chip and cannot be
/// exported. Someone who copies the vault file (and even knows the master password) cannot open
/// it on another machine without the recovery key.
/// </summary>
internal sealed class TpmDeviceKeyProvider : IDeviceKeyProvider
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private static readonly CngProvider Provider = new(ProviderName);
    private bool? _available;

    private static readonly (string Name, RSAEncryptionPadding Padding)[] Paddings =
    [
        ("OAEP-SHA256", RSAEncryptionPadding.OaepSHA256),
        ("OAEP-SHA1", RSAEncryptionPadding.OaepSHA1),
    ];

    public bool IsAvailable
    {
        get
        {
            if (_available is null)
            {
                try
                {
                    CngKey.Exists("Krypta-Probe", Provider);
                    _available = true;
                }
                catch (Exception e) when (e is CryptographicException or PlatformNotSupportedException)
                {
                    _available = false;
                }
            }
            return _available.Value;
        }
    }

    public DeviceBindingInfo Wrap(ReadOnlySpan<byte> secret)
    {
        string keyName = "Krypta-Device-" + Guid.NewGuid().ToString("N");
        var creation = new CngKeyCreationParameters
        {
            Provider = Provider,
            KeyUsage = CngKeyUsages.Decryption,
            ExportPolicy = CngExportPolicies.None,
        };
        creation.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));

        using var key = CngKey.Create(CngAlgorithm.Rsa, keyName, creation);
        using var tpm = new RSACng(key);
        using var publicKey = RSA.Create(tpm.ExportParameters(false));
        byte[] plain = secret.ToArray();
        try
        {
            // TPMs differ in which padding they accept, so check that a round trip works.
            foreach (var (name, padding) in Paddings)
            {
                try
                {
                    byte[] wrapped = publicKey.Encrypt(plain, padding);
                    byte[] check = tpm.Decrypt(wrapped, padding);
                    bool same = CryptographicOperations.FixedTimeEquals(check, plain);
                    CryptographicOperations.ZeroMemory(check);
                    if (same)
                    {
                        return new DeviceBindingInfo
                        {
                            Provider = ProviderName,
                            KeyName = keyName,
                            Padding = name,
                            WrappedSecret = Convert.ToBase64String(wrapped),
                        };
                    }
                }
                catch (CryptographicException)
                {
                    // Try the next padding.
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }

        key.Delete();
        throw new CryptographicException("The TPM of this device cannot be used to protect the vault.");
    }

    public byte[] Unwrap(DeviceBindingInfo info)
    {
        if (info.Provider != ProviderName) throw new CryptographicException("Unknown device key provider.");
        var padding = Paddings.FirstOrDefault(p => p.Name == info.Padding).Padding
            ?? throw new CryptographicException("Unknown padding.");
        using var key = CngKey.Open(info.KeyName, Provider);
        using var tpm = new RSACng(key);
        return tpm.Decrypt(Convert.FromBase64String(info.WrappedSecret), padding);
    }

    public void Delete(DeviceBindingInfo info)
    {
        if (info.Provider != ProviderName || !info.KeyName.StartsWith("Krypta-Device-", StringComparison.Ordinal)) return;
        try
        {
            if (CngKey.Exists(info.KeyName, Provider))
            {
                using var key = CngKey.Open(info.KeyName, Provider);
                key.Delete();
            }
        }
        catch (CryptographicException)
        {
        }
    }
}
