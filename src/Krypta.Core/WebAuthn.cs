using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Krypta.Core;

/// <summary>An error that maps to a DOMException in the browser (for example NotAllowedError).</summary>
public sealed class WebAuthnException(string name, string message) : Exception(message)
{
    public string Name { get; } = name;
}

/// <summary>
/// A software WebAuthn authenticator: creates passkeys (ES256 / P-256) and signs login
/// assertions. Requests and responses use the JSON forms defined by WebAuthn Level 3
/// (binary values are base64url strings).
/// </summary>
public static class WebAuthn
{
    /// <summary>Identifies Krypta as the authenticator model.</summary>
    public static readonly Guid Aaguid = new("7c1d2f3a-52e6-4b0c-9a87-4b7279707461");

    private const byte FlagUserPresent = 0x01;
    private const byte FlagUserVerified = 0x04;
    private const byte FlagBackupEligible = 0x08;
    private const byte FlagBackedUp = 0x10;
    private const byte FlagAttestedData = 0x40;
    private const int CoseAlgEs256 = -7;

    private static readonly JsonSerializerOptions ClientDataJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>Returns the relying party id of a request and checks that the origin may use it.</summary>
    public static string ResolveRpId(string? requestedRpId, string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
            throw new WebAuthnException("SecurityError", "Invalid origin.");
        string host = uri.IdnHost.ToLowerInvariant();
        bool local = host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal);
        if (uri.Scheme != "https" && !(uri.Scheme == "http" && local))
            throw new WebAuthnException("SecurityError", "Passkeys require a secure (https) origin.");

        string rpId = string.IsNullOrEmpty(requestedRpId) ? host : requestedRpId.ToLowerInvariant();
        bool matches = host == rpId || host.EndsWith("." + rpId, StringComparison.Ordinal);
        bool plausible = rpId == "localhost" || (rpId.Contains('.') && !rpId.StartsWith('.') && !rpId.EndsWith('.'));
        if (!matches || !plausible)
            throw new WebAuthnException("SecurityError", "The relying party id does not match the website.");
        return rpId;
    }

    private static string? GetString(JsonElement element, params string[] path)
    {
        foreach (string name in path)
        {
            if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out element)) return null;
        }
        return element.ValueKind == JsonValueKind.String ? element.GetString() : null;
    }

    private static List<string> CredentialIds(JsonElement options, string property)
    {
        var ids = new List<string>();
        if (options.TryGetProperty(property, out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in list.EnumerateArray())
            {
                if (GetString(item, "id") is { } id) ids.Add(id.TrimEnd('='));
            }
        }
        return ids;
    }

    private static byte[] BuildClientData(string type, string challenge, string origin)
    {
        // Field order and format follow the WebAuthn "serialization of client data".
        var sb = new StringBuilder();
        sb.Append("{\"type\":").Append(JsonSerializer.Serialize(type, ClientDataJson));
        sb.Append(",\"challenge\":").Append(JsonSerializer.Serialize(challenge, ClientDataJson));
        sb.Append(",\"origin\":").Append(JsonSerializer.Serialize(origin, ClientDataJson));
        sb.Append(",\"crossOrigin\":false}");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static string NormalizeOrigin(string origin)
    {
        var uri = new Uri(origin);
        return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.IdnHost}" : $"{uri.Scheme}://{uri.IdnHost}:{uri.Port}";
    }

    private static string RequireChallenge(JsonElement options)
    {
        string? challenge = GetString(options, "challenge");
        if (string.IsNullOrEmpty(challenge)) throw new WebAuthnException("TypeError", "The request has no challenge.");
        return B64Url.Encode(B64Url.Decode(challenge));
    }

    /// <summary>
    /// Handles <c>navigator.credentials.create()</c>: makes a new passkey and returns the
    /// registration response (RegistrationResponseJSON) together with the data to store.
    /// </summary>
    public static (JsonObject Response, PasskeyData Passkey) CreateCredential(
        JsonElement options, string origin, IEnumerable<PasskeyData> existing)
    {
        string rpId = ResolveRpId(GetString(options, "rp", "id"), origin);
        string challenge = RequireChallenge(options);
        string? userHandle = GetString(options, "user", "id");
        if (string.IsNullOrEmpty(userHandle)) throw new WebAuthnException("TypeError", "The request has no user id.");

        bool es256 = false;
        if (options.TryGetProperty("pubKeyCredParams", out var algorithms) && algorithms.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in algorithms.EnumerateArray())
            {
                if (item.TryGetProperty("alg", out var alg) && alg.TryGetInt32(out int value) && value == CoseAlgEs256) es256 = true;
            }
        }
        if (!es256) throw new WebAuthnException("NotSupportedError", "The website does not accept ES256 passkeys.");

        var excluded = CredentialIds(options, "excludeCredentials");
        if (existing.Any(p => p.RpId == rpId && excluded.Contains(p.CredentialId)))
            throw new WebAuthnException("InvalidStateError", "A passkey for this account already exists in this vault.");

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(false);
        byte[] credentialId = RandomNumberGenerator.GetBytes(32);

        var cose = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2);              // kty: EC2
        cose.WriteInt32(3); cose.WriteInt32(CoseAlgEs256);   // alg: ES256
        cose.WriteInt32(-1); cose.WriteInt32(1);             // crv: P-256
        cose.WriteInt32(-2); cose.WriteByteString(parameters.Q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(parameters.Q.Y!);
        cose.WriteEndMap();
        byte[] coseKey = cose.Encode();

        byte flags = FlagUserPresent | FlagUserVerified | FlagBackupEligible | FlagBackedUp | FlagAttestedData;
        byte[] authData = new byte[37 + 16 + 2 + credentialId.Length + coseKey.Length];
        WriteAuthDataPrefix(authData, rpId, flags);
        Aaguid.ToByteArray(bigEndian: true).CopyTo(authData, 37);
        BinaryPrimitives.WriteUInt16BigEndian(authData.AsSpan(53), (ushort)credentialId.Length);
        credentialId.CopyTo(authData, 55);
        coseKey.CopyTo(authData, 55 + credentialId.Length);

        var attestation = new CborWriter(CborConformanceMode.Ctap2Canonical);
        attestation.WriteStartMap(3);
        attestation.WriteTextString("fmt"); attestation.WriteTextString("none");
        attestation.WriteTextString("attStmt"); attestation.WriteStartMap(0); attestation.WriteEndMap();
        attestation.WriteTextString("authData"); attestation.WriteByteString(authData);
        attestation.WriteEndMap();

        string normalizedOrigin = NormalizeOrigin(origin);
        byte[] clientData = BuildClientData("webauthn.create", challenge, normalizedOrigin);
        string id = B64Url.Encode(credentialId);

        byte[] pkcs8 = key.ExportPkcs8PrivateKey();
        var passkey = new PasskeyData
        {
            CredentialId = id,
            RpId = rpId,
            RpName = GetString(options, "rp", "name") ?? rpId,
            UserHandle = B64Url.Encode(B64Url.Decode(userHandle)),
            UserName = GetString(options, "user", "name") ?? "",
            UserDisplayName = GetString(options, "user", "displayName") ?? "",
            PrivateKeyPkcs8 = Convert.ToBase64String(pkcs8),
        };
        CryptographicOperations.ZeroMemory(pkcs8);

        var response = new JsonObject
        {
            ["id"] = id,
            ["rawId"] = id,
            ["type"] = "public-key",
            ["authenticatorAttachment"] = "platform",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = B64Url.Encode(clientData),
                ["attestationObject"] = B64Url.Encode(attestation.Encode()),
                ["authenticatorData"] = B64Url.Encode(authData),
                ["publicKey"] = B64Url.Encode(key.ExportSubjectPublicKeyInfo()),
                ["publicKeyAlgorithm"] = CoseAlgEs256,
                ["transports"] = new JsonArray("internal"),
            },
            ["clientExtensionResults"] = new JsonObject { ["credProps"] = new JsonObject { ["rk"] = true } },
        };
        return (response, passkey);
    }

    /// <summary>Passkeys in the vault that can answer a <c>navigator.credentials.get()</c> request.</summary>
    public static List<PasskeyData> FindCandidates(JsonElement options, string origin, IEnumerable<PasskeyData> all)
    {
        string rpId = ResolveRpId(GetString(options, "rpId"), origin);
        var allowed = CredentialIds(options, "allowCredentials");
        return all.Where(p => p.RpId == rpId && (allowed.Count == 0 || allowed.Contains(p.CredentialId))).ToList();
    }

    /// <summary>Signs a login assertion (AuthenticationResponseJSON) with the given passkey.</summary>
    public static JsonObject GetAssertion(JsonElement options, string origin, PasskeyData passkey)
    {
        string rpId = ResolveRpId(GetString(options, "rpId"), origin);
        if (passkey.RpId != rpId) throw new WebAuthnException("NotAllowedError", "This passkey belongs to another website.");
        string challenge = RequireChallenge(options);

        byte[] authData = new byte[37];
        WriteAuthDataPrefix(authData, rpId, FlagUserPresent | FlagUserVerified | FlagBackupEligible | FlagBackedUp);
        byte[] clientData = BuildClientData("webauthn.get", challenge, NormalizeOrigin(origin));

        byte[] signed = new byte[authData.Length + 32];
        authData.CopyTo(signed, 0);
        SHA256.HashData(clientData, signed.AsSpan(authData.Length));

        byte[] pkcs8 = Convert.FromBase64String(passkey.PrivateKeyPkcs8);
        byte[] signature;
        try
        {
            using var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(pkcs8, out _);
            signature = key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }

        return new JsonObject
        {
            ["id"] = passkey.CredentialId,
            ["rawId"] = passkey.CredentialId,
            ["type"] = "public-key",
            ["authenticatorAttachment"] = "platform",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = B64Url.Encode(clientData),
                ["authenticatorData"] = B64Url.Encode(authData),
                ["signature"] = B64Url.Encode(signature),
                ["userHandle"] = passkey.UserHandle,
            },
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    /// <summary>rpIdHash (32) | flags (1) | signature counter (4, always 0 for synced passkeys).</summary>
    private static void WriteAuthDataPrefix(Span<byte> authData, string rpId, byte flags)
    {
        SHA256.HashData(Encoding.UTF8.GetBytes(rpId), authData);
        authData[32] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(authData[33..], 0);
    }
}
