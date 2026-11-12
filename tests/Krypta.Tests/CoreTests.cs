using System.Formats.Cbor;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;
using Krypta.Core;

namespace Krypta.Tests;

public class EncodingTests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32_matches_rfc4648_vectors(string plain, string encoded)
    {
        Assert.Equal(encoded, Base32.Encode(Encoding.ASCII.GetBytes(plain)));
        Assert.Equal(plain, Encoding.ASCII.GetString(Base32.Decode(encoded)));
        Assert.Equal(plain, Encoding.ASCII.GetString(Base32.Decode(encoded.ToLowerInvariant() + "==")));
    }

    [Fact]
    public void Base32_rejects_invalid_characters() => Assert.False(Base32.TryDecode("ABC1", out _));
}

public class TotpTests
{
    private static TotpConfig Config(string asciiKey, string algorithm) => new()
    {
        Secret = Base32.Encode(Encoding.ASCII.GetBytes(asciiKey)),
        Algorithm = algorithm,
        Digits = 8,
    };

    // Test vectors from RFC 6238, appendix B.
    [Theory]
    [InlineData(59, "SHA1", "12345678901234567890", "94287082")]
    [InlineData(1111111109, "SHA1", "12345678901234567890", "07081804")]
    [InlineData(20000000000, "SHA1", "12345678901234567890", "65353130")]
    [InlineData(59, "SHA256", "12345678901234567890123456789012", "46119246")]
    [InlineData(1111111109, "SHA256", "12345678901234567890123456789012", "68084774")]
    [InlineData(59, "SHA512", "1234567890123456789012345678901234567890123456789012345678901234", "90693936")]
    [InlineData(1111111109, "SHA512", "1234567890123456789012345678901234567890123456789012345678901234", "25091201")]
    public void Compute_matches_rfc6238_vectors(long unixTime, string algorithm, string key, string expected)
    {
        Assert.Equal(expected, Totp.Compute(Config(key, algorithm), DateTimeOffset.FromUnixTimeSeconds(unixTime)));
    }

    [Fact]
    public void SecondsRemaining_counts_down_within_the_period()
    {
        var config = new TotpConfig { Secret = "JBSWY3DPEHPK3PXP" };
        Assert.Equal(30, Totp.SecondsRemaining(config, DateTimeOffset.FromUnixTimeSeconds(60)));
        Assert.Equal(1, Totp.SecondsRemaining(config, DateTimeOffset.FromUnixTimeSeconds(89)));
    }

    [Fact]
    public void ParseUri_reads_all_fields()
    {
        var config = Totp.ParseUri("otpauth://totp/Example%20Corp:alice@example.com?secret=jbsw%20y3dp-ehpk3pxp&issuer=Example%20Corp&algorithm=SHA256&digits=8&period=60");
        Assert.Equal("JBSWY3DPEHPK3PXP", config.Secret);
        Assert.Equal("Example Corp", config.Issuer);
        Assert.Equal("alice@example.com", config.Account);
        Assert.Equal("SHA256", config.Algorithm);
        Assert.Equal(8, config.Digits);
        Assert.Equal(60, config.Period);
    }

    [Fact]
    public void ParseUri_uses_defaults_and_label_issuer()
    {
        var config = Totp.ParseUri("otpauth://totp/GitHub:bob?secret=JBSWY3DPEHPK3PXP");
        Assert.Equal("GitHub", config.Issuer);
        Assert.Equal("bob", config.Account);
        Assert.Equal(("SHA1", 6, 30), (config.Algorithm, config.Digits, config.Period));
    }

    [Fact]
    public void ParseUri_rejects_bad_input()
    {
        Assert.Throws<FormatException>(() => Totp.ParseUri("https://example.com"));
        Assert.Throws<FormatException>(() => Totp.ParseUri("otpauth://totp/x?secret=!!!"));
        Assert.Throws<FormatException>(() => Totp.ParseUri("otpauth://totp/x"));
        Assert.Throws<NotSupportedException>(() => Totp.ParseUri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1"));
    }
}

public class PasswordGeneratorTests
{
    [Fact]
    public void Generated_password_has_requested_length_and_all_classes()
    {
        var options = new PasswordOptions { Length = 24 };
        for (int i = 0; i < 200; i++)
        {
            string password = PasswordGenerator.Generate(options);
            Assert.Equal(24, password.Length);
            Assert.Contains(password, char.IsUpper);
            Assert.Contains(password, char.IsLower);
            Assert.Contains(password, char.IsDigit);
            Assert.Contains(password, c => !char.IsLetterOrDigit(c));
        }
    }

    [Fact]
    public void Only_selected_classes_are_used()
    {
        var options = new PasswordOptions { Length = 64, Upper = false, Symbols = false, Lower = false };
        Assert.All(PasswordGenerator.Generate(options), c => Assert.True(char.IsAsciiDigit(c)));
    }

    [Fact]
    public void Ambiguous_characters_can_be_excluded()
    {
        var options = new PasswordOptions { Length = 128, ExcludeAmbiguous = true };
        for (int i = 0; i < 50; i++)
            Assert.DoesNotContain(PasswordGenerator.Generate(options), c => "Il1O0o|".Contains(c));
    }

    [Fact]
    public void Length_is_clamped_and_passwords_differ()
    {
        Assert.Equal(PasswordGenerator.MinLength, PasswordGenerator.Generate(new PasswordOptions { Length = 1 }).Length);
        Assert.Equal(PasswordGenerator.MaxLength, PasswordGenerator.Generate(new PasswordOptions { Length = 9999 }).Length);
        Assert.NotEqual(PasswordGenerator.Generate(new PasswordOptions()), PasswordGenerator.Generate(new PasswordOptions()));
    }

    [Fact]
    public void Entropy_grows_with_length_and_pool()
    {
        double digits = PasswordGenerator.EntropyBits(new PasswordOptions { Length = 10, Upper = false, Lower = false, Symbols = false });
        Assert.Equal(10 * Math.Log2(10), digits, 6);
        Assert.True(PasswordGenerator.EntropyBits(new PasswordOptions { Length = 20 }) > 120);
    }

    [Fact]
    public void Strength_estimate_orders_weak_and_strong()
    {
        Assert.Equal(0, PasswordGenerator.EstimateStrength("aaaaaaaaaaaaaaaaaaaa"));
        Assert.Equal(0, PasswordGenerator.EstimateStrength("hallo"));
        Assert.Equal(4, PasswordGenerator.EstimateStrength(PasswordGenerator.Generate(new PasswordOptions { Length = 24 })));
    }
}

public class VaultTests : IDisposable
{
    private static readonly KdfParams FastKdf = new() { MemoryKiB = 8 * 1024, Iterations = 1, Parallelism = 2 };
    private readonly string _dir = Directory.CreateTempSubdirectory("krypta-test-").FullName;
    private string VaultPath => Path.Combine(_dir, "vault.krypta");

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed class FakeDeviceKey : IDeviceKeyProvider
    {
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
        public bool Present { get; set; } = true;
        public bool IsAvailable => Present;
        public int WrapCount { get; private set; }

        public DeviceBindingInfo Wrap(ReadOnlySpan<byte> secret)
        {
            WrapCount++;
            byte[] wrapped = secret.ToArray();
            for (int i = 0; i < wrapped.Length; i++) wrapped[i] ^= _key[i];
            return new DeviceBindingInfo { Provider = "fake", KeyName = "k", WrappedSecret = Convert.ToBase64String(wrapped) };
        }

        public byte[] Unwrap(DeviceBindingInfo info)
        {
            if (!Present) throw new CryptographicException("Key not found.");
            byte[] secret = Convert.FromBase64String(info.WrappedSecret);
            for (int i = 0; i < secret.Length; i++) secret[i] ^= _key[i];
            return secret;
        }

        public void Delete(DeviceBindingInfo info) { }
    }

    [Fact]
    public void Argon2id_matches_rfc9106_test_vector()
    {
        using var argon = new Argon2id(Enumerable.Repeat((byte)1, 32).ToArray())
        {
            Salt = Enumerable.Repeat((byte)2, 16).ToArray(),
            KnownSecret = Enumerable.Repeat((byte)3, 8).ToArray(),
            AssociatedData = Enumerable.Repeat((byte)4, 12).ToArray(),
            MemorySize = 32,
            Iterations = 3,
            DegreeOfParallelism = 4,
        };
        Assert.Equal("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            Convert.ToHexStringLower(argon.GetBytes(32)));
    }

    [Fact]
    public void Vault_round_trips_entries()
    {
        using (var vault = Vault.Create(VaultPath, "pässwört ß€", out string? recovery, kdf: FastKdf))
        {
            Assert.Null(recovery);
            vault.Data.Entries.Add(new Entry { Title = "Example", Username = "alice", Password = "s3cret", Totp = new TotpConfig { Secret = "JBSWY3DPEHPK3PXP" } });
            vault.Save();
        }

        using var reopened = Vault.Open(VaultPath, "pässwört ß€");
        var entry = Assert.Single(reopened.Data.Entries);
        Assert.Equal(("Example", "alice", "s3cret"), (entry.Title, entry.Username, entry.Password));
        Assert.Equal("JBSWY3DPEHPK3PXP", entry.Totp!.Secret);
    }

    [Fact]
    public void Secrets_are_not_stored_in_plain_text()
    {
        using (var vault = Vault.Create(VaultPath, "master", out _, kdf: FastKdf))
        {
            vault.Data.Entries.Add(new Entry { Title = "VisibleTitleMarker", Password = "VisiblePasswordMarker" });
            vault.Save();
        }
        string raw = Encoding.Latin1.GetString(File.ReadAllBytes(VaultPath));
        Assert.DoesNotContain("VisibleTitleMarker", raw);
        Assert.DoesNotContain("VisiblePasswordMarker", raw);
        Assert.Contains("argon2id", raw);
    }

    [Fact]
    public void Wrong_password_is_rejected()
    {
        Vault.Create(VaultPath, "correct", out _, kdf: FastKdf).Dispose();
        Assert.Throws<WrongPasswordException>(() => Vault.Open(VaultPath, "wrong"));
    }

    [Fact]
    public void Tampering_with_header_or_ciphertext_is_detected()
    {
        Vault.Create(VaultPath, "master", out _, kdf: FastKdf).Dispose();
        byte[] original = File.ReadAllBytes(VaultPath);

        byte[] flippedBody = (byte[])original.Clone();
        flippedBody[^1] ^= 1;
        File.WriteAllBytes(VaultPath, flippedBody);
        Assert.Throws<WrongPasswordException>(() => Vault.Open(VaultPath, "master"));

        // Changing an authenticated header field (parallelism 2 -> 3) must fail too.
        string text = Encoding.Latin1.GetString(original);
        Assert.Contains("\"Parallelism\":2", text);
        File.WriteAllBytes(VaultPath, Encoding.Latin1.GetBytes(text.Replace("\"Parallelism\":2", "\"Parallelism\":3")));
        Assert.Throws<WrongPasswordException>(() => Vault.Open(VaultPath, "master"));

        File.WriteAllBytes(VaultPath, [1, 2, 3]);
        Assert.Throws<VaultException>(() => Vault.Open(VaultPath, "master"));
    }

    [Fact]
    public void Each_save_uses_a_fresh_nonce_and_keeps_a_backup()
    {
        using var vault = Vault.Create(VaultPath, "master", out _, kdf: FastKdf);
        byte[] first = File.ReadAllBytes(VaultPath);
        vault.Save();
        byte[] second = File.ReadAllBytes(VaultPath);
        Assert.NotEqual(first, second);
        Assert.Equal(first, File.ReadAllBytes(VaultPath + ".bak"));
        Assert.False(File.Exists(VaultPath + ".tmp"));
    }

    [Fact]
    public void Password_can_be_changed()
    {
        using (var vault = Vault.Create(VaultPath, "old", out _, kdf: FastKdf))
        {
            vault.Data.Entries.Add(new Entry { Title = "kept" });
            Assert.True(vault.VerifyPassword("old"));
            Assert.False(vault.VerifyPassword("other"));
            vault.ChangePassword("new");
        }
        Assert.Throws<WrongPasswordException>(() => Vault.Open(VaultPath, "old"));
        using var reopened = Vault.Open(VaultPath, "new");
        Assert.Equal("kept", Assert.Single(reopened.Data.Entries).Title);
    }

    [Fact]
    public void Device_bound_vault_needs_the_device_or_the_recovery_key()
    {
        var device = new FakeDeviceKey();
        string? recovery;
        using (var vault = Vault.Create(VaultPath, "master", out recovery, device, FastKdf))
        {
            Assert.True(vault.IsDeviceBound);
            Assert.NotNull(recovery);
        }

        // Same device: opens with the password alone.
        Vault.Open(VaultPath, "master", device).Dispose();

        // A thief with the file and the password, but without the device key, gets nothing.
        Assert.Throws<DeviceKeyUnavailableException>(() => Vault.Open(VaultPath, "master"));
        var otherDevice = new FakeDeviceKey { Present = false };
        Assert.Throws<DeviceKeyUnavailableException>(() => Vault.Open(VaultPath, "master", otherDevice));
        Assert.Throws<WrongPasswordException>(() => Vault.Open(VaultPath, "master", new FakeDeviceKey()));

        // Wrong recovery key fails; the right one opens and re-binds to the new device.
        string wrongRecovery = Vault.FormatRecoveryKey(RandomNumberGenerator.GetBytes(32));
        Assert.Throws<WrongPasswordException>(() => Vault.Open(VaultPath, "master", otherDevice, wrongRecovery));
        Assert.Throws<VaultException>(() => Vault.Open(VaultPath, "master", otherDevice, "ABCD-EFGH"));

        var newDevice = new FakeDeviceKey();
        Vault.Open(VaultPath, "master", newDevice, recovery).Dispose();
        Assert.Equal(1, newDevice.WrapCount);
        Vault.Open(VaultPath, "master", newDevice).Dispose();
    }

    [Fact]
    public void Recovery_key_round_trips()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        string formatted = Vault.FormatRecoveryKey(secret);
        Assert.Matches("^([A-Z2-7]{4}-){12}[A-Z2-7]{4}$", formatted);
        Assert.Equal(secret, Vault.ParseRecoveryKey(formatted.ToLowerInvariant().Replace('-', ' ')));
    }

    [Fact]
    public void Disposed_vault_cannot_be_saved_and_drops_its_data()
    {
        var vault = Vault.Create(VaultPath, "master", out _, kdf: FastKdf);
        vault.Data.Entries.Add(new Entry { Title = "x" });
        vault.Dispose();
        Assert.Empty(vault.Data.Entries);
        Assert.Throws<ObjectDisposedException>(vault.Save);
    }
}

public class WebAuthnTests
{
    private const string Origin = "https://login.example.com";

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    private static JsonElement CreateOptions(string extra = "") => Json($$"""
        {
          "rp": { "id": "example.com", "name": "Example" },
          "user": { "id": "dXNlci0x", "name": "alice@example.com", "displayName": "Alice" },
          "challenge": "Y2hhbGxlbmdlLTE",
          "pubKeyCredParams": [ { "type": "public-key", "alg": -257 }, { "type": "public-key", "alg": -7 } ]
          {{extra}}
        }
        """);

    [Fact]
    public void Created_passkey_is_well_formed_and_can_sign_in()
    {
        var (response, passkey) = WebAuthn.CreateCredential(CreateOptions(), Origin, []);

        Assert.Equal("example.com", passkey.RpId);
        Assert.Equal("alice@example.com", passkey.UserName);
        Assert.Equal("dXNlci0x", passkey.UserHandle);
        Assert.Equal(passkey.CredentialId, response["id"]!.GetValue<string>());
        Assert.Equal("public-key", response["type"]!.GetValue<string>());

        var inner = response["response"]!;
        string clientData = Encoding.UTF8.GetString(B64Url.Decode(inner["clientDataJSON"]!.GetValue<string>()));
        Assert.Equal("{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdlLTE\",\"origin\":\"https://login.example.com\",\"crossOrigin\":false}", clientData);

        // Attestation object: { fmt: "none", attStmt: {}, authData }
        var reader = new CborReader(B64Url.Decode(inner["attestationObject"]!.GetValue<string>()), CborConformanceMode.Ctap2Canonical);
        Assert.Equal(3, reader.ReadStartMap());
        Assert.Equal("fmt", reader.ReadTextString());
        Assert.Equal("none", reader.ReadTextString());
        Assert.Equal("attStmt", reader.ReadTextString());
        Assert.Equal(0, reader.ReadStartMap());
        reader.ReadEndMap();
        Assert.Equal("authData", reader.ReadTextString());
        byte[] authData = reader.ReadByteString();
        reader.ReadEndMap();
        Assert.Equal(authData, B64Url.Decode(inner["authenticatorData"]!.GetValue<string>()));

        // Authenticator data layout.
        Assert.Equal(SHA256.HashData("example.com"u8), authData[..32]);
        Assert.Equal(0x5D, authData[32]); // UP | UV | BE | BS | AT
        Assert.Equal(new byte[4], authData[33..37]);
        Assert.Equal(WebAuthn.Aaguid.ToByteArray(bigEndian: true), authData[37..53]);
        int idLength = (authData[53] << 8) | authData[54];
        Assert.Equal(B64Url.Decode(passkey.CredentialId), authData[55..(55 + idLength)]);

        // COSE public key.
        var cose = new CborReader(authData.AsMemory(55 + idLength), CborConformanceMode.Ctap2Canonical);
        Assert.Equal(5, cose.ReadStartMap());
        Assert.Equal((1, 2), (cose.ReadInt32(), cose.ReadInt32()));
        Assert.Equal((3, -7), (cose.ReadInt32(), cose.ReadInt32()));
        Assert.Equal((-1, 1), (cose.ReadInt32(), cose.ReadInt32()));
        Assert.Equal(-2, cose.ReadInt32());
        byte[] x = cose.ReadByteString();
        Assert.Equal(-3, cose.ReadInt32());
        byte[] y = cose.ReadByteString();
        cose.ReadEndMap();
        Assert.Equal(0, cose.BytesRemaining);

        using var publicKey = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
        using var spki = ECDsa.Create();
        spki.ImportSubjectPublicKeyInfo(B64Url.Decode(inner["publicKey"]!.GetValue<string>()), out _);
        Assert.Equal(x, spki.ExportParameters(false).Q.X);

        // Sign in with the new passkey and verify the signature like a server would.
        var getOptions = Json("""{ "rpId": "example.com", "challenge": "bG9naW4tY2hhbGxlbmdl", "allowCredentials": [] }""");
        var candidate = Assert.Single(WebAuthn.FindCandidates(getOptions, Origin, [passkey]));
        var assertion = WebAuthn.GetAssertion(getOptions, Origin, candidate)["response"]!;

        byte[] assertionAuthData = B64Url.Decode(assertion["authenticatorData"]!.GetValue<string>());
        byte[] assertionClientData = B64Url.Decode(assertion["clientDataJSON"]!.GetValue<string>());
        Assert.Equal(37, assertionAuthData.Length);
        Assert.Equal(0x1D, assertionAuthData[32]); // UP | UV | BE | BS
        Assert.Contains("\"type\":\"webauthn.get\"", Encoding.UTF8.GetString(assertionClientData));
        Assert.Contains("\"challenge\":\"bG9naW4tY2hhbGxlbmdl\"", Encoding.UTF8.GetString(assertionClientData));
        Assert.Equal("dXNlci0x", assertion["userHandle"]!.GetValue<string>());

        byte[] signed = [.. assertionAuthData, .. SHA256.HashData(assertionClientData)];
        byte[] signature = B64Url.Decode(assertion["signature"]!.GetValue<string>());
        Assert.True(publicKey.VerifyData(signed, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void Website_without_es256_is_not_supported()
    {
        var options = Json("""{ "rp": {"id":"example.com"}, "user": {"id":"dQ"}, "challenge": "Yw", "pubKeyCredParams": [ {"type":"public-key","alg":-257} ] }""");
        Assert.Equal("NotSupportedError", Assert.Throws<WebAuthnException>(() => WebAuthn.CreateCredential(options, Origin, [])).Name);
    }

    [Fact]
    public void Excluded_credential_prevents_a_duplicate()
    {
        var (_, passkey) = WebAuthn.CreateCredential(CreateOptions(), Origin, []);
        var options = CreateOptions($$""", "excludeCredentials": [ { "type": "public-key", "id": "{{passkey.CredentialId}}" } ]""");
        Assert.Equal("InvalidStateError", Assert.Throws<WebAuthnException>(() => WebAuthn.CreateCredential(options, Origin, [passkey])).Name);
    }

    [Theory]
    [InlineData("https://login.example.com", "example.com", true)]
    [InlineData("https://example.com", "example.com", true)]
    [InlineData("https://example.com", null, true)]
    [InlineData("http://localhost:3000", "localhost", true)]
    [InlineData("https://evil-example.com", "example.com", false)]
    [InlineData("https://example.com.evil.net", "example.com", false)]
    [InlineData("https://example.com", "login.example.com", false)]
    [InlineData("http://example.com", "example.com", false)]
    [InlineData("https://example.com", "com", false)]
    [InlineData("not a url", "example.com", false)]
    public void Relying_party_id_must_match_the_origin(string origin, string? rpId, bool allowed)
    {
        if (allowed) Assert.Equal(rpId ?? new Uri(origin).Host, WebAuthn.ResolveRpId(rpId, origin));
        else Assert.Equal("SecurityError", Assert.Throws<WebAuthnException>(() => WebAuthn.ResolveRpId(rpId, origin)).Name);
    }

    [Fact]
    public void Candidates_are_filtered_by_site_and_allow_list()
    {
        var (_, a) = WebAuthn.CreateCredential(CreateOptions(), Origin, []);
        var (_, b) = WebAuthn.CreateCredential(CreateOptions(), Origin, []);
        var other = new PasskeyData { RpId = "other.org", CredentialId = a.CredentialId };
        PasskeyData[] all = [a, b, other];

        Assert.Equal(2, WebAuthn.FindCandidates(Json("""{ "rpId": "example.com", "challenge": "Yw" }"""), Origin, all).Count);
        var allowOnlyB = Json($$"""{ "rpId": "example.com", "challenge": "Yw", "allowCredentials": [ { "type": "public-key", "id": "{{b.CredentialId}}" } ] }""");
        Assert.Same(b, Assert.Single(WebAuthn.FindCandidates(allowOnlyB, Origin, all)));

        // A phishing site cannot get an assertion for another site's passkey.
        Assert.Throws<WebAuthnException>(() => WebAuthn.FindCandidates(allowOnlyB, "https://examp1e.com", all));
        Assert.Throws<WebAuthnException>(() => WebAuthn.GetAssertion(Json("""{ "challenge": "Yw" }"""), "https://other.org", a));
    }
}

public class QrDecoderTests
{
    private const string Uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    [Fact]
    public void Decodes_a_qr_code()
    {
        Assert.Equal(Uri, Assert.Single(QrDecoder.Decode(QrDecoder.Encode(Uri, 300), 300, 300)));
    }

    [Fact]
    public void Finds_a_small_qr_code_on_a_large_screenshot()
    {
        const int width = 2560, height = 1440, size = 220;
        byte[] screen = new byte[width * height * 4];
        var random = new Random(7);
        for (int i = 0; i < screen.Length; i += 4)
        {
            // A dark, slightly noisy desktop background.
            byte shade = (byte)(30 + random.Next(20));
            screen[i] = screen[i + 1] = screen[i + 2] = shade;
            screen[i + 3] = 255;
        }
        byte[] qr = QrDecoder.Encode(Uri, size);
        for (int row = 0; row < size; row++)
            Buffer.BlockCopy(qr, row * size * 4, screen, ((900 + row) * width + 1700) * 4, size * 4);

        Assert.Contains(Uri, QrDecoder.Decode(screen, width, height));
    }

    [Fact]
    public void Image_without_qr_code_yields_nothing()
    {
        Assert.Empty(QrDecoder.Decode(new byte[200 * 200 * 4], 200, 200));
    }
}
