using Krypta.Core;

namespace Krypta.Tests;

public class VaultOpsTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 12, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Changing_a_password_keeps_the_old_one()
    {
        var entry = new Entry { Password = "first" };
        VaultOps.SetPassword(entry, "first", Now);
        Assert.Empty(entry.History);

        VaultOps.SetPassword(entry, "second", Now);
        VaultOps.SetPassword(entry, "third", Now.AddDays(1));
        Assert.Equal("third", entry.Password);
        Assert.Equal(["second", "first"], entry.History.Select(h => h.Password));
        Assert.Equal(Now.AddDays(1), entry.History[0].Replaced);

        for (int i = 0; i < 20; i++) VaultOps.SetPassword(entry, "p" + i, Now);
        Assert.Equal(VaultOps.MaxHistory, entry.History.Count);
        Assert.Equal("p18", entry.History[0].Password);

        var empty = new Entry();
        VaultOps.SetPassword(empty, "new", Now);
        Assert.Empty(empty.History);
    }

    [Fact]
    public void Trash_hides_restores_and_expires()
    {
        var keep = new Entry { Title = "keep" };
        var recent = new Entry { Title = "recent" };
        var old = new Entry { Title = "old" };
        var data = new VaultData { Entries = [keep, recent, old] };

        VaultOps.MoveToTrash(recent, Now.AddDays(-29));
        VaultOps.MoveToTrash(old, Now.AddDays(-31));
        Assert.Same(keep, Assert.Single(data.Active));

        Assert.Equal(1, VaultOps.PurgeTrash(data, Now));
        Assert.Equal([keep, recent], data.Entries);

        VaultOps.Restore(recent);
        Assert.Equal(2, data.Active.Count());
    }

    [Fact]
    public void Tags_are_parsed_and_counted()
    {
        Assert.Equal(["work", "bank", "private"], VaultOps.ParseTags(" work, #bank;private ,, Work"));
        var tags = VaultOps.Tags([new Entry { Tags = ["work", "bank"] }, new Entry { Tags = ["Work"] }, new Entry()]);
        Assert.Equal([("work", 2), ("bank", 1)], tags);
    }
}

public class CsvTests
{
    [Fact]
    public void Parses_quotes_commas_and_line_breaks()
    {
        var rows = Csv.Parse("﻿a,b,c\r\n\"x, y\",\"say \"\"hi\"\"\",\"line1\nline2\"\r\n\r\n,,\nlast");
        Assert.Equal(4, rows.Count);
        Assert.Equal(["a", "b", "c"], rows[0]);
        Assert.Equal(["x, y", "say \"hi\"", "line1\nline2"], rows[1]);
        Assert.Equal(["", "", ""], rows[2]);
        Assert.Equal(["last"], rows[3]);
    }

    [Fact]
    public void Written_csv_reads_back_unchanged()
    {
        string[][] rows = [["plain", "with,comma", "with \"quote\""], [" padded ", "multi\r\nline", ""]];
        var parsed = Csv.Parse(Csv.Write(rows));
        Assert.Equal(rows[0], parsed[0]);
        Assert.Equal(rows[1], parsed[1]);
    }
}

public class TransferTests
{
    [Fact]
    public void Imports_a_chrome_export()
    {
        var entries = Transfer.ImportCsv("name,url,username,password,note\nGitHub,https://github.com/login,alice,\"p,w\"\"1\",work\n,https://shop.example.org,bob,secret,\n", []);
        Assert.Equal(2, entries.Count);
        Assert.Equal(("GitHub", "https://github.com/login", "alice", "p,w\"1", "work"),
            (entries[0].Title, entries[0].Url, entries[0].Username, entries[0].Password, entries[0].Notes));
        Assert.Equal("shop.example.org", entries[1].Title);
    }

    [Fact]
    public void Imports_a_bitwarden_export_with_totp_folder_and_favorite()
    {
        const string csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
                           "Work/Dev,1,login,GitHub,,,0,https://github.com,alice,pw,otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n" +
                           ",,login,Mail,,,0,https://mail.example,bob,pw2,JBSWY3DPEHPK3PXP\n" +
                           ",,note,Door code,1234 then #,,0,,,,\n";
        var entries = Transfer.ImportCsv(csv, []);
        Assert.Equal(3, entries.Count);
        Assert.True(entries[0].Favorite);
        Assert.Equal(["Work", "Dev"], entries[0].Tags);
        Assert.Equal("GitHub", entries[0].Totp!.Issuer);
        Assert.Equal("JBSWY3DPEHPK3PXP", entries[1].Totp!.Secret);
        Assert.Equal(EntryKind.Note, entries[2].Kind);
        Assert.Equal("1234 then #", entries[2].Notes);
    }

    [Fact]
    public void Imports_keepass_and_keepassxc_columns()
    {
        var keepass = Transfer.ImportCsv("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"Bank\",\"carol\",\"pw\",\"https://bank.example\",\"pin in safe\"\n", []);
        Assert.Equal(("Bank", "carol", "pw", "https://bank.example", "pin in safe"),
            (keepass[0].Title, keepass[0].Username, keepass[0].Password, keepass[0].Url, keepass[0].Notes));

        var xc = Transfer.ImportCsv("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\"Root/Bank\",\"Bank\",\"carol\",\"pw\",\"https://bank.example\",\"\",\"\"\n", []);
        Assert.Equal(["Bank"], xc[0].Tags);
    }

    [Fact]
    public void Duplicates_are_skipped_and_wrong_files_rejected()
    {
        var existing = new Entry { Title = "GitHub", Username = "alice", Password = "pw", Url = "https://github.com" };
        const string csv = "name,url,username,password\nGitHub,https://github.com,alice,pw\nGitHub,https://github.com,alice,pw\nNew,https://new.example,x,y\nNew,https://new.example,x,y\n";
        Assert.Equal("New", Assert.Single(Transfer.ImportCsv(csv, [existing])).Title);

        Assert.Throws<FormatException>(() => Transfer.ImportCsv("", []));
        Assert.Throws<FormatException>(() => Transfer.ImportCsv("date,amount\n1,2\n", []));
    }

    [Fact]
    public void Export_can_be_imported_again()
    {
        var login = new Entry
        {
            Title = "Git, Hub", Username = "alice", Password = "p\"w\n2", Url = "https://github.com", Notes = "n", Favorite = true, Tags = ["work"],
            Totp = new TotpConfig { Secret = "JBSWY3DPEHPK3PXP", Digits = 8, Period = 60, Algorithm = "SHA256" },
        };
        var card = new Entry { Kind = EntryKind.Card, Title = "Visa", CardNumber = "4111" };
        string csv = Transfer.ExportCsv([login, card]);
        Assert.DoesNotContain("4111", csv);

        var back = Assert.Single(Transfer.ImportCsv(csv, []));
        Assert.Equal((login.Title, login.Username, login.Password, login.Url, login.Notes), (back.Title, back.Username, back.Password, back.Url, back.Notes));
        Assert.True(back.Favorite);
        Assert.Equal(["work"], back.Tags);
        Assert.Equal(("JBSWY3DPEHPK3PXP", 8, 60, "SHA256"), (back.Totp!.Secret, back.Totp.Digits, back.Totp.Period, back.Totp.Algorithm));
    }

    [Fact]
    public void Wifi_qr_text_escapes_special_characters()
    {
        Assert.Equal("WIFI:T:WPA;S:Cafe\\;Net;P:pa\\:ss\\\\1;;", Transfer.WifiQrText(new Entry { Title = "Cafe;Net", Password = "pa:ss\\1" }));
        Assert.Equal("WIFI:T:nopass;S:Open;;", Transfer.WifiQrText(new Entry { Title = "Open" }));
    }
}

public class DeviceBindingChangeTests : IDisposable
{
    private readonly string _dir = System.IO.Directory.CreateTempSubdirectory("krypta-test-").FullName;
    private string VaultPath => System.IO.Path.Combine(_dir, "vault.krypta");

    public void Dispose() => System.IO.Directory.Delete(_dir, recursive: true);

    private sealed class XorDeviceKey : IDeviceKeyProvider
    {
        private readonly byte _mask = (byte)Random.Shared.Next(1, 255);
        public bool IsAvailable => true;
        public DeviceBindingInfo Wrap(ReadOnlySpan<byte> secret) =>
            new() { Provider = "xor", WrappedSecret = Convert.ToBase64String(secret.ToArray().Select(b => (byte)(b ^ _mask)).ToArray()) };
        public byte[] Unwrap(DeviceBindingInfo info) => Convert.FromBase64String(info.WrappedSecret).Select(b => (byte)(b ^ _mask)).ToArray();
        public void Delete(DeviceBindingInfo info) { }
    }

    [Fact]
    public void Key_file_is_a_required_second_factor()
    {
        var kdf = new KdfParams { MemoryKiB = 8 * 1024, Iterations = 1, Parallelism = 1 };
        byte[] keyFile = Vault.NewKeyFile();
        using (var vault = Vault.Create(VaultPath, "master", out _, kdf: kdf, keyFile: keyFile))
        {
            Assert.True(vault.UsesKeyFile);
            vault.Data.Entries.Add(new Entry { Title = "kept" });
            vault.ChangePassword("master2");
        }

        Assert.Throws<KeyFileRequiredException>(() => Vault.Open(VaultPath, "master2"));
        Assert.Throws<WrongPasswordException>(() => Vault.Open(VaultPath, "master2", keyFile: Vault.NewKeyFile()));
        Assert.Throws<VaultException>(() => Vault.Open(VaultPath, "master2", keyFile: [1, 2, 3]));

        using (var vault = Vault.Open(VaultPath, "master2", keyFile: keyFile))
        {
            Assert.Equal("kept", Assert.Single(vault.Data.Entries).Title);
            Assert.Throws<WrongPasswordException>(() => vault.SetKeyFile("wrong", null));
            vault.SetKeyFile("master2", null);
        }
        using (var plain = Vault.Open(VaultPath, "master2"))
        {
            Assert.False(plain.UsesKeyFile);
            plain.SetKeyFile("master2", keyFile);
        }
        Assert.Throws<KeyFileRequiredException>(() => Vault.Open(VaultPath, "master2"));
        Vault.Open(VaultPath, "master2", keyFile: keyFile).Dispose();
    }

    [Fact]
    public void Binding_can_be_added_and_removed_later()
    {
        var kdf = new KdfParams { MemoryKiB = 8 * 1024, Iterations = 1, Parallelism = 1 };
        var device = new XorDeviceKey();
        string? recovery;
        using (var vault = Vault.Create(VaultPath, "master", out _, kdf: kdf))
        {
            vault.Data.Entries.Add(new Entry { Title = "kept" });
            Assert.Null(vault.RecoveryKey);
            Assert.Throws<WrongPasswordException>(() => vault.SetDeviceBinding("wrong", device));
            Assert.False(vault.IsDeviceBound);

            recovery = vault.SetDeviceBinding("master", device);
            Assert.True(vault.IsDeviceBound);
            Assert.Equal(recovery, vault.RecoveryKey);
        }

        // Now the file needs the device (or the recovery key).
        Assert.Throws<DeviceKeyUnavailableException>(() => Vault.Open(VaultPath, "master"));
        Vault.Open(VaultPath, "master", recoveryKey: recovery).Dispose();

        using (var vault = Vault.Open(VaultPath, "master", device))
        {
            Assert.Equal("kept", Assert.Single(vault.Data.Entries).Title);
            Assert.Null(vault.SetDeviceBinding("master", null));
        }
        using var plain = Vault.Open(VaultPath, "master");
        Assert.False(plain.IsDeviceBound);
        Assert.Equal("kept", Assert.Single(plain.Data.Entries).Title);
    }
}
