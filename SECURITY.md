# Security

Krypta is an early version and has **not** had an independent security audit.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
**Security → Report a vulnerability** on this repository so it can be fixed before it is public.

## Design

**Vault file** (`*.krypta`): `magic | header length | header JSON | nonce | tag | ciphertext`.

- Key: `Argon2id(master password, salt; 64 MiB, 3 passes, 4 lanes)`, then
  `HKDF-SHA256(argon output ‖ device secret, salt, "Krypta vault key v1")`.
- Encryption: AES-256-GCM with a fresh random 96-bit nonce on every save. The header
  (parameters, salt, device binding) is authenticated as associated data.
- Saves are written to a temporary file and swapped in; the previous file is kept as `.bak`.

**Device binding** (optional): a random 32-byte device secret is mixed into the key. It is stored
wrapped with a non-exportable RSA-2048 key in the TPM. The recovery key is that secret in Base32.
Without the TPM of this device or the recovery key, the master password alone does not open the file.

**Passkeys**: ES256 (P-256) keys, stored inside the encrypted vault. Krypta checks that the relying
party id belongs to the requesting origin, builds the client data itself (the origin comes from
the browser, not from the page) and requires a confirmation click for every request. The bridge to
the browser is a named pipe restricted to the current Windows user; nothing listens on the network.
Note: the relying-party check is a suffix match and does not use the public suffix list.

**Hardening against other local programs**

- The process access list denies memory reads, writes, thread creation and handle duplication to
  other processes of the same user. (The owner of a process can still rewrite that list; malware
  that knows this, or runs elevated, is not stopped.)
- Windows are excluded from screen capture (`WDA_EXCLUDEFROMCAPTURE`).
- Clipboard data carries the formats that keep it out of clipboard history and cloud sync, and is
  cleared after a timeout if it is still Krypta's.
- The vault key is zeroed when the vault locks. Decrypted entries are ordinary .NET objects while
  the vault is unlocked, so they can remain in memory until the garbage collector reuses it.

**Key file** (optional): the SHA-256 hash of the key file is mixed into the key as well. The file
is created by Krypta (64 random bytes) and written before the vault is.

**Key in memory**: the vault key, device secret and key file hash are held encrypted with
`CryptProtectMemory` and decrypted into a short-lived copy only for the moment they are used.

**Filling logins in the browser**: the extension's popup can list the names of logins saved for
the open website and ask for one to be filled in. Krypta only answers for an entry whose website
is the page's host or a parent domain of it, and shows a confirmation window before any password
leaves the app. The list of names is given without confirmation while the vault is unlocked.

**Typing a password** ("Type it in") sends key strokes to the window that had the focus before.
It avoids the clipboard but, like any typing, can be captured by a keylogger.

**Network**: the leak check (on request, or weekly when the monitor is on) and, when turned on,
website icons, which are requested from `https://<website>/favicon.ico` and decoded by Windows.

- Password check: `GET https://api.pwnedpasswords.com/range/{first 5 hex chars of SHA-1}` with padding.
- E-mail check: `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}` with the user's API key.

## Not protected against

- Malware with administrator or kernel access, and keyloggers or screen readers that are active
  while the vault is unlocked.
- Weak master passwords.
- Loss of the master password, or of both the device and the recovery key.
