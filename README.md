# sefaly

Command-line client for [Sefaly](https://www.sefaly.com), an
end-to-end-encrypted cloud storage service that uses post-quantum
cryptography (ML-KEM-768) for key wrapping. Files are encrypted in
your shell before they leave the machine; the server never has the
keys to decrypt them.

> **Status:** early v0.x. `login`, `logout`, and `whoami` work today.
> `upload`, `ls`, `download` are next.

## Install

> Packaged installers are coming. For now: build from source.

```sh
git clone https://github.com/shokace/sefaly-cli
cd sefaly-cli
go build -o sefaly .
./sefaly --help
```

Requires Go 1.24+ (we use the standard library's `crypto/mlkem` and
`crypto/hkdf`).

## Quick start

```sh
sefaly login
# → opens https://www.sefaly.com/cli-auth?user_code=… in your browser
# → approve the request → CLI is now signed in

sefaly whoami
# → you@example.com (signed in as <device-name>)

sefaly logout
# → clears local credentials
```

## How the auth works (in short)

Sefaly is zero-knowledge: your password and your private key never
reach the server. The CLI inherits that property via a device-flow
ceremony:

1. `sefaly login` generates an ephemeral ML-KEM-768 keypair and sends
   only the public half to the server, alongside a request for a
   pending device code.
2. The browser, after you click Allow, generates a random access
   token, ML-KEM-encapsulates it against the CLI's ephemeral public
   key, and re-encrypts your private key under a HKDF-derived key.
   The server holds the wrapped material but never the raw access
   token or the plaintext private key.
3. The CLI polls, picks up the wrap material, decapsulates with its
   ephemeral private key, recovers the raw access token, and decrypts
   the private key locally. Both go into your OS keychain.

After that, every CLI command authenticates with
`Authorization: Bearer <token>` — same endpoints the web app uses.

The full crypto spec lives in [`docs/CRYPTO_SPEC.md`](docs/CRYPTO_SPEC.md)
once it's written (coming soon).

## Credential storage

The CLI stores its credentials in your OS's native keychain:

- **macOS:** Keychain (via the `security` Keychain Services API)
- **Linux:** Secret Service / GNOME Keyring / KWallet (via D-Bus)
- **Windows:** Credential Manager

If no keychain backend is available (e.g. a headless Linux server
with no D-Bus), the CLI falls back to `~/.sefaly/credentials.json`
with `chmod 600` and prints a warning.

You can revoke the CLI's access at any time from the "Connected
devices" panel in your dashboard, even if you've lost the machine.

## Configuration

By default the CLI talks to `https://www.sefaly.com`. Override with:

```sh
sefaly --api https://staging.sefaly.com login
# or
SEFALY_API_URL=https://staging.sefaly.com sefaly login
```

## Security

Found a vulnerability? See [`SECURITY.md`](SECURITY.md) for the
disclosure policy. Please don't file a public issue for security
matters.

## License

MIT — see [`LICENSE`](LICENSE).
