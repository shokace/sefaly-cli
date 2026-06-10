# sef — Sefaly CLI

Command-line client for [Sefaly](https://www.sefaly.com), an
end-to-end-encrypted cloud storage service that uses post-quantum
cryptography (ML-KEM-768) for key wrapping. Files are encrypted in
your shell before they leave the machine; the server never has the
keys to decrypt them.

The invocable command is **`sef`** — short single-syllable name in
the tradition of `gh`, `fly`, `aws`. The project is still called
Sefaly everywhere else (repo, brand, docs); only the typed command
is shortened.

> **Status:** v0.x. Full file management + sharing + an interactive
> shell. Account settings (billing, storage plan, account deletion,
> 2FA setup) live on the web app by design — the CLI never mutates
> account state. Folder sharing and consuming shares others sent you
> are on the web app for now.

## Install

### One-liner (Linux + macOS)

```sh
curl -fsSL https://www.sefaly.com/install.sh | sh
```

The script detects your OS + arch, grabs the matching release from
GitHub, verifies its SHA-256, and drops the `sef` binary in
`~/.local/bin/`. Add that directory to your `PATH` if it isn't
already.

### Manual download

Grab the tarball for your platform from the
[Releases page](https://github.com/shokace/sefaly-cli/releases/latest)
and extract `sef` somewhere on your `PATH`. SHA-256 checksums for
every artifact are in `sha256sums.txt` on the same release.

### Build from source

```sh
git clone https://github.com/shokace/sefaly-cli
cd sefaly-cli
go build -o sef .
mv sef /usr/local/bin/
sef --help
```

Requires Go 1.26.4+ (we use the standard library's `crypto/mlkem` and
`crypto/hkdf`; 1.26.4 also carries the latest stdlib security fixes).

### Windows

Download `sef_<version>_windows_amd64.zip` from the Releases page,
extract `sef.exe`, and add the containing folder to your `PATH`. The
one-liner above doesn't support Windows yet (planned for a future
release; native Scoop / winget installers are easier than a PowerShell
script).

## Quick start

```sh
sef login
# → opens https://www.sefaly.com/cli-auth?user_code=… in your browser
# → approve the request → CLI is now signed in

sef whoami
# → you@example.com (signed in as <device-name>)

sef ls
# → list files + folders in your account root

sef logout
# → clears local credentials
```

Run `sef` with no arguments on a terminal to drop into the interactive
shell (see below); pipe it or redirect it and you get a plain command
summary instead.

## Commands

| Command | What it does |
| --- | --- |
| `sef login` / `logout` / `whoami` | Authorize this device, sign out, show the account + storage |
| `sef ls [path]` | List a folder (`--long` for size/time, `--tree` recursive) |
| `sef put <file>… [--to <folder>]` | Encrypt + upload files (alias `upload`) |
| `sef get <path> [-o <dest>]` | Download + decrypt a file (alias `download`) |
| `sef mkdir <path> [-p]` | Create a folder |
| `sef mv <src> <dst>` | Move or rename (end-to-end re-encrypts the name) |
| `sef cp <src> <dst>` | Server-side copy a file (+ rename) |
| `sef rm <path>… [-r] [-f]` | Delete (files → Trash, folders permanent) |
| `sef info <path>` | File/folder details (size, path, encryption, id) |
| `sef trash` | List Trash; `restore` / `rm` / `empty` subcommands |
| `sef share <file>` | Create a public link or `--to <email>` direct share |
| `sef shell` | Interactive cloud session |

Paths are slash-separated and mirror your folder hierarchy; filenames
are decrypted locally for display, never sent in plaintext.

## Interactive shell

`sef shell` (or bare `sef` on a terminal) opens a Claude-Code-style
session that keeps a current folder, so you can move around your cloud
like a remote filesystem:

```text
sefaly / ❯ cd Photos/2026
sefaly /Photos/2026 ❯ ls
sefaly /Photos/2026 ❯ get IMG_1234.jpg ~/Desktop
sefaly /Photos/2026 ❯ put ~/new-shot.jpg
sefaly /Photos/2026 ❯ share IMG_1234.jpg
sefaly /Photos/2026 ❯ exit
```

Supported in-session: `cd`, `ls`, `pwd`, `tree`, `info`, `get`, `put`,
`mkdir`, `mv`, `cp`, `rm`, `share`, `trash`, `whoami`, `clear`, `help`,
`exit`. For flags (e.g. `share --to`, `--expires`), use the non-shell
commands.

## Sharing

```sh
sef share report.pdf                       # public link (key lives in the URL #fragment)
sef share report.pdf --expires 7 --max-downloads 5
sef share report.pdf --slug q3-report      # custom slug (Pro)
sef share report.pdf --to alex@example.com # end-to-end direct share to a Sefaly user
sef share ls                               # list your outgoing shares
sef share revoke <link-id>                 # revoke a public link
```

Public links generate a fresh 256-bit key, encrypt the file key under
it, and store only the ciphertext — the key rides in the URL fragment
(after `#`), which browsers never send to the server, so Sefaly can't
read your shared file. Direct shares re-wrap the file key to the
recipient's ML-KEM-768 public key.

## How the auth works (in short)

Sefaly is zero-knowledge: your password and your private key never
reach the server. The CLI inherits that property via a device-flow
ceremony:

1. `sef login` generates an ephemeral ML-KEM-768 keypair and sends
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
sef --api https://staging.sefaly.com login
# or
SEFALY_API_URL=https://staging.sefaly.com sef login
```

## Security

Found a vulnerability? See [`SECURITY.md`](SECURITY.md) for the
disclosure policy. Please don't file a public issue for security
matters.

## License

MIT — see [`LICENSE`](LICENSE).
