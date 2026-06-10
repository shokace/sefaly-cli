# Changelog

All notable changes to `sef` (the Sefaly CLI) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions correspond to the git tag GoReleaser builds from (e.g. `v0.1.1`).

## [0.1.1] - 2026-06-11

A Claude-Code-style overhaul: a branded interactive experience, full
file-management + sharing parity with the web app, and the open security
findings folded in. Account settings stay on the web app by design.

### Added
- Interactive `sef shell` (cloud REPL) that keeps a current folder:
  `cd`, `ls`, `pwd`, `tree`, `info`, `get`, `put`, `mkdir`, `mv`, `cp`,
  `rm`, `share`, `trash`, `whoami`, `clear`, `help`, `exit`. Running
  `sef` with no arguments on a terminal opens it.
- Branded welcome banner with an ASCII Sefaly logo and a new `internal/ui`
  styling package.
- `sef cp` — server-side file copy (with optional rename).
- `sef info` — file/folder details (type, size, decrypted path,
  timestamps, encryption parameters, id).
- `sef trash` — list Trash, plus `restore`, `rm`, and `empty` subcommands.
- `sef share` — public links (with `--expires`, `--max-downloads`,
  `--slug`) and `--to <email>` end-to-end direct shares, plus
  `share ls` and `share revoke`.
- First test suite: crypto round-trips (file encrypt/decrypt, recipient
  wrap, public-link payload, version-downgrade rejection) and the shell's
  path-translation + tokenizer logic.

### Changed
- Bare `sef` on a terminal now opens the interactive shell; when piped or
  run in CI it prints a command summary instead.
- `sef whoami` shows tier, storage used, 2FA status, and email-verified
  state in a styled block.
- `sef rm` sends files to Trash (30-day retention, restore via
  `sef trash`); folder deletion remains permanent.
- Built on Go 1.26.4.

### Removed
- The two-pane Bubble Tea TUI (`sef gui`), superseded by `sef shell`.

### Security
- Login refuses to print or auto-open a device-verification URL that is
  not `https` on the same host as the API base, blocking phishing and
  non-http scheme abuse from a compromised server.
- JSON responses and downloads are size-capped, server-provided storage
  URLs must be `https` (loopback `http` allowed for dev), and the
  download/upload clients refuse `https`→`http` redirects.
- Decrypted files are written `0600` instead of `0644`.
- The Go 1.26.4 toolchain clears the `crypto/x509` (GO-2026-5037) and
  `net/textproto` (GO-2026-5039) standard-library advisories;
  `govulncheck` reports no findings.

### Deferred (use the web app for now)
- Folder sharing, consuming shares others sent you, synced folders, and
  all account settings (billing, storage plan, account deletion, 2FA
  setup). The CLI never mutates account state.

## [0.1.0] - 2026-05-31

Initial release.

### Added
- Device-flow `login` / `logout` / `whoami` (zero-knowledge: the server
  never sees the raw token or the plaintext private key).
- File operations: `ls`, `upload`, `download`, `rm`, `mkdir`, `mv`.
- End-to-end crypto mirroring the web app (ML-KEM-768 key wrap +
  AES-256-GCM content + HKDF), with client-side encrypted filenames.
- OS-keychain credential storage with a `chmod 600` fallback file.
- A two-pane file-manager TUI (`sef gui`).
- GoReleaser cross-platform release pipeline.

[0.1.1]: https://github.com/shokace/sefaly-cli/releases/tag/v0.1.1
[0.1.0]: https://github.com/shokace/sefaly-cli/releases/tag/v0.1.0
