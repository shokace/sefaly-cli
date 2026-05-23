// Package creds persists the CLI's authentication state across
// invocations.
//
// What's stored:
//
//   - APIBaseURL — which Sefaly host this set of creds belongs to.
//     Lets `--api` switch between prod / staging / a local dev server
//     without clobbering each other's creds.
//   - AccessToken — the raw Bearer token. Authenticates every
//     subsequent API call.
//   - UserID, Email — identity metadata so `whoami` doesn't need a
//     network round-trip.
//   - EncryptedPrivateKey — JSON blob `{ciphertext,nonce,kemType}`.
//     We do NOT store the decrypted private key; commands that need
//     it run cryptox.DecryptPrivateKey(AccessToken, UserID,
//     EncryptedPrivateKey) on demand. Keeps the plaintext key off
//     disk; it only ever lives in process memory.
//
// Where it's stored:
//
//   - First choice: OS keychain (Keychain on macOS, Secret Service /
//     GNOME Keyring / KWallet on Linux, Credential Manager on
//     Windows) via 99designs/keyring, which calls the native APIs
//     directly. Encrypted at rest, unlocked by the user's OS login.
//
//     (We previously used zalando/go-keyring, but its hard-coded
//     2 KB cap on macOS values rejected our 3.5 KB credential blob —
//     the encryptedPrivateKey ciphertext is the bulk of the size.
//     99designs's CGo-backed Security.framework calls accept the
//     real Apple limit, which is much higher.)
//
//   - Fallback: ~/.sefaly/credentials.json with chmod 600, used when
//     no OS keychain backend is available (headless Linux servers,
//     CI runners). The CLI prints a warning the first time this path
//     triggers so the user knows their creds are on the filesystem
//     instead of in the keychain.
package creds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/99designs/keyring"
)

// keychainEntry is the namespace + key under which we register the
// credentials blob. `keychainKey` is `default` for now; a future
// multi-account version could iterate other keys (e.g. one per
// profile name).
const (
	keychainService = "sefaly-cli"
	keychainKey     = "default"
	keychainLabel   = "Sefaly CLI credentials"
)

// Credentials is the full set of state the CLI needs to operate.
// JSON-serialised into the keychain (single value) or the fallback
// file.
type Credentials struct {
	APIBaseURL          string `json:"apiBaseUrl"`
	AccessToken         string `json:"accessToken"`
	UserID              string `json:"userId"`
	Email               string `json:"email"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	KemType             string `json:"kemType"`
	DeviceName          string `json:"deviceName,omitempty"`
}

// ErrNotFound is returned when no credentials exist (e.g. user hasn't
// run `sefaly login` yet). Callers can match it with errors.Is to
// emit a friendly "you're not signed in" message.
var ErrNotFound = errors.New("no Sefaly credentials found")

// openKeyring opens the OS-native keychain. We deliberately restrict
// AllowedBackends to native ones only — 99designs/keyring's
// FileBackend prompts for a passphrase per session, which would be a
// terrible UX for an unattended CLI. We have our own chmod-600
// fallback (writeFallbackFile below) for headless environments
// instead.
func openKeyring() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName: keychainService,
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,       // macOS
			keyring.SecretServiceBackend,  // Linux (GNOME Keyring)
			keyring.KWalletBackend,        // Linux (KDE)
			keyring.WinCredBackend,        // Windows
		},
		// macOS: let unsigned dev builds (and signed release builds)
		// access their own keychain items without prompting on every
		// read. The first WRITE may still pop the standard
		// "Always Allow / Allow Once / Deny" dialog — that's
		// expected and the user only sees it once per install.
		KeychainTrustApplication: true,
		// `login` keychain is the standard user-session one.
		KeychainName: "login",
	})
}

// Save writes the credentials, preferring the OS keychain. Returns
// `usedFallback=true` if the keychain wasn't available and we wrote
// the file instead; callers can surface a warning the first time
// that happens.
func Save(c *Credentials) (usedFallback bool, err error) {
	blob, err := json.Marshal(c)
	if err != nil {
		return false, fmt.Errorf("encoding credentials: %w", err)
	}

	if ring, err := openKeyring(); err == nil {
		setErr := ring.Set(keyring.Item{
			Key:         keychainKey,
			Data:        blob,
			Label:       keychainLabel,
			Description: "Stored by the sefaly CLI; remove via `sef logout`.",
		})
		if setErr == nil {
			// Belt-and-suspenders: if a stale fallback file exists
			// from a previous keychain-less run, get rid of it so
			// the two stores don't drift.
			_ = removeFallbackFile()
			return false, nil
		}
		// Fall through to the file fallback on Set error (e.g. the
		// user clicked Deny on the macOS keychain prompt).
	}

	if err := writeFallbackFile(blob); err != nil {
		return true, fmt.Errorf("OS keychain unavailable AND fallback file write failed: %w", err)
	}
	return true, nil
}

// Load reads the credentials, trying the OS keychain first and then
// the fallback file. Returns ErrNotFound when neither holds anything.
//
// If creds come from the fallback file but the keychain IS available,
// we transparently re-Save() so future loads find them in the
// keychain instead. Migrates users who logged in under an older CLI
// build (e.g. one that hit zalando/go-keyring's 2 KB cap on macOS
// and fell through to the file) without making them run `sefaly login`
// a second time just to move the creds.
func Load() (*Credentials, error) {
	if ring, err := openKeyring(); err == nil {
		if item, err := ring.Get(keychainKey); err == nil && len(item.Data) > 0 {
			return decode(item.Data)
		}
	}

	blob, err := readFallbackFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading fallback credentials: %w", err)
	}
	if len(blob) == 0 {
		return nil, ErrNotFound
	}
	c, err := decode(blob)
	if err != nil {
		return nil, err
	}

	// Best-effort migration. Save() will write to the keychain if
	// the backend is available (and remove the fallback file as part
	// of that path), or no-op back to the file if it isn't. Either
	// way, the creds returned to the caller are valid.
	_, _ = Save(c)

	return c, nil
}

// Clear removes credentials from both the keychain and the fallback
// file. Idempotent — if nothing's stored, returns nil.
func Clear() error {
	if ring, err := openKeyring(); err == nil {
		// 99designs/keyring returns keyring.ErrKeyNotFound when
		// there's nothing to remove; treat that as success.
		if err := ring.Remove(keychainKey); err != nil &&
			!errors.Is(err, keyring.ErrKeyNotFound) {
			// Carry on to the fallback even on real errors — we'd
			// rather over-delete than leave creds in either store.
		}
	}
	if err := removeFallbackFile(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing fallback file: %w", err)
	}
	return nil
}

// --------- internal: fallback file ---------

func fallbackPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".sefaly", "credentials.json"), nil
}

func writeFallbackFile(blob []byte) error {
	path, err := fallbackPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating ~/.sefaly: %w", err)
	}
	// Write to a temp file in the same dir, then rename, so a crash
	// mid-write can't leave a half-written credentials.json that the
	// next `sefaly login` would refuse to parse.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("writing temp creds: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming temp creds: %w", err)
	}
	return nil
}

func readFallbackFile() ([]byte, error) {
	path, err := fallbackPath()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func removeFallbackFile() error {
	path, err := fallbackPath()
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func decode(blob []byte) (*Credentials, error) {
	var c Credentials
	if err := json.Unmarshal(blob, &c); err != nil {
		return nil, fmt.Errorf("parsing stored credentials: %w", err)
	}
	if c.AccessToken == "" {
		return nil, ErrNotFound
	}
	return &c, nil
}
