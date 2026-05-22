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
//     Windows). Encrypted at rest, unlocked by the user's OS login.
//   - Fallback: ~/.sefaly/credentials.json with chmod 600, used when
//     the keychain backend isn't available (headless Linux servers,
//     CI runners). The CLI prints a warning the first time this
//     path triggers so the user knows their creds are at-rest on the
//     filesystem instead of in the keychain.
package creds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

// keyringService is the namespace under which we register entries in
// the OS keychain. One entry per CLI install — the `account` field
// is reserved for future multi-account support (today: always
// "default").
const (
	keyringService = "sefaly-cli"
	keyringAccount = "default"
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

// Save writes the credentials, preferring the OS keychain. Returns
// `usedFallback=true` if the keychain wasn't available and we wrote
// the file instead; callers can surface a warning the first time
// that happens.
func Save(c *Credentials) (usedFallback bool, err error) {
	blob, err := json.Marshal(c)
	if err != nil {
		return false, fmt.Errorf("encoding credentials: %w", err)
	}

	// Try the OS keychain first.
	if err := keyring.Set(keyringService, keyringAccount, string(blob)); err == nil {
		// Belt-and-suspenders: if a stale fallback file exists from a
		// previous keychain-less run, get rid of it so the two
		// stores don't drift.
		_ = removeFallbackFile()
		return false, nil
	}

	// Fall back to a file. Best effort — if even this fails, the
	// user couldn't have signed in anyway.
	if err := writeFallbackFile(blob); err != nil {
		return true, fmt.Errorf("OS keychain unavailable AND fallback file write failed: %w", err)
	}
	return true, nil
}

// Load reads the credentials, trying the OS keychain first and then
// the fallback file. Returns ErrNotFound when neither holds anything.
func Load() (*Credentials, error) {
	if blob, err := keyring.Get(keyringService, keyringAccount); err == nil && blob != "" {
		return decode([]byte(blob))
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
	return decode(blob)
}

// Clear removes credentials from both the keychain and the fallback
// file. Idempotent — if nothing's stored, returns nil.
func Clear() error {
	// Ignore "not found" errors from either backend; the goal is
	// "no creds afterwards", which is satisfied either way.
	if err := keyring.Delete(keyringService, keyringAccount); err != nil &&
		!errors.Is(err, keyring.ErrNotFound) {
		// Carry on to the fallback even on real errors — we'd rather
		// over-delete than leave creds in either store.
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
