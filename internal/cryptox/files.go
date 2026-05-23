package cryptox

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// hkdfInfoFileKeyWrap is the HKDF `info` string used to derive the
// AES wrapping key from a ML-KEM shared secret for file (and folder
// name) keys. Must match `WRAP_KEY_HKDF_INFO` in the web app's
// src/lib/crypto/sharing.ts byte-for-byte — a typo here is the
// quietest possible bug (decryption fails with a generic GCM auth
// error rather than a mismatch the user can diagnose).
const hkdfInfoFileKeyWrap = "sefaly-file-key-wrap-v1"

// Why CIRCL instead of crypto/mlkem stdlib for the user's privateKey:
//
// FIPS 203 standardizes two representations of a ML-KEM-768
// decapsulation key:
//
//   - The 64-byte SEED (d || z): the canonical storage format. Go's
//     stdlib `crypto/mlkem.NewDecapsulationKey768` is seed-only.
//   - The 2400-byte EXPANDED form (dkPKE || ek || H(ek) || z): the
//     in-memory representation the algorithm actually uses.
//
// You can derive the expanded form from the seed (it's a deterministic
// expansion through SHA3 / NTT operations), but you CANNOT recover
// the seed from the expanded form — d generates the secret vector s
// via a PRF, and inverting that is the security of the scheme.
//
// The web app uses @noble/post-quantum, which keygens from a seed
// internally but discards it and exposes ONLY the expanded form to
// callers (see src/lib/crypto/mlkem-adapter.ts). Every existing
// Sefaly account's stored privateKey is therefore the expanded form.
// We cannot reconstruct seeds for them; the seed was zeroed at
// signup.
//
// CIRCL's mlkem768.PrivateKey.Unpack accepts the expanded form
// directly. It's the only Go ML-KEM-768 implementation I've found
// that does. Cloudflare ships it in their production TLS stack so
// the maintenance posture is solid.
//
// Note we keep `crypto/mlkem` stdlib for the device-flow ephemeral
// keypair (deviceflow.go) — that's a per-login keypair we generate
// ourselves, so we have the seed and don't need CIRCL there.

// UnwrapFileKey recovers a 32-byte symmetric file (or folder-name) key
// from the server-returned wrap material. The same flow handles both:
//
//   - File row: encapsulatedKey + encryptedFileKey + keyWrapNonce
//     (the latter from `encryptionMetadata.keyWrapNonce`, falling
//     back to the file's content nonce on legacy v1.0 rows).
//   - Folder row: nameKeyEncapsulated + nameKeyWrapped +
//     nameKeyWrapNonce.
//
// `privateKeyBytes` is the user's ML-KEM-768 secret key in the
// 2400-byte FIPS 203 expanded form (as stored by the web app + as
// returned by cryptox.DecryptPrivateKey at login time).
func UnwrapFileKey(
	privateKeyBytes []byte,
	encapsulatedKeyB64, wrappedKeyB64, keyWrapNonceB64 string,
) ([]byte, error) {
	if len(privateKeyBytes) != mlkem768.PrivateKeySize {
		return nil, fmt.Errorf(
			"privateKey must be %d bytes (FIPS 203 expanded form), got %d",
			mlkem768.PrivateKeySize, len(privateKeyBytes),
		)
	}
	var sk mlkem768.PrivateKey
	if err := sk.Unpack(privateKeyBytes); err != nil {
		return nil, fmt.Errorf("loading private key: %w", err)
	}

	encapsulatedKey, err := base64.StdEncoding.DecodeString(encapsulatedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decoding encapsulatedKey: %w", err)
	}
	if len(encapsulatedKey) != mlkem768.CiphertextSize {
		return nil, fmt.Errorf(
			"encapsulatedKey must be %d bytes, got %d",
			mlkem768.CiphertextSize, len(encapsulatedKey),
		)
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(wrappedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decoding wrappedKey: %w", err)
	}
	keyWrapNonce, err := base64.StdEncoding.DecodeString(keyWrapNonceB64)
	if err != nil {
		return nil, fmt.Errorf("decoding keyWrapNonce: %w", err)
	}
	if len(keyWrapNonce) != aesGCMNonceLen {
		return nil, fmt.Errorf("keyWrapNonce must be %d bytes (got %d)", aesGCMNonceLen, len(keyWrapNonce))
	}

	// CIRCL's DecapsulateTo writes into a caller-allocated buffer
	// and is non-failing by design — FIPS 203 specifies "implicit
	// rejection" where a malformed ciphertext yields a pseudorandom
	// shared secret rather than an error (constant-time guard
	// against Bleichenbacher-style attacks). A bad shared secret
	// surfaces downstream as an AES-GCM auth failure on the
	// wrapping-key open, which is exactly the behavior we want.
	sharedSecret := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(sharedSecret, encapsulatedKey)

	// HKDF salt is the encapsulatedKey itself (per the v1.1+ wire
	// format — see sharing.ts). v1.0 legacy files used a zero salt
	// + the file nonce as the wrap nonce; we don't handle them
	// here because they pre-date the rollout that produced any of
	// this user's data. If we ever need to read a v1.0 file from
	// a long-tenured account, this is where the branch would land.
	wrappingKey, err := hkdf.Key(sha256.New, sharedSecret, encapsulatedKey, hkdfInfoFileKeyWrap, 32)
	if err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}

	fileKey, err := aesGCMOpen(wrappingKey, keyWrapNonce, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrapping file key (AES-GCM auth failed — usually means the key material doesn't belong to this account): %w", err)
	}
	if len(fileKey) != 32 {
		return nil, fmt.Errorf("unwrapped file key must be 32 bytes (got %d)", len(fileKey))
	}
	return fileKey, nil
}

// DecryptName decrypts an AES-GCM-encrypted filename or folder name
// with the file/folder key. No AAD — the wire format encrypts names
// without one (different from the device-flow privateKey blob, which
// IS AAD-bound).
func DecryptName(key []byte, ciphertextB64, nonceB64 string) (string, error) {
	if len(key) != 32 {
		return "", errors.New("name key must be 32 bytes")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decoding ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("decoding nonce: %w", err)
	}
	if len(nonce) != aesGCMNonceLen {
		return "", fmt.Errorf("name nonce must be %d bytes (got %d)", aesGCMNonceLen, len(nonce))
	}
	plaintext, err := aesGCMOpen(key, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting name: %w", err)
	}
	return string(plaintext), nil
}
