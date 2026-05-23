package cryptox

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

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

// DecryptFileContent recovers a file's plaintext from its ciphertext +
// the unwrapped fileKey. Mirrors the browser's
// decryptFileAfterDownload (browser-crypto.ts):
//
//   - v1.0 / v1.1: no AAD on the AES-GCM open.
//   - v1.2: AAD = "sefaly-file-aad|v=<ver>|alg=AES-256-GCM|kem=ML-KEM-768"
//     so a server that swaps any of those three fields between
//     encrypt and decrypt fails GCM auth instead of silently
//     decrypting under the wrong parameters.
//
// Unknown / missing versions are rejected outright — same defensive
// posture as the browser (it explicitly fails on missing version to
// stop a malicious server forcing a downgrade to a weaker code path).
func DecryptFileContent(
	fileKey []byte,
	nonceB64 string,
	version string,
	ciphertext []byte,
) ([]byte, error) {
	if len(fileKey) != 32 {
		return nil, errors.New("file key must be 32 bytes")
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}
	if len(nonce) != aesGCMNonceLen {
		return nil, fmt.Errorf("file nonce must be %d bytes (got %d)", aesGCMNonceLen, len(nonce))
	}

	var aad []byte
	switch version {
	case "1.0", "1.1":
		aad = nil // no AAD before v1.2
	case "1.2":
		aad = buildFileAAD(version, "AES-256-GCM", "ML-KEM-768")
	case "":
		return nil, errors.New("missing encryption version on file row — refusing to decrypt without it")
	default:
		return nil, fmt.Errorf("unsupported encryption version: %q", version)
	}

	plaintext, err := aesGCMOpen(fileKey, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM open failed (version=%s) — usually a wrong key or tampered ciphertext: %w", version, err)
	}
	return plaintext, nil
}

// buildFileAAD must produce the EXACT byte sequence the browser
// produces in src/lib/crypto/browser-crypto.ts. Any drift here
// silently breaks decryption for every v1.2 file the user owns.
func buildFileAAD(version, algorithm, kemType string) []byte {
	return []byte(fmt.Sprintf("sefaly-file-aad|v=%s|alg=%s|kem=%s", version, algorithm, kemType))
}

// PublicKeyFromPrivate slices the encapsulation key (`ek`) out of
// the FIPS 203 expanded decapsulation key. Saves a /api/auth/me
// round-trip whenever we already have the user's private key in
// memory — the public key is literally a substring of the private
// key in the standardized layout:
//
//   dk = dkPKE (1152) || ek (1184) || H(ek) (32) || z (32) = 2400 bytes
//
// For ML-KEM-768 the ek slice is bytes [1152, 2336).
func PublicKeyFromPrivate(privKeyBytes []byte) ([]byte, error) {
	if len(privKeyBytes) != mlkem768.PrivateKeySize {
		return nil, fmt.Errorf(
			"private key must be %d bytes, got %d",
			mlkem768.PrivateKeySize, len(privKeyBytes),
		)
	}
	// Copy out so the caller can zero the private-key buffer without
	// also wiping the public key.
	pk := make([]byte, mlkem768.PublicKeySize)
	copy(pk, privKeyBytes[1152:1152+mlkem768.PublicKeySize])
	return pk, nil
}

// UploadCrypto bundles everything an upload needs to send: the
// ciphertext that gets PUT to R2 plus the metadata that lands in
// the File row via POST /api/files/upload/complete. Fields are
// base64 because that's the wire format the complete endpoint
// validates.
type UploadCrypto struct {
	// The encrypted file content (plaintext || GCM tag), AAD-bound
	// to {version="1.2", algorithm="AES-256-GCM", kem="ML-KEM-768"}.
	// Goes in the PUT body.
	Ciphertext []byte

	// ML-KEM-768 ciphertext encapsulating the per-file symmetric key
	// against the user's public key. 1088 bytes, base64.
	EncapsulatedKeyB64 string

	// AES-GCM-wrapped file key (32-byte plaintext key + 16-byte tag),
	// base64. Recovered via UnwrapFileKey on the download side.
	WrappedFileKeyB64 string

	// AES-GCM nonce used for the file content encryption. Distinct
	// from KeyWrapNonceB64 — different (key, nonce) pairs, both
	// required so the AEAD nonce is never reused under the same key.
	NonceB64 string

	// AES-GCM nonce used for the wrappedFileKey AEAD.
	KeyWrapNonceB64 string

	// Encrypted filename + its nonce. Server stores these instead of
	// originalFilename so a DB dump doesn't reveal the catalog.
	EncryptedFilenameB64 string
	FilenameNonceB64     string
}

// EncryptFileForUpload runs the v1.2 upload pipeline end-to-end:
//
//  1. Generate a fresh 32-byte file key + 12-byte nonce.
//  2. AES-256-GCM encrypt the file content with v1.2 AAD
//     ("sefaly-file-aad|v=1.2|alg=AES-256-GCM|kem=ML-KEM-768").
//  3. AES-256-GCM encrypt the filename under the SAME file key
//     with a fresh nonce (filenames have no AAD by spec).
//  4. ML-KEM-768 encapsulate against the user's own public key.
//  5. HKDF the shared secret into a wrapping key
//     (salt=encapsulatedKey, info="sefaly-file-key-wrap-v1").
//  6. AES-256-GCM wrap the file key under the wrapping key.
//
// Returns all the bytes the upload protocol needs. The plaintext
// file key never escapes this function — it's zeroed before return.
func EncryptFileForUpload(
	plaintext []byte,
	filename string,
	publicKeyB64 string,
) (*UploadCrypto, error) {
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	if len(publicKey) != mlkem768.PublicKeySize {
		return nil, fmt.Errorf(
			"public key must be %d bytes, got %d",
			mlkem768.PublicKeySize, len(publicKey),
		)
	}
	var pk mlkem768.PublicKey
	if err := pk.Unpack(publicKey); err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	// 1. File key (32 bytes) + content nonce (12 bytes).
	fileKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
		return nil, fmt.Errorf("reading randomness for file key: %w", err)
	}
	defer func() {
		for i := range fileKey {
			fileKey[i] = 0
		}
	}()
	nonce := make([]byte, aesGCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("reading randomness for nonce: %w", err)
	}

	// 2. Encrypt file content with v1.2 AAD.
	aad := buildFileAAD("1.2", "AES-256-GCM", "ML-KEM-768")
	ciphertext, err := aesGCMSeal(fileKey, nonce, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypting file content: %w", err)
	}

	// 3. Encrypt filename with the SAME key + a fresh nonce. No AAD —
	// browser doesn't bind one either (intentional: the wire format
	// for names is plain AEAD).
	filenameNonce := make([]byte, aesGCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, filenameNonce); err != nil {
		return nil, fmt.Errorf("reading randomness for filename nonce: %w", err)
	}
	encryptedFilename, err := aesGCMSeal(fileKey, filenameNonce, []byte(filename), nil)
	if err != nil {
		return nil, fmt.Errorf("encrypting filename: %w", err)
	}

	// 4. ML-KEM-768 encapsulate against the user's public key.
	kemSeed := make([]byte, mlkem768.EncapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, kemSeed); err != nil {
		return nil, fmt.Errorf("reading randomness for KEM seed: %w", err)
	}
	kemCt := make([]byte, mlkem768.CiphertextSize)
	sharedSecret := make([]byte, mlkem768.SharedKeySize)
	pk.EncapsulateTo(kemCt, sharedSecret, kemSeed)
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// 5. Derive AES wrap key via HKDF. Salt is the encapsulatedKey
	// itself, info matches the browser exactly.
	wrappingKey, err := hkdf.Key(sha256.New, sharedSecret, kemCt, hkdfInfoFileKeyWrap, 32)
	if err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}
	defer func() {
		for i := range wrappingKey {
			wrappingKey[i] = 0
		}
	}()

	// 6. Wrap the file key under wrappingKey. Fresh nonce.
	keyWrapNonce := make([]byte, aesGCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, keyWrapNonce); err != nil {
		return nil, fmt.Errorf("reading randomness for key-wrap nonce: %w", err)
	}
	wrappedFileKey, err := aesGCMSeal(wrappingKey, keyWrapNonce, fileKey, nil)
	if err != nil {
		return nil, fmt.Errorf("wrapping file key: %w", err)
	}

	return &UploadCrypto{
		Ciphertext:           ciphertext,
		EncapsulatedKeyB64:   base64.StdEncoding.EncodeToString(kemCt),
		WrappedFileKeyB64:    base64.StdEncoding.EncodeToString(wrappedFileKey),
		NonceB64:             base64.StdEncoding.EncodeToString(nonce),
		KeyWrapNonceB64:      base64.StdEncoding.EncodeToString(keyWrapNonce),
		EncryptedFilenameB64: base64.StdEncoding.EncodeToString(encryptedFilename),
		FilenameNonceB64:     base64.StdEncoding.EncodeToString(filenameNonce),
	}, nil
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
