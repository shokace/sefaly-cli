// Package cryptox implements the client half of Sefaly's device-flow
// crypto. Every function here mirrors a counterpart in the browser's
// src/lib/crypto/cli-device-flow.ts; the two MUST agree byte-for-byte
// or `sefaly login` fails at the unwrap step. Algorithm choices:
//
//   - ML-KEM-768 (FIPS 203) for the key encapsulation.
//   - AES-256-GCM for symmetric encryption, 12-byte nonce, 16-byte tag.
//   - HKDF-SHA256 for key derivation.
//   - SHA-256 over the UTF-8 encoding of the raw access token for the
//     hash the server uses to look the token up.
//
// Named `cryptox` not `crypto` to avoid shadowing Go's stdlib package
// at import time (the implementation here imports several stdlib
// crypto subpackages and the alias dance gets noisy otherwise).
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// AES-GCM parameters. Browser uses the Web Crypto defaults
	// (12-byte IV, 128-bit tag). Go's cipher.NewGCM defaults match
	// — keep both sides explicit so a future tweak doesn't go
	// unnoticed.
	aesGCMNonceLen = 12

	// HKDF info strings. These are part of the wire format; a typo
	// here breaks login silently because the derived keys won't
	// match the ones the browser produced.
	hkdfInfoTokenWrap = "sefaly-cli-token-wrap-v1"
	hkdfInfoPKEncrypt = "sefaly-cli-pk-v1"

	// AAD on the encrypted private key. Binds the ciphertext to the
	// user id so a malicious server couldn't serve user A's blob to
	// user B's CLI and have it open silently. Format mirrored from
	// browser exactly:
	//   "sefaly-cli-pk-v1|user=<userID>"
	pkAADPrefix = "sefaly-cli-pk-v1|user="
)

// EphemeralKey is the per-login ML-KEM-768 keypair. The CLI sends the
// public half to the server; the browser encapsulates the access
// token against it; only the holder of this struct can recover the
// token. Lives only for the duration of one login flow — we don't
// persist the private half anywhere.
type EphemeralKey struct {
	dk *mlkem.DecapsulationKey768
}

// GenerateEphemeralKey mints a fresh ML-KEM-768 keypair for a single
// login flow.
func GenerateEphemeralKey() (*EphemeralKey, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ML-KEM keygen: %w", err)
	}
	return &EphemeralKey{dk: dk}, nil
}

// PublicKeyBase64 is the standard-base64 encoding of the 1184-byte
// ML-KEM-768 public key. Matches the format the browser expects in
// POST /api/cli/device-code's `ephPub` field.
func (e *EphemeralKey) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(e.dk.EncapsulationKey().Bytes())
}

// UnwrapAccessToken reverses the browser's wrapAccessTokenForCli:
//
//	sharedSecret = ML-KEM-768.Decapsulate(ephPriv, kemCt)
//	unwrapKey    = HKDF-SHA256(sharedSecret, salt=ephPub, info="sefaly-cli-token-wrap-v1")
//	rawToken     = AES-256-GCM-Open(unwrapKey, nonce, wrappedCt)    // no AAD
//
// The salt is the ephemeral public key so each login produces a
// unique unwrap key even if a ML-KEM bug ever caused a shared-secret
// collision across flows.
func (e *EphemeralKey) UnwrapAccessToken(kemCtB64, wrappedCtB64, wrappedNonceB64 string) (string, error) {
	kemCt, err := base64.StdEncoding.DecodeString(kemCtB64)
	if err != nil {
		return "", fmt.Errorf("decoding kemCt: %w", err)
	}
	sharedSecret, err := e.dk.Decapsulate(kemCt)
	if err != nil {
		return "", fmt.Errorf("ML-KEM decapsulation: %w", err)
	}
	ephPub := e.dk.EncapsulationKey().Bytes()

	unwrapKey, err := hkdf.Key(sha256.New, sharedSecret, ephPub, hkdfInfoTokenWrap, 32)
	if err != nil {
		return "", fmt.Errorf("HKDF: %w", err)
	}

	wrappedCt, err := base64.StdEncoding.DecodeString(wrappedCtB64)
	if err != nil {
		return "", fmt.Errorf("decoding wrappedTokenCt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(wrappedNonceB64)
	if err != nil {
		return "", fmt.Errorf("decoding wrappedTokenNonce: %w", err)
	}
	if len(nonce) != aesGCMNonceLen {
		return "", fmt.Errorf("wrappedTokenNonce must be %d bytes (got %d)", aesGCMNonceLen, len(nonce))
	}

	plaintext, err := aesGCMOpen(unwrapKey, nonce, wrappedCt, nil)
	if err != nil {
		return "", fmt.Errorf("unwrapping access token (decapsulation succeeded but symmetric open failed — server may have served a swapped wrap): %w", err)
	}
	return string(plaintext), nil
}

// EncryptedPrivateKey mirrors the {ciphertext,nonce,kemType} triple
// the server stores in AccessToken.encryptedPrivateKey (as JSON).
// Exported so callers can parse the JSON themselves if they want,
// but the common path is via DecryptPrivateKey.
type EncryptedPrivateKey struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	KemType    string `json:"kemType"`
}

// DecryptPrivateKey reverses the browser's encryptPrivateKeyForCli:
//
//	cliKey     = HKDF-SHA256(UTF8(rawAccessToken), salt=zeros32, info="sefaly-cli-pk-v1")
//	privateKey = AES-256-GCM-Open(cliKey, nonce, ciphertext, aad="sefaly-cli-pk-v1|user=<userID>")
//
// `encPkJSON` is the JSON string the server returns as
// `encryptedPrivateKey` from POST /api/cli/poll.
func DecryptPrivateKey(rawAccessToken, userID, encPkJSON string) (privateKey []byte, kemType string, err error) {
	var enc EncryptedPrivateKey
	if err := json.Unmarshal([]byte(encPkJSON), &enc); err != nil {
		return nil, "", fmt.Errorf("parsing encryptedPrivateKey: %w", err)
	}

	// Salt is 32 zero bytes — IKM (the raw token) carries the
	// entropy. Browser does the same; documenting the constant
	// rather than reusing a global because someone copy-pasting
	// this file shouldn't have to chase a const definition.
	salt := make([]byte, 32)
	cliKey, err := hkdf.Key(sha256.New, []byte(rawAccessToken), salt, hkdfInfoPKEncrypt, 32)
	if err != nil {
		return nil, "", fmt.Errorf("HKDF: %w", err)
	}

	ct, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("decoding ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return nil, "", fmt.Errorf("decoding nonce: %w", err)
	}
	if len(nonce) != aesGCMNonceLen {
		return nil, "", fmt.Errorf("nonce must be %d bytes (got %d)", aesGCMNonceLen, len(nonce))
	}

	aad := []byte(pkAADPrefix + userID)
	plaintext, err := aesGCMOpen(cliKey, nonce, ct, aad)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting private key (AAD-bound to user=%s — mismatch usually means a server-side blob swap): %w", userID, err)
	}
	return plaintext, enc.KemType, nil
}

// TokenHashHex returns SHA-256(rawAccessToken) as lower-case hex.
// Matches the cookie session's hashToken() convention so the
// AccessToken lookup by tokenHash works identically for cookie and
// Bearer auth.
func TokenHashHex(rawAccessToken string) string {
	sum := sha256.Sum256([]byte(rawAccessToken))
	return hex.EncodeToString(sum[:])
}

func aesGCMOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}
