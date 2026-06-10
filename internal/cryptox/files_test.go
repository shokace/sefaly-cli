package cryptox

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// genKeypair returns a fresh ML-KEM-768 keypair: the public key base64,
// and the private key in the 2400-byte expanded form UnwrapFileKey wants.
func genKeypair(t *testing.T) (pubB64 string, priv []byte) {
	t.Helper()
	pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pkb := make([]byte, mlkem768.PublicKeySize)
	pk.Pack(pkb)
	skb := make([]byte, mlkem768.PrivateKeySize)
	sk.Pack(skb)
	return base64.StdEncoding.EncodeToString(pkb), skb
}

// TestEncryptFileRoundTrip is the end-to-end happy path: encrypt a file
// for upload against a public key, then recover the key + plaintext +
// filename with the matching private key. Exercises the same code the
// `put` / `get` commands rely on.
func TestEncryptFileRoundTrip(t *testing.T) {
	pubB64, priv := genKeypair(t)
	plaintext := []byte("hello sefaly — this round-trips end to end")

	enc, err := EncryptFileForUpload(plaintext, "secret.txt", pubB64)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	fileKey, err := UnwrapFileKey(priv, enc.EncapsulatedKeyB64, enc.WrappedFileKeyB64, enc.KeyWrapNonceB64)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	got, err := DecryptFileContent(fileKey, enc.NonceB64, "1.2", enc.Ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("content mismatch: got %q", got)
	}
	name, err := DecryptName(fileKey, enc.EncryptedFilenameB64, enc.FilenameNonceB64)
	if err != nil {
		t.Fatalf("decrypt name: %v", err)
	}
	if name != "secret.txt" {
		t.Fatalf("name mismatch: got %q", name)
	}
}

// TestWrapUnwrapForRecipient verifies the direct-share crypto: a file
// key wrapped to a recipient's public key unwraps back to the same key
// with their private key.
func TestWrapUnwrapForRecipient(t *testing.T) {
	pubB64, priv := genKeypair(t)
	fileKey := make([]byte, 32)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	wrap, err := WrapFileKeyForRecipient(fileKey, pubB64)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	got, err := UnwrapFileKey(priv, wrap.EncapsulatedKeyB64, wrap.WrappedKeyB64, wrap.KeyWrapNonceB64)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, fileKey) {
		t.Fatal("recipient unwrap mismatch")
	}
}

// TestPublicLinkRoundTrip verifies the public-link payload encrypts +
// decrypts under the link key, and that the fragment encoding is the
// base64url (no-pad) form the web's linkKeyFromFragment expects.
func TestPublicLinkRoundTrip(t *testing.T) {
	linkKey, err := GenerateLinkKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(linkKey) != 32 {
		t.Fatalf("link key must be 32 bytes, got %d", len(linkKey))
	}
	msg := []byte("a plaintext file key (32 bytes!)")
	payloadB64, nonceB64, err := EncryptForPublicLink(msg, linkKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	payload, _ := base64.StdEncoding.DecodeString(payloadB64)
	nonce, _ := base64.StdEncoding.DecodeString(nonceB64)
	got, err := aesGCMOpen(linkKey, nonce, payload, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("public-link round trip mismatch")
	}
	if frag := LinkKeyToFragment(linkKey); strings.ContainsAny(frag, "+/=") {
		t.Fatalf("fragment is not base64url: %q", frag)
	}
}

// TestVersionDowngradeRejected confirms the decrypt path refuses a
// missing/unknown encryption version rather than silently proceeding.
func TestVersionDowngradeRejected(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	nonce := base64.StdEncoding.EncodeToString(make([]byte, aesGCMNonceLen))
	if _, err := DecryptFileContent(key, nonce, "", []byte("x")); err == nil {
		t.Fatal("expected error on missing version")
	}
	if _, err := DecryptFileContent(key, nonce, "9.9", []byte("x")); err == nil {
		t.Fatal("expected error on unknown version")
	}
}
