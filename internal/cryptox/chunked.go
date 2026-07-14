package cryptox

// Chunked file encryption — format version 2.0.
//
// Mirrors the web app's src/lib/crypto/chunked.ts BYTE-FOR-BYTE. Large
// files (web: >256 MiB) are encrypted as a sequence of fixed-size
// chunks so neither side ever holds the whole file in memory. Key
// wrapping is UNCHANGED from v1.2 (same ML-KEM-768 encapsulation, same
// HKDF, same share wraps) — only the content layout differs.
//
// Wire layout of the stored blob:
//
//	encChunk(0) || encChunk(1) || ... || encChunk(n-1)
//	encChunk(i) = nonce(12) || AES-256-GCM(plainChunk(i)) [+16 tag]
//
// Every chunk embeds a fresh random nonce. Each chunk's AAD binds the
// canonical metadata plus the chunk index and a last-chunk flag, so
// reordering, dropping, duplicating, truncating, or extending chunks
// all fail GCM auth:
//
//	"sefaly-file-aad|v=2.0|alg=AES-256-GCM|kem=ML-KEM-768|chunk=<i>|last=<0|1>"
//
// The plaintext chunk size is recorded in the File row's
// encryptionMetadata.chunkSizeBytes (the web writer uses 32 MiB);
// decrypt paths MUST honor the recorded value, not assume the default.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	// ChunkedEncryptionVersion is the encryptionMetadata.version value
	// for the chunked format.
	ChunkedEncryptionVersion = "2.0"

	// DefaultChunkSizeBytes is the plaintext chunk size this CLI writes
	// (and the web app's writer constant). 32 MiB.
	DefaultChunkSizeBytes = 32 * 1024 * 1024

	// chunkOverheadBytes = 12-byte embedded nonce + 16-byte GCM tag,
	// added to every chunk. Must match CHUNK_OVERHEAD_BYTES in the web
	// app's src/lib/uploads/multipart.ts.
	chunkOverheadBytes = aesGCMNonceLen + 16

	// MultipartThresholdBytes: plaintext size above which uploads take
	// the chunked multipart path. Matches the web client.
	MultipartThresholdBytes = 256 * 1024 * 1024

	// MaxMultipartParts is R2's hard cap on parts per multipart upload
	// (one encrypted chunk per part).
	MaxMultipartParts = 10_000
)

// ChunkOverheadBytes is exported for size math in the upload layer.
const ChunkOverheadBytes = chunkOverheadBytes

// IsChunkedVersion reports whether a file row's encryption version is
// the chunked format.
func IsChunkedVersion(version string) bool {
	return version == ChunkedEncryptionVersion
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, err
	}
	return out, nil
}

func encodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// parsePublicKey decodes + unpacks a base64 ML-KEM-768 public key.
// Same validation as EncryptFileForUpload's inline version.
func parsePublicKey(publicKeyB64 string) (*mlkem768.PublicKey, error) {
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
	return &pk, nil
}

// buildChunkAAD must produce the EXACT byte sequence the browser
// produces in src/lib/crypto/chunked.ts :: buildChunkAAD. Any drift
// silently breaks decryption of every chunked file.
func buildChunkAAD(chunkIndex int, isLast bool) []byte {
	last := 0
	if isLast {
		last = 1
	}
	return []byte(fmt.Sprintf(
		"sefaly-file-aad|v=%s|alg=AES-256-GCM|kem=ML-KEM-768|chunk=%d|last=%d",
		ChunkedEncryptionVersion, chunkIndex, last,
	))
}

// EncryptChunk encrypts one plaintext chunk. Returns
// nonce || ciphertext+tag, sized exactly len(plainChunk) + 28.
func EncryptChunk(fileKey, plainChunk []byte, chunkIndex int, isLast bool) ([]byte, error) {
	if len(fileKey) != 32 {
		return nil, errors.New("file key must be 32 bytes")
	}
	nonce, err := randomBytes(aesGCMNonceLen)
	if err != nil {
		return nil, fmt.Errorf("reading randomness for chunk nonce: %w", err)
	}
	sealed, err := aesGCMSeal(fileKey, nonce, plainChunk, buildChunkAAD(chunkIndex, isLast))
	if err != nil {
		return nil, fmt.Errorf("encrypting chunk %d: %w", chunkIndex, err)
	}
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// DecryptChunk decrypts one nonce-prefixed encrypted chunk. Fails on
// any tampering: wrong position, flipped last flag, modified bytes.
func DecryptChunk(fileKey, encryptedChunk []byte, chunkIndex int, isLast bool) ([]byte, error) {
	if len(fileKey) != 32 {
		return nil, errors.New("file key must be 32 bytes")
	}
	if len(encryptedChunk) <= chunkOverheadBytes {
		return nil, errors.New("encrypted chunk is too short")
	}
	nonce := encryptedChunk[:aesGCMNonceLen]
	sealed := encryptedChunk[aesGCMNonceLen:]
	plain, err := aesGCMOpen(fileKey, nonce, sealed, buildChunkAAD(chunkIndex, isLast))
	if err != nil {
		return nil, fmt.Errorf(
			"AES-GCM open failed on chunk %d (version=%s) — usually a wrong key or tampered ciphertext: %w",
			chunkIndex, ChunkedEncryptionVersion, err,
		)
	}
	return plain, nil
}

// ChunkCount returns the number of chunks a plaintext of the given
// size splits into.
func ChunkCount(plaintextBytes int64, chunkSizeBytes int) (int, error) {
	if plaintextBytes <= 0 {
		return 0, errors.New("plaintext size must be positive")
	}
	if chunkSizeBytes <= 0 {
		return 0, errors.New("chunk size must be positive")
	}
	cs := int64(chunkSizeBytes)
	return int((plaintextBytes + cs - 1) / cs), nil
}

// CiphertextSizeForPlaintext is the exact stored-blob size for a
// chunked encryption of the given plaintext: every chunk gains the
// fixed 28-byte overhead. This is what multipart/init is told and
// what /upload/complete verifies against the R2 HEAD.
func CiphertextSizeForPlaintext(plaintextBytes int64, chunkSizeBytes int) (int64, error) {
	n, err := ChunkCount(plaintextBytes, chunkSizeBytes)
	if err != nil {
		return 0, err
	}
	return plaintextBytes + int64(n)*chunkOverheadBytes, nil
}

// DecryptChunkedStream decrypts a chunked (v2.0) ciphertext stream to
// dst, holding at most two encrypted chunks in memory at a time. The
// stream length doesn't need to be known up front: the reader is
// consumed with one chunk of read-ahead so the final chunk can be
// authenticated with last=1 (a truncated stream therefore fails auth
// on its final chunk instead of silently producing a short file).
//
// Returns the number of plaintext bytes written.
func DecryptChunkedStream(fileKey []byte, chunkSizeBytes int, src io.Reader, dst io.Writer) (int64, error) {
	if chunkSizeBytes <= 0 {
		return 0, errors.New("chunk size must be positive")
	}
	encChunkLen := chunkSizeBytes + chunkOverheadBytes

	var written int64
	var pending []byte // previous full read, not yet decrypted (might be the last chunk)
	index := 0

	flush := func(chunk []byte, isLast bool) error {
		plain, err := DecryptChunk(fileKey, chunk, index, isLast)
		if err != nil {
			return err
		}
		n, err := dst.Write(plain)
		written += int64(n)
		if err != nil {
			return fmt.Errorf("writing plaintext: %w", err)
		}
		index++
		return nil
	}

	for {
		buf := make([]byte, encChunkLen)
		n, err := io.ReadFull(src, buf)
		switch {
		case err == nil:
			// A full-size chunk arrived. The one before it (if any) is
			// now definitely not last.
			if pending != nil {
				if err := flush(pending, false); err != nil {
					return written, err
				}
			}
			pending = buf
		case errors.Is(err, io.ErrUnexpectedEOF):
			// Short read = the stream's final, partial chunk.
			if pending != nil {
				if err := flush(pending, false); err != nil {
					return written, err
				}
			}
			return written, flush(buf[:n], true)
		case errors.Is(err, io.EOF):
			// Stream ended exactly on a chunk boundary: pending is last.
			if pending == nil {
				return written, errors.New("empty ciphertext stream")
			}
			return written, flush(pending, true)
		default:
			return written, fmt.Errorf("reading ciphertext: %w", err)
		}
	}
}

// ChunkedUploadCrypto is the key ceremony for a chunked upload —
// everything EncryptFileForUpload produces EXCEPT the content
// ciphertext, which the upload loop produces one chunk at a time via
// EncryptChunk using the returned FileKey.
type ChunkedUploadCrypto struct {
	// FileKey is the plaintext 32-byte content key. CALLER OWNS IT:
	// feed it to EncryptChunk per chunk, then zero it the moment the
	// upload settles (success or failure).
	FileKey []byte

	EncapsulatedKeyB64 string
	WrappedFileKeyB64  string

	// NonceB64 is a random placeholder: v2.0 has no single content
	// nonce (each chunk embeds its own), but the File row's nonce
	// column is required and validated, so we ship 12 random bytes no
	// decrypt path reads. Same as the web client.
	NonceB64 string

	KeyWrapNonceB64      string
	EncryptedFilenameB64 string
	FilenameNonceB64     string
	ChunkSizeBytes       int
}

// PrepareChunkedUpload runs the v2.0 key ceremony: fresh file key,
// filename encryption, ML-KEM wrap — identical to EncryptFileForUpload
// steps 1/3/4/5/6, skipping only the whole-file content encryption.
func PrepareChunkedUpload(filename, publicKeyB64 string, chunkSizeBytes int) (*ChunkedUploadCrypto, error) {
	if chunkSizeBytes <= 0 {
		return nil, errors.New("chunk size must be positive")
	}
	pk, err := parsePublicKey(publicKeyB64)
	if err != nil {
		return nil, err
	}

	fileKey, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("reading randomness for file key: %w", err)
	}
	// NOTE: fileKey is intentionally NOT zeroed here — the chunk loop
	// needs it. Zeroing is the caller's job.

	filenameNonce, err := randomBytes(aesGCMNonceLen)
	if err != nil {
		return nil, fmt.Errorf("reading randomness for filename nonce: %w", err)
	}
	encryptedFilename, err := aesGCMSeal(fileKey, filenameNonce, []byte(filename), nil)
	if err != nil {
		return nil, fmt.Errorf("encrypting filename: %w", err)
	}

	wrap, err := wrapKeyForRecipient(fileKey, pk)
	if err != nil {
		return nil, fmt.Errorf("wrapping file key: %w", err)
	}

	placeholderNonce, err := randomBytes(aesGCMNonceLen)
	if err != nil {
		return nil, fmt.Errorf("reading randomness for placeholder nonce: %w", err)
	}

	return &ChunkedUploadCrypto{
		FileKey:              fileKey,
		EncapsulatedKeyB64:   wrap.EncapsulatedKeyB64,
		WrappedFileKeyB64:    wrap.WrappedKeyB64,
		NonceB64:             encodeB64(placeholderNonce),
		KeyWrapNonceB64:      wrap.KeyWrapNonceB64,
		EncryptedFilenameB64: encodeB64(encryptedFilename),
		FilenameNonceB64:     encodeB64(filenameNonce),
		ChunkSizeBytes:       chunkSizeBytes,
	}, nil
}
