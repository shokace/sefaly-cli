// Package api is the CLI's HTTP client for the Sefaly REST API.
// Every method here corresponds to one endpoint and wraps the
// request-encoding / response-decoding boilerplate, so command-layer
// code can focus on what it actually wants to do.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultBaseURL is the canonical Sefaly host. The CLI talks to the
// www variant directly so it doesn't depend on the apex → www
// redirect — a 307 with a body is "fine" in net/http but "clean" is
// better.
const DefaultBaseURL = "https://www.sefaly.com"

// UserAgent gets stamped on every outgoing request so server-side
// rate limiting + logs can distinguish CLI traffic from browser
// traffic. Includes the version (filled in at build time via
// ldflags).
var UserAgent = "sefaly-cli/dev"

// Client is a thin wrapper around net/http with a base URL, a
// timeout, and an optional Bearer token. Construct one per process,
// share across commands.
type Client struct {
	BaseURL string
	Token   string // empty = anonymous; set for authenticated endpoints
	httpc   *http.Client
}

func New(baseURL, bearerToken string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: baseURL,
		Token:   bearerToken,
		httpc:   &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError surfaces the server's error message + HTTP status.
// Commands can check for specific statuses (e.g. 401 = re-login,
// 404 = code expired) by type-asserting.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
}

// IsStatus returns true if `err` is an APIError with the given status.
// Convenience for branches like `if api.IsStatus(err, 404) { … }`.
func IsStatus(err error, status int) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status == status
	}
	return false
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Try to extract the server's structured error message.
		// Falls back to the raw body if it's not JSON.
		var errPayload struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBytes, &errPayload) == nil && errPayload.Error != "" {
			return &APIError{Status: resp.StatusCode, Message: errPayload.Error}
		}
		return &APIError{Status: resp.StatusCode, Message: string(respBytes)}
	}

	if out != nil {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

// ---- Device flow ----

type DeviceCodeResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

func (c *Client) StartDeviceFlow(ctx context.Context, ephPubBase64 string) (*DeviceCodeResponse, error) {
	out := &DeviceCodeResponse{}
	err := c.doJSON(ctx, http.MethodPost, "/api/cli/device-code", map[string]string{
		"ephPub":  ephPubBase64,
		"kemType": "ML-KEM-768",
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type PollResponse struct {
	Status              string `json:"status"` // pending | approved | denied | expired | unknown
	AccessTokenID       string `json:"accessTokenId,omitempty"`
	DeviceName          string `json:"deviceName,omitempty"`
	KemCt               string `json:"kemCt,omitempty"`
	WrappedTokenCt      string `json:"wrappedTokenCt,omitempty"`
	WrappedTokenNonce   string `json:"wrappedTokenNonce,omitempty"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey,omitempty"`
	User                *struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		PublicKey string `json:"publicKey"`
	} `json:"user,omitempty"`
}

func (c *Client) PollDeviceFlow(ctx context.Context, deviceCode string) (*PollResponse, error) {
	out := &PollResponse{}
	err := c.doJSON(ctx, http.MethodPost, "/api/cli/poll", map[string]string{
		"deviceCode": deviceCode,
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---- Authenticated ----

type Me struct {
	ID                       string `json:"id"`
	Email                    string `json:"email"`
	PublicKey                string `json:"publicKey"`
	Tier                     string `json:"tier"`
	StorageUsedBytes         string `json:"storageUsedBytes"`
	EmailVerifiedAt          string `json:"emailVerifiedAt"`
	TotpEnabled              bool   `json:"totpEnabled"`
	TotpBackupCodesRemaining int    `json:"totpBackupCodesRemaining"`
}

func (c *Client) Me(ctx context.Context) (*Me, error) {
	var resp struct {
		User Me `json:"user"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/auth/me", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.User, nil
}

// ---- File tree ----

// Folder is one row from /api/files?tree=1's `folders` array. Names
// are encrypted; the CLI decrypts them locally using the wrap material
// also returned on the row.
//
// Pre-rollout folders carry plaintext `Name` and null wrap material;
// post-rollout folders carry null `Name` and full wrap material. The
// CLI picks whichever is present.
type Folder struct {
	ID                  string  `json:"id"`
	ParentID            *string `json:"parentId"`
	Name                *string `json:"name"`
	EncryptedName       *string `json:"encryptedName"`
	NameNonce           *string `json:"nameNonce"`
	NameKeyEncapsulated *string `json:"nameKeyEncapsulated"`
	NameKeyWrapped      *string `json:"nameKeyWrapped"`
	NameKeyWrapNonce    *string `json:"nameKeyWrapNonce"`
	CreatedAt           string  `json:"createdAt"`
	UpdatedAt           string  `json:"updatedAt"`
}

// File is one row from `files`. Same plaintext-vs-encrypted name
// duality as Folder, with one extra wrinkle: the wrap nonce lives
// inside `encryptionMetadata.keyWrapNonce` rather than as a
// top-level column.
type File struct {
	ID                 string                 `json:"id"`
	FolderID           *string                `json:"folderId"`
	OriginalFilename   *string                `json:"originalFilename"`
	EncryptedFilename  *string                `json:"encryptedFilename"`
	FilenameNonce      *string                `json:"filenameNonce"`
	MimeType           *string                `json:"mimeType"`
	SizeBytes          string                 `json:"sizeBytes"` // serialized as string because BigInt
	StoragePath        string                 `json:"storagePath"`
	EncryptedFileKey   string                 `json:"encryptedFileKey"`
	EncapsulatedKey    string                 `json:"encapsulatedKey"`
	Nonce              string                 `json:"nonce"`
	EncryptionMetadata map[string]interface{} `json:"encryptionMetadata"`
	CreatedAt          string                 `json:"createdAt"`
	UpdatedAt          string                 `json:"updatedAt"`
}

// KeyWrapNonce extracts the AES-GCM nonce used to wrap the file key,
// pulled from the JSON `encryptionMetadata.keyWrapNonce`. Falls back
// to the file's content `Nonce` on v1.0 legacy rows (where the same
// nonce was reused — the v1.1+ rollout added a dedicated wrap nonce
// to fix that).
func (f *File) KeyWrapNonce() string {
	if v, ok := f.EncryptionMetadata["keyWrapNonce"].(string); ok && v != "" {
		return v
	}
	return f.Nonce
}

// TreeResponse is /api/files?tree=1's payload. Only `folders` and
// `files` are populated today; the `syncedShares` field exists in
// the schema but the CLI doesn't render shared content yet.
type TreeResponse struct {
	Folders []Folder `json:"folders"`
	Files   []File   `json:"files"`
}

func (c *Client) Tree(ctx context.Context) (*TreeResponse, error) {
	out := &TreeResponse{}
	if err := c.doJSON(ctx, http.MethodGet, "/api/files?tree=1", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- Download ----

// OwnerWrap is the wrap material the server returns to the FILE
// OWNER (not to a share recipient). Carries everything the CLI needs
// to unwrap the file key + decrypt the content in one round-trip.
type OwnerWrap struct {
	EncapsulatedKey   string `json:"encapsulatedKey"`
	WrappedFileKey    string `json:"wrappedFileKey"`
	Nonce             string `json:"nonce"`        // file CONTENT nonce
	KeyWrapNonce      string `json:"keyWrapNonce"` // key WRAP nonce
	EncryptionVersion string `json:"encryptionVersion"`
}

// FileURLResponse is what /api/files/[id]/url returns. `DownloadURL`
// may be a presigned R2 URL (prod) OR a same-origin streaming
// endpoint (filesystem-backed dev). Either way the CLI's
// FetchCiphertext can read it with no special handling.
type FileURLResponse struct {
	DownloadURL      string     `json:"downloadUrl"`
	OriginalFilename *string    `json:"originalFilename"`
	MimeType         *string    `json:"mimeType"`
	OwnerWrap        *OwnerWrap `json:"ownerWrap,omitempty"`
}

// FileURL asks the server for a download URL + the wrap material
// needed to decrypt. Authenticated.
func (c *Client) FileURL(ctx context.Context, fileID string) (*FileURLResponse, error) {
	out := &FileURLResponse{}
	if err := c.doJSON(ctx, http.MethodGet, "/api/files/"+fileID+"/url", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// FetchCiphertext downloads bytes from a URL that's NOT necessarily
// on our base host — typically the presigned R2 URL returned by
// /api/files/[id]/url. No Bearer header (R2 wouldn't accept it
// anyway; the auth is baked into the URL's query string by the
// presign). User-Agent is still stamped so server-side R2 logs
// can identify CLI clients.
//
// Reads into memory. For very large files we'll want a streaming
// AES-GCM open + on-the-fly disk write, but that needs streaming
// support from the underlying cipher; the AEAD interface used here
// doesn't support it. Acceptable for the MVP — typical Sefaly files
// fit comfortably.
func (c *Client) FetchCiphertext(ctx context.Context, url string) ([]byte, error) {
	// A separate, longer-timeout client. The default 30s on the
	// JSON client is too tight for multi-MB downloads; bump to
	// 10 min which covers anything reasonable while still bounding
	// hangs. Per-request override is fine — we don't share state
	// with the JSON path.
	dl := &http.Client{Timeout: 10 * time.Minute}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building download request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := dl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, &APIError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("GET %s: storage backend returned %d", url, resp.StatusCode),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading ciphertext: %w", err)
	}
	return body, nil
}
