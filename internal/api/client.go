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
	"net/url"
	"time"
)

const (
	// maxJSONResponse caps doJSON body reads — a backstop against a
	// malicious or buggy server streaming unbounded data. Real API
	// responses (even a large file tree) are far smaller.
	maxJSONResponse = 64 << 20 // 64 MiB
	// maxCiphertextResponse caps a single file download. Whole-file
	// in-memory decrypt already bounds practical size; this stops an
	// infinite/oversized stream from exhausting memory.
	maxCiphertextResponse = 16 << 30 // 16 GiB
)

// noDowngradeRedirect permits ordinary redirects but refuses any that
// drop https→http — which would otherwise put a presigned URL's
// signature, or uploaded ciphertext, on the wire in cleartext — and
// caps the chain length.
func noDowngradeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https %q", req.URL.String())
	}
	return nil
}

// requireSecureURL rejects a storage URL that isn't https (loopback
// http allowed for local dev). A compromised API server could otherwise
// hand us an http:// or off-scheme download/upload URL.
func requireSecureURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid storage URL: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
	}
	return fmt.Errorf("refusing non-https storage URL (scheme %q)", u.Scheme)
}

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
		httpc: &http.Client{
			Timeout: 30 * time.Second,
			// Refuse to follow redirects. The JSON client carries the
			// Bearer access token in `Authorization`, and a malicious
			// or misconfigured API host could 302 that token to an
			// attacker-controlled endpoint. The Sefaly API never
			// intentionally returns 3xx for any documented JSON route,
			// so the user-visible cost is zero. Returning an explicit
			// error (not http.ErrUseLastResponse) makes c.httpc.Do
			// surface a clear failure to the caller instead of
			// silently producing an unparseable 3xx body.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("refusing to follow redirect to %q (would carry the Bearer token off-origin)", req.URL.String())
			},
		},
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
	// Stamp an Origin header matching our base URL. Current servers
	// (post-2026-05) short-circuit assertCsrfSafe for Bearer-
	// authenticated requests, so this is a no-op on them. We keep
	// stamping it for compatibility with older Sefaly servers where
	// the CSRF gate predates that change — without it, the request
	// would 403 on those.
	req.Header.Set("Origin", c.BaseURL)

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONResponse))
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

// RevokeSelf soft-revokes the token this client is authenticating
// with (flips revokedAt on the server-side AccessToken row). Wired
// up to `sef logout` so logout is server-side, not just a local
// clear. Idempotent: the server returns 200 whether or not the row
// was already revoked.
func (c *Client) RevokeSelf(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/cli/token", nil, nil)
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
	DeletedAt          *string                `json:"deletedAt,omitempty"` // set only on Trash rows
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

// EncryptionVersion extracts `encryptionMetadata.version` (empty when
// absent — decrypt paths reject that themselves).
func (f *File) EncryptionVersion() string {
	if v, ok := f.EncryptionMetadata["version"].(string); ok {
		return v
	}
	return ""
}

// ChunkSizeBytes extracts `encryptionMetadata.chunkSizeBytes`, the
// plaintext bytes per chunk on chunked (v2.0) files. Returns 0 when
// absent (v1.x rows); JSON numbers unmarshal as float64.
func (f *File) ChunkSizeBytes() int {
	if v, ok := f.EncryptionMetadata["chunkSizeBytes"].(float64); ok && v > 0 {
		return int(v)
	}
	return 0
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

// ---- Upload ----

// UploadInitRequest is the POST body for /api/files/upload/init.
// Tiny on purpose — the server only needs sizeBytes (to pre-flight
// the quota check + sign the presigned PUT with a fixed
// content-length) and folderId (to authorize the caller against
// any cross-owner WRITE share on a folder they don't own).
type UploadInitRequest struct {
	SizeBytes int    `json:"sizeBytes"`
	FolderID  string `json:"folderId,omitempty"` // empty / unset → root
}

type UploadInitResponse struct {
	UploadURL     string `json:"uploadUrl"`
	FileID        string `json:"fileId"`
	StoragePath   string `json:"storagePath"`
	ContentLength int    `json:"contentLength"`
	ExpiresIn     int    `json:"expiresInSeconds"`
}

func (c *Client) UploadInit(ctx context.Context, req *UploadInitRequest) (*UploadInitResponse, error) {
	// folderId must be marshalled as null (NOT empty string) for the
	// "root folder" case — the server's validator treats "" as
	// missing-or-null but null is the cleaner wire signal. Roll our
	// own body to avoid the omitempty + null contortions JSON tags
	// would need.
	type body struct {
		SizeBytes int     `json:"sizeBytes"`
		FolderID  *string `json:"folderId"`
	}
	b := body{SizeBytes: req.SizeBytes}
	if req.FolderID != "" {
		fid := req.FolderID
		b.FolderID = &fid
	}
	out := &UploadInitResponse{}
	if err := c.doJSON(ctx, http.MethodPost, "/api/files/upload/init", &b, out); err != nil {
		return nil, err
	}
	return out, nil
}

// UploadPut PUTs ciphertext to a presigned URL (typically R2). The
// presign is signed against a specific Content-Length, so we MUST
// send the matching size — anything else gets a 403 from R2. No
// Bearer header (the auth is in the URL's query string). Same
// Content-Type the browser uses: application/octet-stream, so the
// original mimetype isn't leaked to network observers.
func (c *Client) UploadPut(ctx context.Context, url string, ciphertext []byte) error {
	if err := requireSecureURL(url); err != nil {
		return err
	}
	dl := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: noDowngradeRedirect}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(ciphertext))
	if err != nil {
		return fmt.Errorf("building PUT request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(ciphertext))
	req.Header.Set("User-Agent", UserAgent)

	resp, err := dl.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return &APIError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("storage PUT failed (%d): %s", resp.StatusCode, string(body)),
		}
	}
	return nil
}

// UploadCompleteRequest matches POST /api/files/upload/complete's
// validated body. `originalFilename` is intentionally null on every
// CLI upload — we encrypt the filename client-side and ship the
// ciphertext in `EncryptedFilename` + `FilenameNonce` so the server
// never sees the plaintext. `ShareWraps` is reserved for the future
// shared-folder upload path; CLI doesn't construct shares yet.
type UploadCompleteRequest struct {
	FileID             string                 `json:"fileId"`
	StoragePath        string                 `json:"storagePath"`
	OriginalFilename   *string                `json:"originalFilename"`
	EncryptedFilename  string                 `json:"encryptedFilename"`
	FilenameNonce      string                 `json:"filenameNonce"`
	MimeType           *string                `json:"mimeType"`
	FolderID           *string                `json:"folderId"`
	EncapsulatedKey    string                 `json:"encapsulatedKey"`
	WrappedFileKey     string                 `json:"wrappedFileKey"`
	Nonce              string                 `json:"nonce"`
	KeyWrapNonce       string                 `json:"keyWrapNonce"`
	EncryptionMetadata map[string]interface{} `json:"encryptionMetadata"`
	ShareWraps         []interface{}          `json:"shareWraps"`
}

type UploadCompleteResponse struct {
	File struct {
		ID                string  `json:"id"`
		OriginalFilename  *string `json:"originalFilename"`
		EncryptedFilename *string `json:"encryptedFilename"`
		MimeType          *string `json:"mimeType"`
		SizeBytes         string  `json:"sizeBytes"`
		CreatedAt         string  `json:"createdAt"`
		FolderID          *string `json:"folderId"`
	} `json:"file"`
}

func (c *Client) UploadComplete(ctx context.Context, req *UploadCompleteRequest) (*UploadCompleteResponse, error) {
	if req.ShareWraps == nil {
		// The server validates `shareWraps` as required-array. Send
		// an empty slice rather than nil to avoid encoding it as
		// JSON `null`.
		req.ShareWraps = []interface{}{}
	}
	out := &UploadCompleteResponse{}
	if err := c.doJSON(ctx, http.MethodPost, "/api/files/upload/complete", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- Multipart upload (chunked format v2.0, large files) ----

// MultipartInitRequest is the POST body for
// /api/files/upload/multipart/init. sizeBytes is the TOTAL ciphertext
// size (plaintext + 28 bytes per chunk); partSizeBytes is the uniform
// encrypted-chunk size (one chunk per part, last part smaller).
type MultipartInitRequest struct {
	SizeBytes     int64  `json:"sizeBytes"`
	FolderID      string `json:"-"` // marshalled as null when empty, like UploadInit
	PartSizeBytes int    `json:"partSizeBytes"`
	PartCount     int    `json:"partCount"`
}

type MultipartInitResponse struct {
	FileID      string `json:"fileId"`
	StoragePath string `json:"storagePath"`
	UploadID    string `json:"uploadId"`
	// Token is an HMAC binding (fileId, uploadId, this session). The
	// part / complete-parts / abort endpoints require it back — treat
	// it like a bearer secret for this one upload.
	Token string `json:"token"`
}

func (c *Client) MultipartInit(ctx context.Context, req *MultipartInitRequest) (*MultipartInitResponse, error) {
	type body struct {
		SizeBytes     int64   `json:"sizeBytes"`
		FolderID      *string `json:"folderId"`
		PartSizeBytes int     `json:"partSizeBytes"`
		PartCount     int     `json:"partCount"`
	}
	b := body{SizeBytes: req.SizeBytes, PartSizeBytes: req.PartSizeBytes, PartCount: req.PartCount}
	if req.FolderID != "" {
		fid := req.FolderID
		b.FolderID = &fid
	}
	out := &MultipartInitResponse{}
	if err := c.doJSON(ctx, http.MethodPost, "/api/files/upload/multipart/init", &b, out); err != nil {
		return nil, err
	}
	return out, nil
}

// MultipartPartURL mints a presigned PUT URL for one part (1-based
// partNumber). The layout is re-sent so the server can derive and
// signature-bind the part's exact Content-Length.
func (c *Client) MultipartPartURL(
	ctx context.Context,
	init *MultipartInitResponse,
	partNumber, partSizeBytes, partCount int,
) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	body := map[string]any{
		"fileId":        init.FileID,
		"uploadId":      init.UploadID,
		"token":         init.Token,
		"partNumber":    partNumber,
		"partSizeBytes": partSizeBytes,
		"partCount":     partCount,
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/files/upload/multipart/part", body, &out); err != nil {
		return "", err
	}
	return out.URL, nil
}

// MultipartPart pairs a part number with the ETag R2 returned for it.
type MultipartPart struct {
	PartNumber int    `json:"partNumber"`
	ETag       string `json:"etag"`
}

// MultipartCompleteParts stitches the uploaded parts into the final
// object (CompleteMultipartUpload). The regular UploadComplete call
// follows it to commit the File row.
func (c *Client) MultipartCompleteParts(
	ctx context.Context,
	init *MultipartInitResponse,
	parts []MultipartPart,
) error {
	body := map[string]any{
		"fileId":   init.FileID,
		"uploadId": init.UploadID,
		"token":    init.Token,
		"parts":    parts,
	}
	return c.doJSON(ctx, http.MethodPost, "/api/files/upload/multipart/complete-parts", body, nil)
}

// MultipartAbort discards an in-progress multipart upload and frees
// its quota reservation. Best-effort cleanup on failure paths — the
// server's reap cron sweeps anything this misses.
func (c *Client) MultipartAbort(ctx context.Context, init *MultipartInitResponse) error {
	body := map[string]any{
		"fileId":   init.FileID,
		"uploadId": init.UploadID,
		"token":    init.Token,
	}
	return c.doJSON(ctx, http.MethodPost, "/api/files/upload/multipart/abort", body, nil)
}

// UploadPutPart PUTs one encrypted chunk to a presigned part URL and
// returns the ETag R2 answered with (required by
// MultipartCompleteParts). Same security posture as UploadPut.
func (c *Client) UploadPutPart(ctx context.Context, url string, part []byte) (string, error) {
	if err := requireSecureURL(url); err != nil {
		return "", err
	}
	dl := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: noDowngradeRedirect}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(part))
	if err != nil {
		return "", fmt.Errorf("building part PUT request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(part))
	req.Header.Set("User-Agent", UserAgent)

	resp, err := dl.Do(req)
	if err != nil {
		return "", fmt.Errorf("PUT part: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", &APIError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("storage part PUT failed (%d): %s", resp.StatusCode, string(body)),
		}
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("storage did not return a part ETag")
	}
	return etag, nil
}

// DuplicateFile server-side copies a file into folderID (nil = root),
// reusing the source's wrap material verbatim (POST /api/files/:id/
// duplicate). Returns the new file's id. No client crypto needed — the
// server copies the ciphertext blob and the encrypted name as-is.
func (c *Client) DuplicateFile(ctx context.Context, fileID string, folderID *string) (string, error) {
	var out struct {
		File struct {
			ID string `json:"id"`
		} `json:"file"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/files/"+fileID+"/duplicate",
		map[string]any{"folderId": folderID}, &out); err != nil {
		return "", err
	}
	return out.File.ID, nil
}

// ---- File / folder mutation ----

// DeleteFile soft-removes a single file. The server handles the R2
// object cleanup + share-recipient event fan-out. Idempotent on the
// server side; returns 404 if the id doesn't exist or isn't ours.
func (c *Client) DeleteFile(ctx context.Context, fileID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/files/"+fileID, nil, nil)
}

// DeleteFolder removes a folder. Server-side this is recursive and
// transactional — all descendant files + subfolders + share rows go
// with it. We don't pass any options; the server's behaviour matches
// the dashboard's "delete folder" semantics.
func (c *Client) DeleteFolder(ctx context.Context, folderID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/folders/"+folderID, nil, nil)
}

// CreateFolderRequest matches POST /api/folders body for the
// encrypted-name path. Mirrors the dashboard's create call:
//
//   - `EncryptedName`     = AES-GCM(folderNameKey, nameBytes, nonce=nameNonce)
//   - `NameNonce`         = 12-byte AES-GCM nonce, base64
//   - `NameKeyEncapsulated` / `NameKeyWrapped` / `NameKeyWrapNonce`
//     = ML-KEM-768 wrap of the per-folder name key, against the
//     authenticated user's own public key (no cross-owner WRITE
//     path from the CLI in v1).
//   - `ParentID` optional; null/empty → root.
type CreateFolderRequest struct {
	ParentID            *string `json:"parentId"`
	EncryptedName       string  `json:"encryptedName"`
	NameNonce           string  `json:"nameNonce"`
	NameKeyEncapsulated string  `json:"nameKeyEncapsulated"`
	NameKeyWrapped      string  `json:"nameKeyWrapped"`
	NameKeyWrapNonce    string  `json:"nameKeyWrapNonce"`
}

type CreateFolderResponse struct {
	Folder struct {
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
	} `json:"folder"`
}

func (c *Client) CreateFolder(ctx context.Context, req *CreateFolderRequest) (*CreateFolderResponse, error) {
	out := &CreateFolderResponse{}
	if err := c.doJSON(ctx, http.MethodPost, "/api/folders", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// PatchFile and PatchFolder take a free-form body so callers can
// express the three states the server treats distinctly:
//
//   - key absent           → leave field alone
//   - key present, null    → move-to-root (folderId=null /
//     parentId=null) on files / folders
//   - key present, string  → set to value
//
// Go's `omitempty` + `*string` collapses the first two states (a
// nil pointer omits the key, so "explicit null" is unreachable),
// so we drop the struct shape here and let the command layer hand
// us a map. Keys the server understands:
//
//	files:    folderId, originalFilename, encryptedFilename, filenameNonce
//	folders:  parentId, name, encryptedName, nameNonce
//
// Anything else is ignored by the server.
func (c *Client) PatchFile(ctx context.Context, fileID string, body map[string]interface{}) error {
	return c.doJSON(ctx, http.MethodPatch, "/api/files/"+fileID, body, nil)
}

func (c *Client) PatchFolder(ctx context.Context, folderID string, body map[string]interface{}) error {
	return c.doJSON(ctx, http.MethodPatch, "/api/folders/"+folderID, body, nil)
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
// ---- Trash ----

// TrashList returns the caller's soft-deleted files (GET /api/trash).
// Each row carries the same encrypted-name material as a tree File, so
// names decrypt with the existing helpers.
func (c *Client) TrashList(ctx context.Context) ([]File, error) {
	var out struct {
		Files []File `json:"files"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/trash", nil, &out); err != nil {
		return nil, err
	}
	return out.Files, nil
}

// TrashRestore restores trashed files by id (POST /api/trash). The
// server re-checks quota; a 413 means the restore would exceed storage.
func (c *Client) TrashRestore(ctx context.Context, fileIDs []string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/trash", map[string]any{"fileIds": fileIDs}, nil)
}

// TrashDeleteForever permanently removes trashed files by id
// (DELETE /api/trash) — hard delete + blob reclaim, irreversible.
func (c *Client) TrashDeleteForever(ctx context.Context, fileIDs []string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/trash", map[string]any{"fileIds": fileIDs}, nil)
}

// ---- Sharing ----

// LookupPublicKey resolves a recipient's user id + ML-KEM public key by
// email (POST /api/users/lookup-public-key). 404 → no Sefaly account.
func (c *Client) LookupPublicKey(ctx context.Context, email string) (recipientID, publicKeyB64 string, err error) {
	var out struct {
		Recipient struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			PublicKey string `json:"publicKey"`
		} `json:"recipient"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/users/lookup-public-key",
		map[string]string{"email": email}, &out); err != nil {
		return "", "", err
	}
	return out.Recipient.ID, out.Recipient.PublicKey, nil
}

// ShareFileWithUser creates a direct FileShare to a registered user
// (POST /api/files/:id/share) using a per-recipient ML-KEM wrap.
func (c *Client) ShareFileWithUser(ctx context.Context, fileID, recipientID, encapsulatedKey, wrappedFileKey, keyWrapNonce string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/files/"+fileID+"/share", map[string]string{
		"recipientId":     recipientID,
		"encapsulatedKey": encapsulatedKey,
		"wrappedFileKey":  wrappedFileKey,
		"keyWrapNonce":    keyWrapNonce,
	}, nil)
}

// PublicLinkOptions are the optional knobs for a public link. Nil/zero =
// server default (tier-capped TTL, unlimited downloads, random token).
type PublicLinkOptions struct {
	ExpiresInDays *int
	MaxDownloads  *int
	CustomSlug    string
}

// CreateFilePublicLink creates an anonymous public link for a file
// (POST /api/files/:id/share/public). The link key is NOT sent — only
// the payload encrypted under it. Returns (token, slug) for building the
// `/s/<slug-or-token>#<linkKey>` URL.
func (c *Client) CreateFilePublicLink(ctx context.Context, fileID, encryptedPayload, payloadNonce string, opt PublicLinkOptions) (token, slug string, err error) {
	body := map[string]any{"encryptedPayload": encryptedPayload, "payloadNonce": payloadNonce}
	if opt.ExpiresInDays != nil {
		body["expiresInDays"] = *opt.ExpiresInDays
	}
	if opt.MaxDownloads != nil {
		body["maxDownloads"] = *opt.MaxDownloads
	}
	if opt.CustomSlug != "" {
		body["customSlug"] = opt.CustomSlug
	}
	var out struct {
		Link struct {
			Token      string  `json:"token"`
			CustomSlug *string `json:"customSlug"`
		} `json:"link"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/files/"+fileID+"/share/public", body, &out); err != nil {
		return "", "", err
	}
	s := ""
	if out.Link.CustomSlug != nil {
		s = *out.Link.CustomSlug
	}
	return out.Link.Token, s, nil
}

// OutgoingShares is the caller's outbound share inventory.
type OutgoingShares struct {
	Files []struct {
		ID             string `json:"id"`
		RecipientEmail string `json:"recipientEmail"`
	} `json:"files"`
	Folders []struct {
		ID             string `json:"id"`
		RecipientEmail string `json:"recipientEmail"`
		FileCount      int    `json:"fileCount"`
	} `json:"folders"`
	PublicLinks []struct {
		ID         string  `json:"id"`
		Token      string  `json:"token"`
		CustomSlug *string `json:"customSlug"`
	} `json:"publicLinks"`
}

func (c *Client) ListOutgoingShares(ctx context.Context) (*OutgoingShares, error) {
	out := &OutgoingShares{}
	if err := c.doJSON(ctx, http.MethodGet, "/api/shares/outgoing", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokePublicLink revokes a public link by id (DELETE
// /api/public-links/:id). Sets revokedAt server-side; the token + any
// custom slug stop working immediately.
func (c *Client) RevokePublicLink(ctx context.Context, linkID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/public-links/"+linkID, nil, nil)
}

// FetchCiphertextStream is the streaming sibling of FetchCiphertext,
// for chunked (v2.0) files where the ciphertext must NOT be buffered
// whole (it can be hundreds of GB). The caller owns closing the
// returned body. Same security posture as FetchCiphertext: https-only,
// no downgrade redirects, no Bearer header (auth is in the URL).
func (c *Client) FetchCiphertextStream(ctx context.Context, url string) (io.ReadCloser, error) {
	if err := requireSecureURL(url); err != nil {
		return nil, err
	}
	// No overall timeout: a 100 GB download legitimately runs for
	// hours. The context cancels it, and TCP failures surface as read
	// errors in the decrypt loop.
	dl := &http.Client{CheckRedirect: noDowngradeRedirect}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building download request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := dl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, &APIError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("GET %s: storage backend returned %d", url, resp.StatusCode),
		}
	}
	return resp.Body, nil
}

func (c *Client) FetchCiphertext(ctx context.Context, url string) ([]byte, error) {
	if err := requireSecureURL(url); err != nil {
		return nil, err
	}
	// A separate, longer-timeout client. The default 30s on the
	// JSON client is too tight for multi-MB downloads; bump to
	// 10 min which covers anything reasonable while still bounding
	// hangs. Refuse https→http redirects so a presigned URL can't be
	// bounced onto a cleartext hop.
	dl := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: noDowngradeRedirect}

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCiphertextResponse))
	if err != nil {
		return nil, fmt.Errorf("reading ciphertext: %w", err)
	}
	if int64(len(body)) == maxCiphertextResponse {
		return nil, fmt.Errorf("download exceeds the maximum supported size (%d bytes)", int64(maxCiphertextResponse))
	}
	return body, nil
}
