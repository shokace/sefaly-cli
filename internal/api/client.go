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
