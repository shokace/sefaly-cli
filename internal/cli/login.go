package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVar(&loginDeviceName, "name", "",
		"Label for this device in the Connected Devices panel. "+
			"Prompted interactively if not provided.")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false,
		"Don't try to open the verification URL in a browser. "+
			"Useful on headless machines.")
}

var (
	loginDeviceName string
	loginNoBrowser  bool
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authorize this machine against your Sefaly account",
	Long: `Starts a device-authorization flow:

  1. Prints a short user code + a URL.
  2. You open the URL in any browser where you're signed in to
     Sefaly, type the code (or click an approval link), and approve.
  3. This CLI picks up an end-to-end-encrypted access token and your
     private encryption key, decrypts them locally, and stashes them
     in your OS keychain.

The server never sees the raw access token or your private key in
plaintext. The token can be revoked any time from the Connected
Devices panel on the web app.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Minute)
		defer cancel()

		// Honor `--api` / $SEFALY_API_URL but ignore any stored URL —
		// this is a fresh login flow; the user might be re-pointing
		// to a different host.
		baseURL := resolveBaseURL("")
		client := api.New(baseURL, "")

		// Step 1: ephemeral keypair. Lives only for this login.
		ephKey, err := cryptox.GenerateEphemeralKey()
		if err != nil {
			return fmt.Errorf("generating ephemeral keypair: %w", err)
		}

		// Step 2: ask the server for a device code.
		dc, err := client.StartDeviceFlow(ctx, ephKey.PublicKeyBase64())
		if err != nil {
			return fmt.Errorf("starting device flow: %w", err)
		}

		// Step 3: show the code + URL, try to open the browser.
		fmt.Printf("\n  To authorize this device, open:\n    %s\n\n", dc.VerificationURIComplete)
		fmt.Printf("  And confirm the code:\n    %s\n\n", dc.UserCode)

		if !loginNoBrowser {
			if err := openBrowser(dc.VerificationURIComplete); err != nil {
				// Not fatal — the URL is printed above and the user
				// can open it themselves.
				fmt.Printf("  (couldn't open the browser automatically: %v)\n\n", err)
			}
		}

		fmt.Println("  Waiting for approval…")

		// Step 4: poll until APPROVED / DENIED / EXPIRED / error.
		interval := time.Duration(dc.Interval) * time.Second
		if interval < time.Second {
			interval = 3 * time.Second
		}
		var approved *api.PollResponse
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("login timed out before approval")
			case <-time.After(interval):
			}

			poll, err := client.PollDeviceFlow(ctx, dc.DeviceCode)
			if err != nil {
				// 429 from the rate limiter just means we polled too
				// fast — slow down and continue. Anything else is
				// terminal.
				if api.IsStatus(err, 429) {
					interval *= 2
					continue
				}
				if api.IsStatus(err, 404) {
					return errors.New("login session not found — it may have expired before approval")
				}
				return fmt.Errorf("polling: %w", err)
			}

			switch poll.Status {
			case "pending":
				continue
			case "approved":
				approved = poll
			case "denied":
				return errors.New("request denied in the browser")
			case "expired":
				return errors.New("the code expired before approval — run `sef login` again")
			default:
				return fmt.Errorf("unexpected poll status: %q", poll.Status)
			}
			if approved != nil {
				break
			}
		}

		// Sanity-check: every field we need to proceed.
		if approved.User == nil ||
			approved.KemCt == "" ||
			approved.WrappedTokenCt == "" ||
			approved.WrappedTokenNonce == "" ||
			approved.EncryptedPrivateKey == "" {
			return errors.New("approval response missing fields — try logging in again")
		}

		// Step 5: unwrap the access token with our ephemeral private
		// key. This is the moment the CLI proves it was the
		// legitimate target of the wrap — only the holder of the
		// ephemeral private key can decapsulate.
		rawToken, err := ephKey.UnwrapAccessToken(
			approved.KemCt,
			approved.WrappedTokenCt,
			approved.WrappedTokenNonce,
		)
		if err != nil {
			return fmt.Errorf("unwrapping access token: %w", err)
		}

		// Step 6: verify the entire chain by actually decrypting the
		// private key. If this fails, something downstream (upload,
		// download) would also fail; better to surface it now while
		// the user still expects a sign-in error.
		privKey, kemType, err := cryptox.DecryptPrivateKey(
			rawToken,
			approved.User.ID,
			approved.EncryptedPrivateKey,
		)
		if err != nil {
			return fmt.Errorf("verifying private key: %w", err)
		}
		// Zero the plaintext private key — we don't persist it.
		// On-demand decryption from the stored ciphertext + token is
		// what subsequent file commands do.
		for i := range privKey {
			privKey[i] = 0
		}

		// Step 7: persist.
		c := &creds.Credentials{
			APIBaseURL:          baseURL,
			AccessToken:         rawToken,
			UserID:              approved.User.ID,
			Email:               approved.User.Email,
			EncryptedPrivateKey: approved.EncryptedPrivateKey,
			KemType:             kemType,
			DeviceName:          approved.DeviceName,
		}
		usedFallback, err := creds.Save(c)
		if err != nil {
			return fmt.Errorf("saving credentials: %w", err)
		}

		fmt.Printf("\n  Logged in as %s", approved.User.Email)
		if approved.DeviceName != "" {
			fmt.Printf(" (device: %s)", approved.DeviceName)
		}
		fmt.Println(".")
		if usedFallback {
			fmt.Println("  Warning: OS keychain unavailable; credentials saved to ~/.sefaly/credentials.json (chmod 600).")
		}
		return nil
	},
}

// openBrowser tries to open `url` in the user's default browser.
// Best-effort — failure isn't fatal because we've already printed
// the URL.
func openBrowser(url string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
		args = []string{url}
	case "windows":
		name = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	default: // linux, *bsd
		name = "xdg-open"
		args = []string{url}
	}
	return exec.Command(name, args...).Start()
}
