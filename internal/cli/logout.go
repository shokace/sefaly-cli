package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(logoutCmd)
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke this device's token and clear local credentials",
	Long: `Tells the server to revoke this device's access token, then
removes the token and encrypted private key from the OS keychain (or
the fallback file).

Idempotent: running it twice is fine; running it on a machine with
no stored creds is fine.

If the server can't be reached, local credentials are cleared anyway
— this keeps a "kill this device's access to my account" intent
honoured even when offline. In that case, revoke from the
"Connected devices" panel on the web app once you're online to
finish the job server-side.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		existing, err := creds.Load()
		if err != nil && !errors.Is(err, creds.ErrNotFound) {
			return fmt.Errorf("reading stored credentials: %w", err)
		}

		// Best-effort server-side revoke before the local clear. We
		// run this FIRST so a logged-in user with a working network
		// gets their token revoked atomically with their local wipe;
		// running it after the clear would risk forgetting the
		// AccessToken row if the server call fails (since we've
		// already lost the token by then).
		var serverRevoked bool
		var serverErr error
		if existing != nil && existing.AccessToken != "" {
			baseURL, baseErr := resolveBaseURL(existing.APIBaseURL)
			if baseErr != nil {
				// Don't block local logout on a bad stored URL — clear
				// the credentials below regardless. Just note the
				// server-side revoke can't happen and tell the user.
				serverErr = baseErr
			} else {
				ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
				client := api.New(baseURL, existing.AccessToken)
				serverErr = client.RevokeSelf(ctx)
				cancel()
			}
			// 401 means the token was already invalid server-side
			// (revoked / expired). Treat it as "already done", not an
			// error — `sef logout` after the token's natural death
			// shouldn't complain.
			if serverErr == nil || api.IsStatus(serverErr, 401) {
				serverRevoked = true
				serverErr = nil
			}
		}

		// Always clear locally, regardless of server outcome. A user
		// running `sef logout` on a compromised machine wants the
		// keys gone NOW; we don't gate that on the server being
		// reachable.
		if err := creds.Clear(); err != nil {
			return fmt.Errorf("clearing local credentials: %w", err)
		}

		if existing == nil {
			fmt.Println("  No credentials to clear.")
			return nil
		}

		fmt.Printf("  Cleared local credentials for %s.\n", existing.Email)
		switch {
		case serverRevoked:
			fmt.Println("  Server-side token revoked.")
		case serverErr != nil:
			// Surface the failure but don't return non-zero — the
			// local state IS cleared. Scripts running this in a
			// teardown shouldn't fail the whole pipeline because the
			// server call timed out.
			fmt.Fprintf(os.Stderr, "  Warning: couldn't revoke server-side (%v).\n", serverErr)
			fmt.Fprintln(os.Stderr, "  Revoke from the Connected Devices panel on the web app to finish.")
		}
		return nil
	},
}
