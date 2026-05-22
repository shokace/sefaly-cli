package cli

import (
	"errors"
	"fmt"

	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(logoutCmd)
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear this device's local Sefaly credentials",
	Long: `Removes the access token and encrypted private key from the
OS keychain (or the fallback file).

This does NOT revoke the token server-side — the AccessToken row
keeps existing on the server until you either explicitly revoke it
from the "Connected devices" panel on the web app, or it ages out
(90-day TTL on device tokens).

If you suspect this machine is compromised, revoke from the web app
in addition to running this command.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Be friendly if nothing is stored — `logout` should be
		// idempotent so scripts can run it without worrying.
		existing, err := creds.Load()
		if err != nil && !errors.Is(err, creds.ErrNotFound) {
			return fmt.Errorf("reading stored credentials: %w", err)
		}
		if err := creds.Clear(); err != nil {
			return fmt.Errorf("clearing credentials: %w", err)
		}
		if existing != nil {
			fmt.Printf("  Cleared credentials for %s.\n", existing.Email)
		} else {
			fmt.Println("  No credentials to clear.")
		}
		fmt.Println("  Tip: revoke this device from the Connected Devices panel on the web app to kill its server-side token too.")
		return nil
	},
}
