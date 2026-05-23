package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(whoamiCmd)
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the signed-in account",
	Long: `Prints the email of the signed-in account, the API host
the credentials are scoped to, and the device label (if set).

Also hits /api/auth/me on the server to confirm the token still
works — so if the token was revoked from the web app or expired,
whoami will report it instead of silently lying.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		stored, err := creds.Load()
		if err != nil {
			if errors.Is(err, creds.ErrNotFound) {
				return errors.New("not signed in — run `sef login`")
			}
			return fmt.Errorf("reading credentials: %w", err)
		}

		// Print local view first so an offline machine still gets
		// useful output if the network call fails.
		fmt.Printf("  %s\n", stored.Email)
		if stored.DeviceName != "" {
			fmt.Printf("    Device: %s\n", stored.DeviceName)
		}
		fmt.Printf("    API:    %s\n", stored.APIBaseURL)

		// Server check. Use the stored baseURL unless `--api`
		// overrides — switching hosts via the flag without
		// re-logging-in won't give a useful answer anyway.
		baseURL := resolveBaseURL(stored.APIBaseURL)
		client := api.New(baseURL, stored.AccessToken)

		ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer cancel()
		me, err := client.Me(ctx)
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — it may have been revoked. Run `sef login` to re-authorize.")
			}
			// Soft warning rather than a hard error — useful info
			// still printed above, network might just be flaky.
			fmt.Printf("    (couldn't reach the server: %v)\n", err)
			return nil
		}
		fmt.Printf("    Tier:   %s\n", me.Tier)
		if me.TotpEnabled {
			fmt.Printf("    2FA:    enabled\n")
		}
		return nil
	},
}
