package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/ui"
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

		// Server check. Use the stored baseURL unless `--api`
		// overrides — switching hosts via the flag without
		// re-logging-in won't give a useful answer anyway.
		baseURL, err := resolveBaseURL(stored.APIBaseURL)
		if err != nil {
			return err
		}
		client := api.New(baseURL, stored.AccessToken)

		ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer cancel()
		me, meErr := client.Me(ctx)
		if api.IsStatus(meErr, 401) {
			return errors.New("server rejected your token — it may have been revoked. Run `sef login` to re-authorize.")
		}

		// Local view first so it's useful even if the server is
		// unreachable; enrich with server data when we have it.
		rows := [][2]string{{"Email", ui.Fg(stored.Email)}}
		if stored.DeviceName != "" {
			rows = append(rows, [2]string{"Device", stored.DeviceName})
		}
		if meErr == nil {
			twofa := "disabled"
			if me.TotpEnabled {
				twofa = fmt.Sprintf("enabled · %d backup code(s) left", me.TotpBackupCodesRemaining)
			}
			verified := "no"
			if me.EmailVerifiedAt != "" {
				verified = "yes"
			}
			rows = append(rows,
				[2]string{"Tier", me.Tier},
				[2]string{"Storage", trimSpace(humanSize(me.StorageUsedBytes)) + " used"},
				[2]string{"2FA", twofa},
				[2]string{"Email verified", verified},
			)
		}
		rows = append(rows, [2]string{"API", stored.APIBaseURL})

		fmt.Println()
		fmt.Println(ui.Heading("  Account"))
		fmt.Println(ui.KV(rows))
		if meErr != nil {
			fmt.Println("  " + ui.Warn_(fmt.Sprintf("couldn't reach the server: %v", meErr)))
		}
		fmt.Println()
		return nil
	},
}
