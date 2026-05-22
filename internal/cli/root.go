// Package cli wires the user-facing commands to the underlying
// api / cryptox / creds packages. Each command lives in its own
// file (login.go, logout.go, whoami.go, …) and registers itself
// with the root command at init time.
package cli

import (
	"fmt"
	"os"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/spf13/cobra"
)

// Version is the CLI's reported version. Overwritten at build time
// via -ldflags "-X github.com/shokace/sefaly-cli/internal/cli.Version=v0.1.0".
// `dev` is what you see when running `go build` locally without
// ldflags.
var Version = "dev"

// apiBaseURL is the `--api` flag's value, resolved per invocation.
// Empty means "use the stored creds' URL, or the default if not
// signed in". Read by each command via resolveBaseURL() so the
// behavior is consistent.
var apiBaseURL string

var rootCmd = &cobra.Command{
	Use:   "sefaly",
	Short: "End-to-end encrypted cloud storage from your terminal.",
	Long: `Sefaly's command-line client.

Files are encrypted in this shell before they leave the machine.
The server never has the keys to decrypt them.

Start with:    sefaly login
Check status:  sefaly whoami
Sign out:      sefaly logout

More at https://www.sefaly.com.`,
	SilenceUsage:  true, // don't dump --help on every error; the error message is enough
	SilenceErrors: true, // we print our own
}

func init() {
	rootCmd.PersistentFlags().StringVar(&apiBaseURL, "api", "",
		"Override the API base URL (default: stored creds, then "+api.DefaultBaseURL+
			"). Also honors $SEFALY_API_URL.")

	rootCmd.Version = Version

	// User-Agent header includes the version so server-side logs and
	// rate limits can distinguish CLI traffic by client version.
	api.UserAgent = "sefaly-cli/" + Version
}

// Execute is the entrypoint. Returns the process exit code; callers
// (i.e. main) should pass that to os.Exit.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}

// resolveBaseURL returns the API base URL the current invocation
// should talk to. Precedence (highest first):
//
//  1. --api flag
//  2. $SEFALY_API_URL env var
//  3. The URL stored alongside the user's credentials (so a previous
//     `sefaly --api … login` is sticky for subsequent commands)
//  4. The compiled-in default (https://www.sefaly.com)
//
// `storedURL` is the value the caller pulled from creds — empty if
// the user isn't signed in. Kept as an argument rather than a creds
// import so unauth'd commands (login) can call this too.
func resolveBaseURL(storedURL string) string {
	if apiBaseURL != "" {
		return apiBaseURL
	}
	if env := os.Getenv("SEFALY_API_URL"); env != "" {
		return env
	}
	if storedURL != "" {
		return storedURL
	}
	return api.DefaultBaseURL
}
