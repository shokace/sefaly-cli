// Package cli wires the user-facing commands to the underlying
// api / cryptox / creds packages. Each command lives in its own
// file (login.go, logout.go, whoami.go, …) and registers itself
// with the root command at init time.
package cli

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/spf13/cobra"
)

// Version is the CLI's reported version. Overwritten at build time
// via -ldflags "-X github.com/shokace/sefaly-cli/internal/cli.Version=v0.1.0".
// `dev` is what you see when running `go build` locally without
// ldflags.
var Version = "dev"

// binaryName is what the CLI calls itself in usage strings, error
// messages, and `--help`. Match it to the actual filename the build
// produces (see CI + README): the install is `sef`, not `sefaly`.
// Short single-syllable command names are the norm for CLIs people
// type a lot (`gh`, `fly`, `aws`, `kubectl`). The project is still
// "Sefaly" everywhere else — repo name, copyright, brand — only the
// invocable binary is shortened.
const binaryName = "sef"

// apiBaseURL is the `--api` flag's value, resolved per invocation.
// Empty means "use the stored creds' URL, or the default if not
// signed in". Read by each command via resolveBaseURL() so the
// behavior is consistent.
var apiBaseURL string

var rootCmd = &cobra.Command{
	Use:   binaryName,
	Short: "End-to-end encrypted cloud storage from your terminal.",
	Long: `Sefaly's command-line client.

Files are encrypted in this shell before they leave the machine.
The server never has the keys to decrypt them.

Start with:    sef login
Check status:  sef whoami
List files:    sef ls
Sign out:      sef logout

More at https://www.sefaly.com.`,
	SilenceUsage:  true, // don't dump --help on every error; the error message is enough
	SilenceErrors: true, // we print our own
	// Bare `sef` (no subcommand): on an interactive terminal, drop into
	// the cloud shell (banner + REPL). When piped / redirected / in CI,
	// print the branded welcome instead — predictable + scriptable.
	// `--help` and subcommands are unaffected.
	RunE: func(cmd *cobra.Command, args []string) error {
		if isInteractive() {
			return runShell()
		}
		printWelcome()
		return nil
	},
}

// isInteractive reports whether stdin is a terminal (vs a pipe/redirect/
// CI). Drives whether bare `sef` enters the REPL or prints the welcome.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func init() {
	rootCmd.PersistentFlags().StringVar(&apiBaseURL, "api", "",
		"Override the API base URL (default: stored creds, then "+api.DefaultBaseURL+
			"). Also honors $SEFALY_API_URL.")

	rootCmd.Version = Version

	// User-Agent header includes the version so server-side logs and
	// rate limits can distinguish CLI traffic by client version.
	api.UserAgent = binaryName + "/" + Version
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
// The resolved URL MUST use https://, except for loopback hosts
// (localhost, 127.0.0.1, [::1]) which may use http:// for local
// development. Plain http to a non-loopback host would send the
// Bearer access token and the wrapped private key in cleartext,
// which would collapse the zero-knowledge guarantee. Rejecting at
// resolve time means a typo or a phishing prompt
// ("set SEFALY_API_URL=http://...") fails loudly instead of
// silently downgrading the transport.
//
// `storedURL` is the value the caller pulled from creds — empty if
// the user isn't signed in. Kept as an argument rather than a creds
// import so unauth'd commands (login) can call this too.
func resolveBaseURL(storedURL string) (string, error) {
	var resolved string
	switch {
	case apiBaseURL != "":
		resolved = apiBaseURL
	case os.Getenv("SEFALY_API_URL") != "":
		resolved = os.Getenv("SEFALY_API_URL")
	case storedURL != "":
		resolved = storedURL
	default:
		resolved = api.DefaultBaseURL
	}
	if err := validateAPIURL(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// validateAPIURL enforces https:// for any non-loopback host. Local
// dev (http://localhost:3000 and friends) is still allowed because
// nothing is on the wire between cooperating processes on the same
// machine.
func validateAPIURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid API URL %q: %w", s, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Host) {
		return nil
	}
	return fmt.Errorf("API URL must use https:// (got %q). Loopback (localhost, 127.0.0.1, [::1]) may use http://", s)
}

func isLoopback(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	// Strip IPv6 brackets if the URL was bare like [::1] with no port.
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
