package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/shokace/sefaly-cli/internal/tui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	rootCmd.AddCommand(guiCmd)

	// Wire the bare-`sef` default. When no subcommand is provided
	// and stdin is a TTY, launch the GUI. In pipes / CI / `sef >
	// file`, fall back to printing help — predictable, scriptable.
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			// Unknown positional arg — let cobra's normal "unknown
			// command" error fire by returning that here.
			return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
		}
		if !isInteractive() {
			return cmd.Help()
		}
		return runGUI(cmd)
	}
}

var guiCmd = &cobra.Command{
	Use:   "gui",
	Short: "Launch the two-pane file manager TUI",
	Long: `Opens a Midnight-Commander-style split view: the local
filesystem on the left, your Sefaly account on the right. Tab
switches focus between panes; arrow keys (or WASD) navigate;
Enter descends into a folder; Backspace ascends.

Phase A — read-only browsing. Transfers (upload / download) and
mutations (mkdir / rm / rename) land in follow-up releases.

Bare ` + "`sef`" + ` does the same thing in an interactive terminal;
` + "`sef gui`" + ` is the explicit form that also works inside scripts
that genuinely want the TUI.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGUI(cmd)
	},
}

// runGUI loads credentials, decrypts the user's private key, and
// hands control to the Bubble Tea program. Wraps the
// teardown ("scrub privKey, restore terminal") so callers don't
// have to.
func runGUI(cmd *cobra.Command) error {
	if !isInteractive() {
		return errors.New("`sef gui` needs an interactive terminal (stdin must be a TTY)")
	}

	stored, err := creds.Load()
	if err != nil {
		if errors.Is(err, creds.ErrNotFound) {
			return errors.New("not signed in — run `sef login`")
		}
		return fmt.Errorf("reading credentials: %w", err)
	}

	privKey, _, err := cryptox.DecryptPrivateKey(
		stored.AccessToken,
		stored.UserID,
		stored.EncryptedPrivateKey,
	)
	if err != nil {
		return fmt.Errorf("decrypting private key (re-login may help): %w", err)
	}
	// Defensive: even if the model is supposed to zero this on
	// quit, scrub it again here when the program exits — covers
	// the panic / signal-exit paths.
	defer func() {
		for i := range privKey {
			privKey[i] = 0
		}
	}()

	publicKey, err := cryptox.PublicKeyFromPrivate(privKey)
	if err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

	baseURL := resolveBaseURL(stored.APIBaseURL)
	client := api.New(baseURL, stored.AccessToken)

	wd, err := os.Getwd()
	if err != nil {
		// Fall back to home dir. Unlikely path — Getwd only fails
		// if the cwd was deleted out from under us.
		wd, _ = os.UserHomeDir()
	}

	model := tui.NewModel(client, privKey, publicKeyB64, wd)

	// AltScreen takes over the terminal (Vim / claude-code style);
	// MouseAllMotion would also work but Phase A is keyboard-only.
	prog := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithContext(cmd.Context()),
	)

	if _, err := prog.Run(); err != nil {
		return fmt.Errorf("TUI: %w", err)
	}
	return nil
}

// isInteractive returns true when stdin is a TTY. Used to decide
// whether bare `sef` launches the GUI or prints help — a pipe /
// CI invocation should never get stuck inside a Bubble Tea event
// loop waiting for input that'll never come.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
