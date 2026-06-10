package cli

import (
	"fmt"

	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/ui"
)

// statusLine builds the contextual line shown under the banner: the
// signed-in identity, or a nudge to log in. Best-effort — never errors.
func statusLine() string {
	c, err := creds.Load()
	if err != nil || c == nil || c.Email == "" {
		return ui.Mutedf("Not signed in. ") + ui.Faintf("Run ") + ui.Accentf("sef login") + ui.Faintf(" to get started.")
	}
	who := ui.Mutedf("Signed in as ") + ui.Fg(c.Email)
	if c.DeviceName != "" {
		who += ui.Faintf("  ·  " + c.DeviceName)
	}
	return who
}

// printWelcome renders the full first-run banner + a styled command
// overview. Shown when `sef` is run with no subcommand.
func printWelcome() {
	fmt.Print(ui.Banner(Version, statusLine()))

	rows := [][2]string{
		{"sef ls [path]", "List files and folders"},
		{"sef put <file>…", "Upload + encrypt files"},
		{"sef get <path>", "Download + decrypt a file"},
		{"sef cp <src> <dst>", "Copy a file or folder"},
		{"sef mv <src> <dst>", "Move or rename"},
		{"sef mkdir <path>", "Create a folder"},
		{"sef rm <path>", "Move to Trash"},
		{"sef share <path>", "Create a share link or invite"},
		{"sef info <path>", "Show file / folder details"},
		{"sef trash", "List / restore / empty Trash"},
		{"sef shell", "Interactive cloud session"},
	}
	fmt.Println(ui.Heading("  Commands"))
	fmt.Println(ui.KV(rows))
	fmt.Println()
	fmt.Println("  " + ui.Faintf("Run ") + ui.Accentf("sef <command> --help") + ui.Faintf(" for details, or ") + ui.Accentf("sef help") + ui.Faintf(" for everything."))
	fmt.Println()
}
