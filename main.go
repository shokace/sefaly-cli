// Command sefaly is the CLI client for Sefaly's end-to-end-encrypted
// cloud storage. See README.md / `sefaly --help` for usage.
package main

import (
	"os"

	"github.com/shokace/sefaly-cli/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
