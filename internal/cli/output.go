package cli

import (
	"encoding/json"
	"fmt"
	"os"
)

// jsonOutput is the global --json flag: when set, commands print a
// machine-readable JSON document to stdout instead of formatted text, so
// agents and scripts can parse results reliably. Registered in root.go.
var jsonOutput bool

// emitJSON marshals v as indented JSON to stdout. Commands call this on
// the --json path and return early.
func emitJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(b))
	return nil
}
