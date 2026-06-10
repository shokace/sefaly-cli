package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/ui"
	"github.com/spf13/cobra"
)

// confirmDestructive prompts (styled) for a yes/no on a destructive
// action, reusing rm.go's confirm reader. Returns true only on "y"/"yes".
func confirmDestructive(question string) bool {
	ok, _ := confirm("  " + ui.Warn_(question) + " " + ui.Faintf("[y/N] "))
	return ok
}

func init() {
	rootCmd.AddCommand(trashCmd)
	trashCmd.AddCommand(trashRestoreCmd, trashRmCmd, trashEmptyCmd)
	trashEmptyCmd.Flags().BoolVarP(&trashForce, "force", "f", false, "Skip the confirmation prompt.")
	trashRmCmd.Flags().BoolVarP(&trashForce, "force", "f", false, "Skip the confirmation prompt.")
}

var trashForce bool

var trashCmd = &cobra.Command{
	Use:   "trash",
	Short: "List, restore, or permanently delete files in Trash",
	Long: `Files deleted with ` + "`sef rm`" + ` go to Trash and are kept for 30
days before they're purged. From here you can see them, restore them, or
delete them for good.

  sef trash                  list everything in Trash
  sef trash restore <name>   restore a file (by name or id)
  sef trash rm <name>        permanently delete a file
  sef trash empty            permanently delete everything in Trash

(Folders are not trashed — deleting a folder is immediate.)`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, privKey, client, err := authedClient()
		if err != nil {
			return err
		}
		defer zero(privKey)

		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		files, err := trashOrAuthErr(client, ctx)
		if err != nil {
			return err
		}
		if jsonOutput {
			type ti struct {
				Name      string `json:"name"`
				ID        string `json:"id"`
				SizeBytes string `json:"sizeBytes"`
				DeletedAt string `json:"deletedAt,omitempty"`
			}
			out := []ti{}
			for _, f := range files {
				name, _ := fileDisplayName(f, privKey)
				da := ""
				if f.DeletedAt != nil {
					da = *f.DeletedAt
				}
				out = append(out, ti{Name: name, ID: f.ID, SizeBytes: f.SizeBytes, DeletedAt: da})
			}
			return emitJSON(out)
		}
		if len(files) == 0 {
			fmt.Println(ui.Mutedf("  Trash is empty."))
			return nil
		}
		fmt.Println()
		fmt.Println(ui.Heading(fmt.Sprintf("  Trash · %d item(s)", len(files))))
		for _, f := range files {
			name, derr := fileDisplayName(f, privKey)
			if derr != nil {
				name = ui.Faintf("(decryption failed)")
			}
			when := ""
			if f.DeletedAt != nil {
				when = ui.Faintf("deleted " + shortTime(*f.DeletedAt))
			}
			fmt.Printf("  %s  %s  %s\n", ui.Faintf(trimSpace(humanSize(f.SizeBytes))), name, when)
		}
		fmt.Println()
		fmt.Println("  " + ui.Faintf("Restore with ") + ui.Accentf("sef trash restore <name>") + ui.Faintf(", or empty with ") + ui.Accentf("sef trash empty") + ui.Faintf("."))
		return nil
	},
}

var trashRestoreCmd = &cobra.Command{
	Use:   "restore <name|id>...",
	Short: "Restore one or more files from Trash",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, privKey, client, err := authedClient()
		if err != nil {
			return err
		}
		defer zero(privKey)
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		files, err := trashOrAuthErr(client, ctx)
		if err != nil {
			return err
		}
		ids, err := matchTrashed(files, args, privKey)
		if err != nil {
			return err
		}
		if err := client.TrashRestore(ctx, ids); err != nil {
			if api.IsStatus(err, 413) {
				return errors.New("restore would exceed your storage quota — free up space first")
			}
			return fmt.Errorf("restoring: %w", err)
		}
		fmt.Println(ui.Success_(fmt.Sprintf("Restored %d file(s).", len(ids))))
		return nil
	},
}

var trashRmCmd = &cobra.Command{
	Use:     "rm <name|id>...",
	Aliases: []string{"delete"},
	Short:   "Permanently delete files from Trash (irreversible)",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, privKey, client, err := authedClient()
		if err != nil {
			return err
		}
		defer zero(privKey)
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		files, err := trashOrAuthErr(client, ctx)
		if err != nil {
			return err
		}
		ids, err := matchTrashed(files, args, privKey)
		if err != nil {
			return err
		}
		if !trashForce && !confirmDestructive(fmt.Sprintf("Permanently delete %d file(s)? This cannot be undone.", len(ids))) {
			fmt.Println(ui.Mutedf("  Cancelled."))
			return nil
		}
		if err := client.TrashDeleteForever(ctx, ids); err != nil {
			return fmt.Errorf("deleting: %w", err)
		}
		fmt.Println(ui.Success_(fmt.Sprintf("Permanently deleted %d file(s).", len(ids))))
		return nil
	},
}

var trashEmptyCmd = &cobra.Command{
	Use:   "empty",
	Short: "Permanently delete everything in Trash (irreversible)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, privKey, client, err := authedClient()
		if err != nil {
			return err
		}
		defer zero(privKey)
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		files, err := trashOrAuthErr(client, ctx)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			fmt.Println(ui.Mutedf("  Trash is already empty."))
			return nil
		}
		ids := make([]string, len(files))
		for i := range files {
			ids[i] = files[i].ID
		}
		if !trashForce && !confirmDestructive(fmt.Sprintf("Permanently delete all %d file(s) in Trash? This cannot be undone.", len(ids))) {
			fmt.Println(ui.Mutedf("  Cancelled."))
			return nil
		}
		if err := client.TrashDeleteForever(ctx, ids); err != nil {
			return fmt.Errorf("emptying Trash: %w", err)
		}
		fmt.Println(ui.Success_(fmt.Sprintf("Emptied Trash (%d file(s)).", len(ids))))
		return nil
	},
}

// trashOrAuthErr fetches the trash list, mapping a 401 to a friendly
// re-login message.
func trashOrAuthErr(client *api.Client, ctx context.Context) ([]api.File, error) {
	files, err := client.TrashList(ctx)
	if err != nil {
		if api.IsStatus(err, 401) {
			return nil, errors.New("server rejected your token — run `sef login` to re-authorize")
		}
		return nil, fmt.Errorf("fetching Trash: %w", err)
	}
	return files, nil
}

// matchTrashed resolves each arg (a decrypted name or a raw file id) to
// a trashed file id, erroring on no-match or an ambiguous name.
func matchTrashed(files []api.File, args []string, privKey []byte) ([]string, error) {
	var ids []string
	for _, arg := range args {
		found := ""
		for i := range files {
			if files[i].ID == arg {
				found = files[i].ID
				break
			}
			name, derr := fileDisplayName(files[i], privKey)
			if derr == nil && name == arg {
				if found != "" {
					return nil, fmt.Errorf("multiple trashed files named %q — use the file id (see `sef trash`)", arg)
				}
				found = files[i].ID
			}
		}
		if found == "" {
			return nil, fmt.Errorf("no trashed file named %q", arg)
		}
		ids = append(ids, found)
	}
	return ids, nil
}
