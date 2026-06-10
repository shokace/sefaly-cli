package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/shokace/sefaly-cli/internal/ui"
	"github.com/spf13/cobra"
)

var cpOverwrite bool

func init() {
	rootCmd.AddCommand(cpCmd)
	cpCmd.Flags().BoolVar(&cpOverwrite, "overwrite", false,
		"Replace an existing file with the same name instead of keeping both (auto-suffixed).")
}

var cpCmd = &cobra.Command{
	Use:     "cp <src> <dst>",
	Aliases: []string{"copy"},
	Short:   "Copy a file",
	Long: `Copy a file to another location in your account. The copy is made
server-side — the encrypted bytes and the wrapped key are reused as-is,
so the plaintext is never re-transmitted.

  sef cp report.pdf Documents          # copy into Documents/ (same name)
  sef cp report.pdf report-copy.pdf    # copy + rename
  sef cp a/x.txt b/y.txt               # copy across folders + rename

Folder copy isn't supported (same as the web app — it needs a recursive
server-side walk that doesn't exist yet). Copy the files you need, or use
the web app's share→copy flow.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcArg, dstArg := args[0], args[1]

		_, privKey, client, err := authedClient()
		if err != nil {
			return err
		}
		defer zero(privKey)

		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		tree, err := client.Tree(ctx)
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("fetching file tree: %w", err)
		}

		// Source must be a single existing file. Folders are not copyable.
		srcFileID, srcFolderID, err := resolveDeleteTarget(srcArg, tree, privKey)
		if err != nil {
			return err
		}
		if srcFolderID != "" {
			return errors.New("can't copy a folder yet (the web app doesn't either) — copy the files inside it")
		}

		// Destination: existing folder → copy into (keep name); else
		// (parent, newName) → copy into parent + rename.
		destParent, newName, err := resolveMoveDestination(dstArg, tree, privKey)
		if err != nil {
			return err
		}

		// The locate the source row (its key is reused for the copy + any
		// rename) and its current name.
		var src *api.File
		for i := range tree.Files {
			if tree.Files[i].ID == srcFileID {
				src = &tree.Files[i]
				break
			}
		}
		if src == nil {
			return errors.New("source file not found")
		}
		srcName, err := fileDisplayName(*src, privKey)
		if err != nil {
			return fmt.Errorf("reading source name: %w", err)
		}

		// What the copy should be called, then resolve any collision in
		// the destination. excludeID is "" because the original stays put,
		// so the copy must not reuse its name.
		desired := newName
		if desired == "" {
			desired = srcName
		}
		finalName, overwriteID, suffixed := resolveNameCollision(tree, destParent, desired, "", privKey, cpOverwrite)
		if suffixed {
			fmt.Printf("  %q already exists there — copying as %q (use --overwrite to replace)\n", desired, finalName)
		}

		newID, err := client.DuplicateFile(ctx, srcFileID, destParent)
		if err != nil {
			if api.IsStatus(err, 413) {
				return errors.New("copy would exceed your storage quota — free up space or upgrade")
			}
			return fmt.Errorf("copying: %w", err)
		}

		// DuplicateFile reuses the source's encrypted name, so rename the
		// copy whenever the final name differs from the source's name.
		if finalName != srcName {
			fileKey, err := cryptox.UnwrapFileKey(privKey, src.EncapsulatedKey, src.EncryptedFileKey, src.KeyWrapNonce())
			if err != nil {
				return fmt.Errorf("copied, but renaming failed (unwrap): %w", err)
			}
			defer zero(fileKey)
			encName, nonce, err := cryptox.EncryptNameWithKey(finalName, fileKey)
			if err != nil {
				return fmt.Errorf("copied, but renaming failed (encrypt): %w", err)
			}
			if err := client.PatchFile(ctx, newID, map[string]interface{}{
				"encryptedFilename": encName,
				"filenameNonce":     nonce,
			}); err != nil {
				return fmt.Errorf("copied, but renaming failed: %w", err)
			}
		}

		// With --overwrite, drop the file we replaced (after the copy lands).
		if overwriteID != "" {
			if err := client.DeleteFile(ctx, overwriteID); err != nil {
				fmt.Fprintln(os.Stderr, ui.Warn_(fmt.Sprintf("copied, but couldn't remove the previous %q: %v", desired, err)))
			}
		}

		fmt.Println(ui.Success_(fmt.Sprintf("Copied %s → %s", srcArg, dstArg)))
		return nil
	},
}
