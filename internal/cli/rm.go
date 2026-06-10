package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(rmCmd)
	rmCmd.Flags().BoolVarP(&rmRecursive, "recursive", "r", false,
		"Allow deleting folders (otherwise refuses anything that isn't a single file).")
	rmCmd.Flags().BoolVarP(&rmForce, "force", "f", false,
		"Skip the confirmation prompt.")
}

var (
	rmRecursive bool
	rmForce     bool
)

var rmCmd = &cobra.Command{
	Use:     "rm <path>...",
	Aliases: []string{"remove", "delete"},
	Short:   "Delete files or folders",
	Long: `Delete one or more files (or folders, with -r) from your account.

Mirrors Unix rm conventions:

  sef rm report.pdf              # delete a single file
  sef rm Photos/IMG_1234.jpg     # delete by nested path
  sef rm -r OldStuff             # delete a folder + everything inside
  sef rm -f throwaway.txt        # skip the confirmation prompt
  sef rm a.txt b.txt c.txt       # multi-file

Deleted files go to Trash and are kept for 30 days — restore or purge
them with ` + "`sef trash`" + `. Folder deletion is permanent and immediate (no
folder trash yet). If you delete a shared folder, recipients lose access
in the same transaction.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
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
		defer zero(privKey)

		baseURL, err := resolveBaseURL(stored.APIBaseURL)
		if err != nil {
			return err
		}
		client := api.New(baseURL, stored.AccessToken)

		// One tree fetch shared across every arg — far cheaper than
		// per-arg lookups, and the consistency is fine: a tree race
		// (folder vanished between fetch and delete) just produces
		// a 404 from the per-arg DELETE which we surface plainly.
		ctxTree, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		tree, err := client.Tree(ctxTree)
		cancel()
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("fetching file tree: %w", err)
		}

		// Resolve every target up front so a bad path fails before we
		// delete anything. Avoids the "deleted 2 of 3, then errored"
		// half-applied state from the user's perspective.
		type target struct {
			path     string
			fileID   string // exactly one of fileID/folderID is set
			folderID string
		}
		targets := make([]target, 0, len(args))
		for _, arg := range args {
			fileID, folderID, err := resolveDeleteTarget(arg, tree, privKey)
			if err != nil {
				return err
			}
			if folderID != "" && !rmRecursive {
				return fmt.Errorf("%q is a folder — pass -r to delete it (and its contents)", arg)
			}
			targets = append(targets, target{path: arg, fileID: fileID, folderID: folderID})
		}

		// Single confirmation for the whole batch — feels less
		// nagging than one per file, and the rm <list> ergonomics
		// people expect work that way.
		if !rmForce {
			ok, err := confirm(fmt.Sprintf("Delete %d item%s? This cannot be undone. [y/N] ",
				len(targets), pluralS(len(targets))))
			if err != nil {
				return err
			}
			if !ok {
				fmt.Println("  Cancelled.")
				return nil
			}
		}

		var hadError bool
		for _, t := range targets {
			ctxDel, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			var err error
			if t.fileID != "" {
				err = client.DeleteFile(ctxDel, t.fileID)
			} else {
				err = client.DeleteFolder(ctxDel, t.folderID)
			}
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error deleting %s: %v\n", t.path, err)
				hadError = true
				continue
			}
			fmt.Printf("  ✓ Deleted %s\n", t.path)
		}
		if hadError {
			return errors.New("one or more deletions failed")
		}
		return nil
	},
}

// resolveDeleteTarget walks the path and decides whether it points
// at a file or a folder. Returns exactly one of (fileID, folderID)
// set. Errors on no-match. If both a file and folder exist with the
// same name in the same parent (which shouldn't happen but is
// schema-legal), refuses with an explicit ambiguity error rather
// than silently picking one.
func resolveDeleteTarget(
	path string,
	tree *api.TreeResponse,
	privKey []byte,
) (fileID, folderID string, err error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return "", "", errors.New("can't delete the root folder")
	}
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	parentPath := strings.Join(parts[:len(parts)-1], "/")

	parentID, err := resolvePath(parentPath, tree.Folders, privKey)
	if err != nil {
		return "", "", err
	}

	// Look for a folder with this name in the parent.
	foldersByParent := indexFoldersByParent(tree.Folders)
	for _, f := range foldersByParent[strPtrKey(parentID)] {
		name, nerr := folderDisplayName(f, privKey)
		if nerr != nil {
			continue
		}
		if name == last {
			if folderID != "" {
				return "", "", fmt.Errorf("multiple folders named %q in this parent — disambiguate via the web UI", last)
			}
			folderID = f.ID
		}
	}

	// Look for a file with this name in the parent.
	filesByParent := indexFilesByParent(tree.Files)
	for _, f := range filesByParent[strPtrKey(parentID)] {
		name, nerr := fileDisplayName(f, privKey)
		if nerr != nil {
			continue
		}
		if name == last {
			if fileID != "" {
				return "", "", fmt.Errorf("multiple files named %q in this folder — disambiguate via the web UI", last)
			}
			fileID = f.ID
		}
	}

	switch {
	case folderID != "" && fileID != "":
		return "", "", fmt.Errorf(
			"both a file and a folder named %q exist here — delete one via the web UI first",
			last,
		)
	case folderID == "" && fileID == "":
		return "", "", fmt.Errorf("no such file or folder: %q", path)
	}
	return fileID, folderID, nil
}

func confirm(prompt string) (bool, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("reading confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
