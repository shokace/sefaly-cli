package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/spf13/cobra"
)

var mvOverwrite bool

func init() {
	rootCmd.AddCommand(mvCmd)
	mvCmd.Flags().BoolVar(&mvOverwrite, "overwrite", false,
		"Replace a file with the same name at the destination instead of keeping both (auto-suffixed).")
}

var mvCmd = &cobra.Command{
	Use:     "mv <src> <dst>",
	Aliases: []string{"move", "rename"},
	Short:   "Move or rename a file or folder",
	Long: `Move or rename a file or folder.

  sef mv old.txt new.txt                  # rename
  sef mv report.pdf Documents             # move into Documents/
  sef mv Photos/IMG.jpg Archive/IMG.jpg   # move + rename in one step
  sef mv Photos Pictures                  # rename a folder
  sef mv Photos Archive                   # move folder into Archive/
                                          # (if Archive exists)
                                          # OR rename Photos to Archive
                                          # (if Archive doesn't)

If <dst> resolves to an existing folder, <src> is moved INTO it
(keeping its current name). Otherwise <src> is moved + renamed to
<dst>. Files are renamed encrypted-end-to-end: the new name is
encrypted client-side under the existing file key and the server
never sees the plaintext.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcArg, dstArg := args[0], args[1]

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

		ctxTree, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		tree, err := client.Tree(ctxTree)
		cancel()
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("fetching file tree: %w", err)
		}

		// Resolve src first — must point at a single existing file
		// or folder.
		srcFileID, srcFolderID, err := resolveDeleteTarget(srcArg, tree, privKey)
		if err != nil {
			return err
		}

		// Decide the destination's parent + final-name. Two cases:
		// (a) dst exists as a folder → that folder is the new parent,
		//     name stays the same.
		// (b) dst doesn't exist → split into (parentPath, newName);
		//     parent must exist; newName is the rename target.
		newParent, newName, err := resolveMoveDestination(dstArg, tree, privKey)
		if err != nil {
			return err
		}

		ctxOp, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()

		switch {
		case srcFileID != "":
			if err := moveFile(ctxOp, client, tree, privKey, srcFileID, newParent, newName); err != nil {
				return err
			}
		case srcFolderID != "":
			if err := moveFolder(ctxOp, client, tree, privKey, srcFolderID, newParent, newName); err != nil {
				return err
			}
		}

		fmt.Printf("  ✓ %s → %s\n", srcArg, dstArg)
		return nil
	},
}

// resolveMoveDestination figures out what (parentID, newName) the
// move should land at:
//
//   - dst is an existing folder           → parent=dst, name="" (keep src's name)
//   - dst doesn't exist, parent path does → parent=that, name=last segment
//   - dst exists as a file                → error (rm + mv yourself)
//
// An empty `newName` returned means "keep the source's current name".
func resolveMoveDestination(
	dst string,
	tree *api.TreeResponse,
	privKey []byte,
) (parentID *string, newName string, err error) {
	dst = strings.Trim(dst, "/")
	if dst == "" {
		// "mv x ''" or "mv x /" — interpret as "move to root", keep name.
		return nil, "", nil
	}

	// Try dst-as-folder first. If it resolves, we're doing a move-
	// into.
	if folderID, ferr := resolvePath(dst, tree.Folders, privKey); ferr == nil {
		// Refuse to move a folder into one of its own descendants —
		// catches that here too rather than relying on the server
		// to bounce it.
		return folderID, "", nil
	}

	// dst doesn't resolve as a folder. Split into (parent, last).
	parts := strings.Split(dst, "/")
	last := parts[len(parts)-1]
	parentPath := strings.Join(parts[:len(parts)-1], "/")

	parent, perr := resolvePath(parentPath, tree.Folders, privKey)
	if perr != nil {
		return nil, "", fmt.Errorf(
			"destination %q: %w (and no folder by that name exists either)",
			dst, perr,
		)
	}

	// A same-named file at the destination is NOT an error here — the
	// caller (moveFile) resolves it by auto-suffixing or, with
	// --overwrite, replacing.
	return parent, last, nil
}

// moveFile issues PATCH /api/files/:id with the right combination
// of folderId + encryptedFilename. Caller has already resolved the
// destination, so we just translate that into wire fields.
func moveFile(
	ctx context.Context,
	client *api.Client,
	tree *api.TreeResponse,
	privKey []byte,
	fileID string,
	newParent *string,
	newName string,
) error {
	// Find the source file in the tree to grab its current folder
	// and (if renaming) its wrap material.
	var src *api.File
	for i := range tree.Files {
		if tree.Files[i].ID == fileID {
			src = &tree.Files[i]
			break
		}
	}
	if src == nil {
		return errors.New("file disappeared from the tree between resolution and move")
	}

	body := make(map[string]interface{}, 3)

	// Move part: include folderId only if it's actually changing.
	// The server's `hasOwnProperty.has('folderId')` check treats
	// "present-and-same" as a no-op move (no-op fan-out logic), so
	// including it would be safe but noisy.
	currentParent := src.FolderID
	if !samePtrString(currentParent, newParent) {
		if newParent == nil {
			body["folderId"] = nil
		} else {
			body["folderId"] = *newParent
		}
	}

	// Name part. The desired name is the explicit rename target, or the
	// source's current name when moving into a folder. Resolve any
	// collision at the destination (auto-suffix, or --overwrite to
	// replace), then re-encrypt the name only if it actually changes.
	srcName, err := fileDisplayName(*src, privKey)
	if err != nil {
		return fmt.Errorf("reading source name: %w", err)
	}
	desired := newName
	if desired == "" {
		desired = srcName
	}
	finalName, overwriteID, suffixed := resolveNameCollision(tree, newParent, desired, fileID, privKey, mvOverwrite)
	if suffixed {
		fmt.Printf("  a file named %q already exists there — moving as %q (use --overwrite to replace)\n", desired, finalName)
	}

	if finalName != srcName {
		fileKey, err := cryptox.UnwrapFileKey(
			privKey,
			src.EncapsulatedKey,
			src.EncryptedFileKey,
			src.KeyWrapNonce(),
		)
		if err != nil {
			return fmt.Errorf("unwrapping file key for rename: %w", err)
		}
		defer zero(fileKey)
		encName, nonce, err := cryptox.EncryptNameWithKey(finalName, fileKey)
		if err != nil {
			return fmt.Errorf("encrypting new filename: %w", err)
		}
		body["encryptedFilename"] = encName
		body["filenameNonce"] = nonce
	}

	if len(body) == 0 {
		return errors.New("nothing to do — source and destination are the same")
	}

	if err := client.PatchFile(ctx, fileID, body); err != nil {
		return err
	}
	// With --overwrite, drop the file we replaced (after the move lands).
	if overwriteID != "" {
		if err := client.DeleteFile(ctx, overwriteID); err != nil {
			return fmt.Errorf("moved, but couldn't remove the replaced %q: %w", desired, err)
		}
	}
	return nil
}

// moveFolder issues PATCH /api/folders/:id with the right
// combination of parentId + encryptedName. Same shape as moveFile
// but folder-flavoured.
func moveFolder(
	ctx context.Context,
	client *api.Client,
	tree *api.TreeResponse,
	privKey []byte,
	folderID string,
	newParent *string,
	newName string,
) error {
	if newParent != nil && *newParent == folderID {
		return errors.New("can't move a folder into itself")
	}

	var src *api.Folder
	for i := range tree.Folders {
		if tree.Folders[i].ID == folderID {
			src = &tree.Folders[i]
			break
		}
	}
	if src == nil {
		return errors.New("folder disappeared from the tree between resolution and move")
	}

	// Walk ancestors of newParent to reject "move A into A's
	// descendant" before sending the request — the server also
	// rejects this but we get a friendlier error.
	if newParent != nil {
		if isDescendantOf(*newParent, folderID, tree.Folders) {
			return errors.New("can't move a folder into one of its own descendants")
		}
	}

	body := make(map[string]interface{}, 3)

	if !samePtrString(src.ParentID, newParent) {
		if newParent == nil {
			body["parentId"] = nil
		} else {
			body["parentId"] = *newParent
		}
	}

	if newName != "" {
		// Folder rename uses the existing per-folder name key. Same
		// unwrap path as folderDisplayName: ML-KEM decapsulate the
		// nameKeyEncapsulated + AES-unwrap to recover the key.
		if src.NameKeyEncapsulated == nil ||
			src.NameKeyWrapped == nil ||
			src.NameKeyWrapNonce == nil {
			// Legacy plaintext folder. Renaming via the plaintext
			// `name` field still works; the server keeps both
			// columns mutually exclusive and accepts plaintext on
			// folders that don't yet have an encrypted name.
			body["name"] = newName
		} else {
			nameKey, err := cryptox.UnwrapFileKey(
				privKey,
				*src.NameKeyEncapsulated,
				*src.NameKeyWrapped,
				*src.NameKeyWrapNonce,
			)
			if err != nil {
				return fmt.Errorf("unwrapping folder name key: %w", err)
			}
			defer zero(nameKey)
			encName, nonce, err := cryptox.EncryptNameWithKey(newName, nameKey)
			if err != nil {
				return fmt.Errorf("encrypting new folder name: %w", err)
			}
			body["encryptedName"] = encName
			body["nameNonce"] = nonce
		}
	}

	if len(body) == 0 {
		return errors.New("nothing to do — source and destination are the same")
	}

	return client.PatchFolder(ctx, folderID, body)
}

// isDescendantOf returns true if `candidateID` is a (transitive)
// descendant of `ancestorID` in the folder tree. Used to reject
// `sef mv parent parent/child` before the server has to.
func isDescendantOf(candidateID, ancestorID string, folders []api.Folder) bool {
	parentOf := make(map[string]*string, len(folders))
	for _, f := range folders {
		parentOf[f.ID] = f.ParentID
	}
	cur := parentOf[candidateID]
	for cur != nil {
		if *cur == ancestorID {
			return true
		}
		cur = parentOf[*cur]
	}
	return false
}

func samePtrString(a, b *string) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}
