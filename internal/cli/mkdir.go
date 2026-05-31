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

func init() {
	rootCmd.AddCommand(mkdirCmd)
	mkdirCmd.Flags().BoolVarP(&mkdirParents, "parents", "p", false,
		"Create missing intermediate folders (like `mkdir -p`).")
}

var mkdirParents bool

var mkdirCmd = &cobra.Command{
	Use:     "mkdir <path>...",
	Aliases: []string{"md"},
	Short:   "Create folders",
	Long: `Create one or more folders. Folder names are encrypted
client-side and the server never sees the plaintext.

  sef mkdir Photos
  sef mkdir Photos/2026
  sef mkdir -p Documents/Tax/2026   # creates Documents and Tax if missing
  sef mkdir a b c                    # multi-folder

Without -p, every intermediate folder in the path must already
exist — sef mkdir refuses to create them automatically (matches
GNU mkdir's default).`,
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

		publicKey, err := cryptox.PublicKeyFromPrivate(privKey)
		if err != nil {
			return fmt.Errorf("extracting public key: %w", err)
		}
		publicKeyB64 := base64StdString(publicKey)

		baseURL, err := resolveBaseURL(stored.APIBaseURL)
		if err != nil {
			return err
		}
		client := api.New(baseURL, stored.AccessToken)

		// One tree fetch per invocation. With -p we mutate the local
		// tree as we create folders so subsequent path segments can
		// resolve their newly-minted parents without a refetch.
		ctxTree, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		tree, err := client.Tree(ctxTree)
		cancel()
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("fetching file tree: %w", err)
		}

		var hadError bool
		for _, arg := range args {
			if err := mkdirOne(cmd.Context(), client, tree, arg, publicKeyB64, privKey); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  Error creating %s: %v\n", arg, err)
				hadError = true
			}
		}
		if hadError {
			return errors.New("one or more folders could not be created")
		}
		return nil
	},
}

// mkdirOne creates ONE folder at the given slash-separated path.
// With --parents, also creates missing ancestors along the way.
// Mutates `tree.Folders` in place so the next arg's path resolution
// (or subsequent segment under --parents) can see the new rows
// without a server refetch.
func mkdirOne(
	parentCtx context.Context,
	client *api.Client,
	tree *api.TreeResponse,
	path string,
	publicKeyB64 string,
	privKey []byte,
) error {
	path = strings.Trim(path, "/")
	if path == "" {
		return errors.New("empty path")
	}
	segments := strings.Split(path, "/")

	var parentID *string
	// Walk segments. For all-but-last, require existence (unless -p
	// fills the gap). The last segment is the one we always create.
	for i, segment := range segments {
		if segment == "" {
			return fmt.Errorf("empty path segment in %q", path)
		}
		isLast := i == len(segments)-1

		// Look for an existing folder with this name under parentID.
		existing := findChildFolderID(tree, parentID, segment, privKey)
		if existing != nil {
			if isLast {
				return fmt.Errorf("folder %q already exists", path)
			}
			parentID = existing
			continue
		}

		if !isLast && !mkdirParents {
			return fmt.Errorf("parent folder %q does not exist (pass -p to create it)", segment)
		}

		// Create the folder.
		created, err := createOneFolder(parentCtx, client, tree, parentID, segment, publicKeyB64)
		if err != nil {
			return err
		}
		parentID = &created
	}

	fmt.Printf("  ✓ Created %s\n", path)
	return nil
}

// createOneFolder issues POST /api/folders for one new folder,
// returns its id, and stitches the new row into `tree.Folders` so
// in-batch lookups see it.
func createOneFolder(
	parentCtx context.Context,
	client *api.Client,
	tree *api.TreeResponse,
	parentID *string,
	name string,
	publicKeyB64 string,
) (string, error) {
	enc, err := cryptox.EncryptFolderName(name, publicKeyB64)
	if err != nil {
		return "", fmt.Errorf("encrypting folder name: %w", err)
	}

	ctx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
	defer cancel()
	resp, err := client.CreateFolder(ctx, &api.CreateFolderRequest{
		ParentID:            parentID,
		EncryptedName:       enc.EncryptedNameB64,
		NameNonce:           enc.NameNonceB64,
		NameKeyEncapsulated: enc.NameKeyEncapsulated,
		NameKeyWrapped:      enc.NameKeyWrapped,
		NameKeyWrapNonce:    enc.NameKeyWrapNonce,
	})
	if err != nil {
		return "", fmt.Errorf("create folder request: %w", err)
	}

	// Stitch into the local tree so subsequent lookups in this
	// invocation see the row without refetching.
	encName := enc.EncryptedNameB64
	encNonce := enc.NameNonceB64
	nke := enc.NameKeyEncapsulated
	nkw := enc.NameKeyWrapped
	nkwn := enc.NameKeyWrapNonce
	tree.Folders = append(tree.Folders, api.Folder{
		ID:                  resp.Folder.ID,
		ParentID:            parentID,
		EncryptedName:       &encName,
		NameNonce:           &encNonce,
		NameKeyEncapsulated: &nke,
		NameKeyWrapped:      &nkw,
		NameKeyWrapNonce:    &nkwn,
	})

	return resp.Folder.ID, nil
}

// findChildFolderID looks for an existing folder named `name`
// directly under `parentID` in the in-memory tree. Returns nil if
// not found. Errors during decrypt are treated as "no match" — a
// folder we can't decrypt isn't a folder the user can address via
// path resolution anyway.
func findChildFolderID(
	tree *api.TreeResponse,
	parentID *string,
	name string,
	privKey []byte,
) *string {
	byParent := indexFoldersByParent(tree.Folders)
	for _, f := range byParent[strPtrKey(parentID)] {
		display, err := folderDisplayName(f, privKey)
		if err != nil {
			continue
		}
		if display == name {
			id := f.ID
			return &id
		}
	}
	return nil
}
