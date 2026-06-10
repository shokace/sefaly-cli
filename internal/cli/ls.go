package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(lsCmd)
	lsCmd.Flags().BoolVarP(&lsLong, "long", "l", false,
		"Long format: show size, modified time, type indicator.")
	lsCmd.Flags().BoolVar(&lsTree, "tree", false,
		"Recursive tree listing instead of a single folder's contents.")
}

var (
	lsLong bool
	lsTree bool
)

var lsCmd = &cobra.Command{
	Use:   "ls [path]",
	Short: "List files and folders in your account",
	Long: `List the contents of a folder.

  sef ls                    list the root folder
  sef ls Photos             list "Photos" at the root
  sef ls Photos/2026/Trip   navigate the tree, list "Trip"
  sef ls --long             include size + modified time
  sef ls --tree             recursive view from the given path

Filenames are decrypted locally — the server only ever sees their
ciphertext.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		stored, err := creds.Load()
		if err != nil {
			if errors.Is(err, creds.ErrNotFound) {
				return errors.New("not signed in — run `sef login`")
			}
			return fmt.Errorf("reading credentials: %w", err)
		}

		// Decrypt the user's privateKey from the stored ciphertext +
		// the raw access token (HKDF-derived key). The plaintext key
		// lives only for the duration of this command and gets zeroed
		// at the end. It's the input to every ML-KEM decapsulation
		// below.
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

		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		tree, err := client.Tree(ctx)
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("fetching file tree: %w", err)
		}

		// Build {parentId → []folder} + {parentId → []file} indexes
		// so the listing step is a flat lookup. Names get resolved
		// lazily — we only pay the decrypt cost for rows we're
		// actually going to print.
		foldersByParent := indexFoldersByParent(tree.Folders)
		filesByParent := indexFilesByParent(tree.Files)

		// Resolve the user-supplied path (slash-separated folder
		// names) to a folder id. Root is nil.
		targetPath := ""
		if len(args) == 1 {
			targetPath = args[0]
		}
		targetFolderID, err := resolvePath(targetPath, tree.Folders, privKey)
		if err != nil {
			return err
		}

		// Flat listing of the resolved folder's immediate children.
		folders := foldersByParent[strPtrKey(targetFolderID)]
		files := filesByParent[strPtrKey(targetFolderID)]

		if jsonOutput {
			type item struct {
				Name      string `json:"name"`
				Type      string `json:"type"`
				ID        string `json:"id"`
				SizeBytes string `json:"sizeBytes,omitempty"`
				MimeType  string `json:"mimeType,omitempty"`
				Modified  string `json:"modified"`
			}
			out := []item{}
			for _, f := range folders {
				name, _ := folderDisplayName(f, privKey)
				out = append(out, item{Name: name, Type: "folder", ID: f.ID, Modified: f.UpdatedAt})
			}
			for _, f := range files {
				name, _ := fileDisplayName(f, privKey)
				mt := ""
				if f.MimeType != nil {
					mt = *f.MimeType
				}
				out = append(out, item{Name: name, Type: "file", ID: f.ID, SizeBytes: f.SizeBytes, MimeType: mt, Modified: f.UpdatedAt})
			}
			return emitJSON(out)
		}

		if lsTree {
			return printTree(targetFolderID, foldersByParent, filesByParent, privKey, 0)
		}

		entries := make([]entry, 0, len(folders)+len(files))
		for _, f := range folders {
			name, err := folderDisplayName(f, privKey)
			if err != nil {
				name = "(decryption failed)"
			}
			entries = append(entries, entry{
				name:      name,
				isFolder:  true,
				updatedAt: f.UpdatedAt,
			})
		}
		for _, f := range files {
			name, err := fileDisplayName(f, privKey)
			if err != nil {
				name = "(decryption failed)"
			}
			entries = append(entries, entry{
				name:      name,
				isFolder:  false,
				sizeBytes: f.SizeBytes,
				updatedAt: f.UpdatedAt,
			})
		}

		// Folders first, then files, each group alphabetical. Matches
		// what `ls` does on a regular filesystem with the `--group-
		// directories-first` GNU flag — the convention most file
		// managers also use.
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].isFolder != entries[j].isFolder {
				return entries[i].isFolder
			}
			return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
		})

		if len(entries) == 0 {
			fmt.Println("(empty)")
			return nil
		}
		for _, e := range entries {
			if lsLong {
				fmt.Println(e.longLine())
			} else {
				fmt.Println(e.shortLine())
			}
		}
		return nil
	},
}

// ---- internal helpers ----

type entry struct {
	name      string
	isFolder  bool
	sizeBytes string // BigInt string; only set for files
	updatedAt string // ISO-8601 from the API
}

func (e entry) shortLine() string {
	if e.isFolder {
		return e.name + "/"
	}
	return e.name
}

func (e entry) longLine() string {
	// Width-fitting columns chosen for terminal readability rather
	// than parser friendliness. Anyone scripting against this output
	// should use `--format json` (TODO when we add other commands).
	typeCol := "-"
	sizeCol := humanSize(e.sizeBytes)
	if e.isFolder {
		typeCol = "d"
		sizeCol = "        -"
	}
	when := shortTime(e.updatedAt)
	name := e.name
	if e.isFolder {
		name += "/"
	}
	return fmt.Sprintf("%s %s  %s  %s", typeCol, sizeCol, when, name)
}

func indexFoldersByParent(all []api.Folder) map[string][]api.Folder {
	m := map[string][]api.Folder{}
	for _, f := range all {
		m[strPtrKey(f.ParentID)] = append(m[strPtrKey(f.ParentID)], f)
	}
	return m
}

func indexFilesByParent(all []api.File) map[string][]api.File {
	m := map[string][]api.File{}
	for _, f := range all {
		m[strPtrKey(f.FolderID)] = append(m[strPtrKey(f.FolderID)], f)
	}
	return m
}

// strPtrKey normalizes a *string to a map key. nil → "" (root).
func strPtrKey(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// resolvePath walks a slash-separated path of folder names from root
// to the target. Returns nil for the root, or *folderID for a nested
// match. Errors when a segment doesn't resolve to a single existing
// folder.
func resolvePath(path string, folders []api.Folder, privKey []byte) (*string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil, nil
	}
	parts := strings.Split(path, "/")

	// Build {parentId → folders} on the fly. Could memoise but `ls`
	// is one-shot and the tree size is small.
	byParent := indexFoldersByParent(folders)

	var currentID *string
	for _, segment := range parts {
		candidates := byParent[strPtrKey(currentID)]
		var match *api.Folder
		for i := range candidates {
			name, err := folderDisplayName(candidates[i], privKey)
			if err != nil {
				continue
			}
			if name == segment {
				if match != nil {
					return nil, fmt.Errorf("path segment %q matches multiple folders — disambiguate via the web UI", segment)
				}
				m := candidates[i]
				match = &m
			}
		}
		if match == nil {
			return nil, fmt.Errorf("no such folder: %q", segment)
		}
		id := match.ID
		currentID = &id
	}
	return currentID, nil
}

func folderDisplayName(f api.Folder, privKey []byte) (string, error) {
	if f.Name != nil && *f.Name != "" {
		// Legacy plaintext folder (pre-name-encryption rollout).
		return *f.Name, nil
	}
	if f.EncryptedName == nil || f.NameNonce == nil ||
		f.NameKeyEncapsulated == nil || f.NameKeyWrapped == nil ||
		f.NameKeyWrapNonce == nil {
		return "", errors.New("folder has neither plaintext nor encrypted name")
	}
	nameKey, err := cryptox.UnwrapFileKey(
		privKey,
		*f.NameKeyEncapsulated,
		*f.NameKeyWrapped,
		*f.NameKeyWrapNonce,
	)
	if err != nil {
		return "", fmt.Errorf("unwrapping folder name key: %w", err)
	}
	defer zero(nameKey)
	return cryptox.DecryptName(nameKey, *f.EncryptedName, *f.NameNonce)
}

func fileDisplayName(f api.File, privKey []byte) (string, error) {
	if f.OriginalFilename != nil && *f.OriginalFilename != "" {
		return *f.OriginalFilename, nil
	}
	if f.EncryptedFilename == nil || f.FilenameNonce == nil {
		return "", errors.New("file has neither plaintext nor encrypted filename")
	}
	fileKey, err := cryptox.UnwrapFileKey(
		privKey,
		f.EncapsulatedKey,
		f.EncryptedFileKey,
		f.KeyWrapNonce(),
	)
	if err != nil {
		return "", fmt.Errorf("unwrapping file key: %w", err)
	}
	defer zero(fileKey)
	return cryptox.DecryptName(fileKey, *f.EncryptedFilename, *f.FilenameNonce)
}

// printTree renders a `tree`-style recursive listing rooted at the
// given folder id. Depth is used for indentation only.
func printTree(
	parentID *string,
	foldersByParent map[string][]api.Folder,
	filesByParent map[string][]api.File,
	privKey []byte,
	depth int,
) error {
	indent := strings.Repeat("  ", depth)
	folders := foldersByParent[strPtrKey(parentID)]
	sort.SliceStable(folders, func(i, j int) bool {
		a, _ := folderDisplayName(folders[i], privKey)
		b, _ := folderDisplayName(folders[j], privKey)
		return strings.ToLower(a) < strings.ToLower(b)
	})
	for _, f := range folders {
		name, err := folderDisplayName(f, privKey)
		if err != nil {
			name = "(decryption failed)"
		}
		fmt.Println(indent + name + "/")
		id := f.ID
		if err := printTree(&id, foldersByParent, filesByParent, privKey, depth+1); err != nil {
			return err
		}
	}

	files := filesByParent[strPtrKey(parentID)]
	sort.SliceStable(files, func(i, j int) bool {
		a, _ := fileDisplayName(files[i], privKey)
		b, _ := fileDisplayName(files[j], privKey)
		return strings.ToLower(a) < strings.ToLower(b)
	})
	for _, f := range files {
		name, err := fileDisplayName(f, privKey)
		if err != nil {
			name = "(decryption failed)"
		}
		fmt.Println(indent + name)
	}
	return nil
}

// zero overwrites a slice with zeros. Used to scrub sensitive bytes
// before they become eligible for GC reuse. Best-effort — Go's GC may
// have already copied the buffer, but this kills the primary copy.
func zero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// humanSize converts a byte count (as a BigInt-style string, since
// the API serializes BigInt → string) to a right-aligned compact
// human-readable form. 9 chars wide so the column lines up.
func humanSize(s string) string {
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n < 0 {
		return "        ?"
	}
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%6d  B", n)
	case n < k*k:
		return fmt.Sprintf("%6.1f KB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%6.1f MB", float64(n)/(k*k))
	case n < k*k*k*k:
		return fmt.Sprintf("%6.1f GB", float64(n)/(k*k*k))
	default:
		return fmt.Sprintf("%6.1f TB", float64(n)/(k*k*k*k))
	}
}

// shortTime trims an ISO-8601 timestamp to `YYYY-MM-DD HH:MM` so the
// long-format column stays compact.
func shortTime(iso string) string {
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return iso
	}
	return t.Local().Format("2006-01-02 15:04")
}
