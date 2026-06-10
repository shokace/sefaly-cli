package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/shokace/sefaly-cli/internal/ui"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(infoCmd)
}

var infoCmd = &cobra.Command{
	Use:     "info <path>",
	Aliases: []string{"stat"},
	Short:   "Show details about a file or folder",
	Long: `Print metadata for a file or folder: type, size, timestamps,
the encryption parameters, and its id.

  sef info report.pdf
  sef info Photos/2026`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
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

		fileID, folderID, err := resolveDeleteTarget(args[0], tree, privKey)
		if err != nil {
			return err
		}

		if fileID != "" {
			return printFileInfo(tree, fileID, privKey)
		}
		return printFolderInfo(tree, folderID, privKey)
	},
}

func printFileInfo(tree *api.TreeResponse, fileID string, privKey []byte) error {
	var f *api.File
	for i := range tree.Files {
		if tree.Files[i].ID == fileID {
			f = &tree.Files[i]
			break
		}
	}
	if f == nil {
		return errors.New("file not found")
	}
	name, _ := fileDisplayName(*f, privKey)
	mimeType := "—"
	if f.MimeType != nil && *f.MimeType != "" {
		mimeType = *f.MimeType
	}
	ver := "1.2"
	if v, ok := f.EncryptionMetadata["version"].(string); ok && v != "" {
		ver = v
	}

	fmt.Println()
	fmt.Println("  " + ui.Boldf(name))
	fmt.Println(ui.KV([][2]string{
		{"Type", "file · " + mimeType},
		{"Size", trimSpace(humanSize(f.SizeBytes))},
		{"Path", folderPathOf(f.FolderID, tree, privKey) + name},
		{"Created", shortTime(f.CreatedAt)},
		{"Modified", shortTime(f.UpdatedAt)},
		{"Encryption", fmt.Sprintf("AES-256-GCM · ML-KEM-768 · v%s", ver)},
		{"File ID", ui.Faintf(f.ID)},
	}))
	fmt.Println()
	return nil
}

func printFolderInfo(tree *api.TreeResponse, folderID string, privKey []byte) error {
	var fo *api.Folder
	for i := range tree.Folders {
		if tree.Folders[i].ID == folderID {
			fo = &tree.Folders[i]
			break
		}
	}
	if fo == nil {
		return errors.New("folder not found")
	}
	name, _ := folderDisplayName(*fo, privKey)

	// Count immediate children.
	subFolders, subFiles := 0, 0
	for _, sub := range tree.Folders {
		if strPtrKey(sub.ParentID) == folderID {
			subFolders++
		}
	}
	for _, fi := range tree.Files {
		if strPtrKey(fi.FolderID) == folderID {
			subFiles++
		}
	}

	fmt.Println()
	fmt.Println("  " + ui.Boldf(name+"/"))
	fmt.Println(ui.KV([][2]string{
		{"Type", "folder"},
		{"Path", folderPathOf(fo.ParentID, tree, privKey) + name + "/"},
		{"Contents", fmt.Sprintf("%d folder(s), %d file(s)", subFolders, subFiles)},
		{"Created", shortTime(fo.CreatedAt)},
		{"Modified", shortTime(fo.UpdatedAt)},
		{"Folder ID", ui.Faintf(fo.ID)},
	}))
	fmt.Println()
	return nil
}

// folderPathOf builds the slash-prefixed decrypted path to a file's
// parent folder ("/Photos/2026/"), or "/" for root.
func folderPathOf(folderID *string, tree *api.TreeResponse, privKey []byte) string {
	if folderID == nil {
		return "/"
	}
	byID := map[string]api.Folder{}
	for _, fo := range tree.Folders {
		byID[fo.ID] = fo
	}
	var segs []string
	cur := folderID
	for cur != nil {
		fo, ok := byID[*cur]
		if !ok {
			break
		}
		n, _ := folderDisplayName(fo, privKey)
		segs = append([]string{n}, segs...)
		cur = fo.ParentID
	}
	out := "/"
	for _, s := range segs {
		out += s + "/"
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	return s
}

// authedClientURL is the shared setup every authenticated command runs:
// load creds, decrypt the private key, resolve the base URL, build a
// client. Returns the creds, the (caller-must-zero) private key, the
// client, and the resolved base URL (needed when constructing
// user-facing links). Centralizes the boilerplate.
func authedClientURL() (*creds.Credentials, []byte, *api.Client, string, error) {
	stored, err := creds.Load()
	if err != nil {
		if errors.Is(err, creds.ErrNotFound) {
			return nil, nil, nil, "", errors.New("not signed in — run `sef login`")
		}
		return nil, nil, nil, "", fmt.Errorf("reading credentials: %w", err)
	}
	privKey, _, err := cryptox.DecryptPrivateKey(stored.AccessToken, stored.UserID, stored.EncryptedPrivateKey)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("decrypting private key (re-login may help): %w", err)
	}
	baseURL, err := resolveBaseURL(stored.APIBaseURL)
	if err != nil {
		zero(privKey)
		return nil, nil, nil, "", err
	}
	return stored, privKey, api.New(baseURL, stored.AccessToken), baseURL, nil
}

// authedClient is authedClientURL without the base URL, for the common
// case where the command doesn't build links.
func authedClient() (*creds.Credentials, []byte, *api.Client, error) {
	s, k, c, _, err := authedClientURL()
	return s, k, c, err
}
