package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/shokace/sefaly-cli/internal/api"
)

// Filenames are end-to-end encrypted, so the server stores only
// ciphertext and cannot enforce name uniqueness within a folder. Every
// client therefore has to do it: before creating, moving, copying, or
// renaming a file, resolve any collision against the folder's existing
// (decrypted) names. The helpers here are shared by put / cp / mv.

// folderFileNames maps each decrypted file name in a folder to its file
// id (nil folderID = root). Names that fail to decrypt are skipped.
func folderFileNames(tree *api.TreeResponse, folderID *string, privKey []byte) map[string]string {
	out := map[string]string{}
	for i := range tree.Files {
		if strPtrKey(tree.Files[i].FolderID) != strPtrKey(folderID) {
			continue
		}
		name, err := fileDisplayName(tree.Files[i], privKey)
		if err != nil {
			continue
		}
		out[name] = tree.Files[i].ID
	}
	return out
}

// uniqueFileName returns `desired` if it's free among `taken`, otherwise
// the first "base (N)ext" that isn't — mirroring Finder / Drive. The
// suffix goes before the extension, so "report.pdf" becomes
// "report (1).pdf", not "report.pdf (1)".
func uniqueFileName(desired string, taken map[string]string) string {
	if _, clash := taken[desired]; !clash {
		return desired
	}
	ext := filepath.Ext(desired)
	base := strings.TrimSuffix(desired, ext)
	if base == "" {
		// Dotfile like ".env": filepath.Ext returns the whole name, so
		// treat it as the base with no extension (".env (1)", not " (1).env").
		base, ext = desired, ""
	}
	for i := 1; i < 100000; i++ {
		cand := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, clash := taken[cand]; !clash {
			return cand
		}
	}
	return desired // pathological; let the caller proceed
}

// resolveNameCollision decides the final file name for an operation that
// lands `desiredName` in folderID:
//
//   - no clash (or the only clash is excludeID itself) → desiredName.
//   - clash + overwrite → desiredName, plus the id of the file to delete.
//   - clash, no overwrite → an auto-suffixed name; suffixed=true.
//
// excludeID is the file being moved (so "move in place" isn't treated as
// a self-collision); pass "" for copy/upload, where the source stays put
// and the new file must avoid its name.
func resolveNameCollision(
	tree *api.TreeResponse,
	folderID *string,
	desiredName, excludeID string,
	privKey []byte,
	overwrite bool,
) (finalName, overwriteID string, suffixed bool) {
	existing := folderFileNames(tree, folderID, privKey)
	oldID, clash := existing[desiredName]
	if !clash || oldID == excludeID {
		return desiredName, "", false
	}
	if overwrite {
		return desiredName, oldID, false
	}
	return uniqueFileName(desiredName, existing), "", true
}
