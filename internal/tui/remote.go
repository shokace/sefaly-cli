package tui

import (
	"sort"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/cryptox"
)

// RemoteEntry is one row in the remote pane — a Sefaly file or
// folder. Names are pre-decrypted at tree-load time and cached in
// the pane so render passes don't re-decrypt on every keystroke.
type RemoteEntry struct {
	DisplayName string
	IsDir       bool
	// Exactly one of FolderID / FileID is set depending on IsDir.
	FolderID string
	FileID   string
	Size     int64
	IsParent bool
}

// RemotePane tracks Sefaly-side state — the full tree (we fetch
// it once at startup), where we currently are in it (parents
// breadcrumb), and the usual cursor / scroll offset.
type RemotePane struct {
	// tree is the full /api/files?tree=1 response. We keep it
	// around so navigation between folders is instant (no extra
	// network calls — the whole catalog is in memory). A future
	// pagination story would replace this with on-demand fetching.
	tree *api.TreeResponse

	// parents is the breadcrumb stack of folder IDs from root to
	// the current folder. nil = at the root. Element [n] is the
	// folder we're currently inside; [n-1] is its parent.
	parents []string

	// entries are the current folder's children, sorted folders-
	// first then alphabetical (matches the local pane).
	entries []RemoteEntry

	cursor int
	offset int

	// nameCache memoizes decryption results so the renderer can
	// stay synchronous. Keyed by "f:<folderID>" or "F:<fileID>"
	// so file/folder IDs don't collide.
	nameCache map[string]string
}

func newRemotePane() *RemotePane {
	return &RemotePane{
		nameCache: make(map[string]string),
	}
}

// setTree applies a freshly-loaded tree to the pane. Computes the
// root listing eagerly so the user sees something the moment the
// fetch returns. Subsequent descents call rebuild() on demand.
func (p *RemotePane) setTree(tree *api.TreeResponse, privKey []byte) {
	p.tree = tree
	p.parents = nil
	p.rebuild(privKey)
}

// handleKey applies a navigation key. Mirrors LocalPane.handleKey
// — same WASD + arrow bindings.
func (p *RemotePane) handleKey(msg tea.KeyMsg, privKey []byte) tea.Cmd {
	switch msg.String() {
	case "up", "w":
		if p.cursor > 0 {
			p.cursor--
		}
		return nil

	case "down", "s":
		if p.cursor < len(p.entries)-1 {
			p.cursor++
		}
		return nil

	case "pgup":
		p.cursor -= 10
		if p.cursor < 0 {
			p.cursor = 0
		}
		return nil

	case "pgdown":
		p.cursor += 10
		if p.cursor > len(p.entries)-1 {
			p.cursor = len(p.entries) - 1
		}
		return nil

	case "home":
		p.cursor = 0
		return nil

	case "end":
		p.cursor = len(p.entries) - 1
		return nil

	case "enter", "right", "d":
		if p.cursor < 0 || p.cursor >= len(p.entries) {
			return nil
		}
		sel := p.entries[p.cursor]
		switch {
		case sel.IsParent:
			p.ascend(privKey)
		case sel.IsDir:
			p.descend(sel.FolderID, privKey)
		}
		// Selecting a file does nothing in Phase A.
		return nil

	case "backspace", "left", "a", "esc":
		p.ascend(privKey)
		return nil
	}
	return nil
}

func (p *RemotePane) descend(folderID string, privKey []byte) {
	p.parents = append(p.parents, folderID)
	p.cursor = 0
	p.offset = 0
	p.rebuild(privKey)
}

func (p *RemotePane) ascend(privKey []byte) {
	if len(p.parents) == 0 {
		return
	}
	p.parents = p.parents[:len(p.parents)-1]
	p.cursor = 0
	p.offset = 0
	p.rebuild(privKey)
}

// rebuild recomputes `entries` from `tree` + `parents`. Cheap —
// linear scan of the tree's folder + file slices, filtered to
// the current parent. The decrypt step hits nameCache first.
func (p *RemotePane) rebuild(privKey []byte) {
	if p.tree == nil {
		p.entries = nil
		return
	}

	currentParent := p.currentParent()
	out := make([]RemoteEntry, 0, 16)

	// ".." row for non-root folders.
	if currentParent != nil {
		out = append(out, RemoteEntry{
			DisplayName: "..",
			IsDir:       true,
			IsParent:    true,
		})
	}

	// Folders whose parentId matches the current parent.
	for i := range p.tree.Folders {
		f := &p.tree.Folders[i]
		if !sameParent(f.ParentID, currentParent) {
			continue
		}
		out = append(out, RemoteEntry{
			DisplayName: p.folderName(f, privKey),
			IsDir:       true,
			FolderID:    f.ID,
		})
	}

	// Files whose folderId matches the current parent.
	for i := range p.tree.Files {
		f := &p.tree.Files[i]
		if !sameParent(f.FolderID, currentParent) {
			continue
		}
		size, _ := strconv.ParseInt(f.SizeBytes, 10, 64)
		out = append(out, RemoteEntry{
			DisplayName: p.fileName(f, privKey),
			IsDir:       false,
			FileID:      f.ID,
			Size:        size,
		})
	}

	// Same sort as the local pane: ".." pinned at the top,
	// folders first, alphabetical within each group.
	startIdx := 0
	if len(out) > 0 && out[0].IsParent {
		startIdx = 1
	}
	tail := out[startIdx:]
	sort.SliceStable(tail, func(i, j int) bool {
		if tail[i].IsDir != tail[j].IsDir {
			return tail[i].IsDir
		}
		return foldLower(tail[i].DisplayName) < foldLower(tail[j].DisplayName)
	})

	p.entries = out
	if p.cursor >= len(out) {
		p.cursor = 0
	}
}

// currentParent returns the folder ID of the directory we're
// inside, or nil for the root.
func (p *RemotePane) currentParent() *string {
	if len(p.parents) == 0 {
		return nil
	}
	last := p.parents[len(p.parents)-1]
	return &last
}

// folderName returns the display name for a Folder row, using the
// nameCache where possible. On decrypt failure (corrupt material,
// wrong key) renders a placeholder so the pane stays usable
// rather than panicking.
func (p *RemotePane) folderName(f *api.Folder, privKey []byte) string {
	key := "f:" + f.ID
	if cached, ok := p.nameCache[key]; ok {
		return cached
	}
	// Plaintext-named legacy folders bypass the decrypt path.
	if f.Name != nil && *f.Name != "" {
		p.nameCache[key] = *f.Name
		return *f.Name
	}
	if f.EncryptedName == nil || f.NameNonce == nil ||
		f.NameKeyEncapsulated == nil || f.NameKeyWrapped == nil ||
		f.NameKeyWrapNonce == nil {
		name := "<unnamed folder>"
		p.nameCache[key] = name
		return name
	}
	nameKey, err := cryptox.UnwrapFileKey(
		privKey,
		*f.NameKeyEncapsulated,
		*f.NameKeyWrapped,
		*f.NameKeyWrapNonce,
	)
	if err != nil {
		name := "<undecryptable>"
		p.nameCache[key] = name
		return name
	}
	defer zeroBytes(nameKey)
	name, err := cryptox.DecryptName(nameKey, *f.EncryptedName, *f.NameNonce)
	if err != nil {
		name = "<undecryptable>"
	}
	p.nameCache[key] = name
	return name
}

// fileName returns the display name for a File row. Same cache +
// fallback logic as folderName.
func (p *RemotePane) fileName(f *api.File, privKey []byte) string {
	key := "F:" + f.ID
	if cached, ok := p.nameCache[key]; ok {
		return cached
	}
	if f.OriginalFilename != nil && *f.OriginalFilename != "" {
		p.nameCache[key] = *f.OriginalFilename
		return *f.OriginalFilename
	}
	if f.EncryptedFilename == nil || f.FilenameNonce == nil {
		name := "<unnamed file>"
		p.nameCache[key] = name
		return name
	}
	fileKey, err := cryptox.UnwrapFileKey(
		privKey,
		f.EncapsulatedKey,
		f.EncryptedFileKey,
		f.KeyWrapNonce(),
	)
	if err != nil {
		name := "<undecryptable>"
		p.nameCache[key] = name
		return name
	}
	defer zeroBytes(fileKey)
	name, err := cryptox.DecryptName(fileKey, *f.EncryptedFilename, *f.FilenameNonce)
	if err != nil {
		name = "<undecryptable>"
	}
	p.nameCache[key] = name
	return name
}

// breadcrumb returns a slash-joined display path for the current
// folder, e.g. "/Photos/2026". Used by the header row above the
// entries list. In practice every parent's name is already in
// nameCache (populated when the user descended past it), so the
// privKey lookup is just a fallback.
func (p *RemotePane) breadcrumb(privKey []byte) string {
	if p.tree == nil || len(p.parents) == 0 {
		return "/"
	}
	out := ""
	for _, id := range p.parents {
		for i := range p.tree.Folders {
			if p.tree.Folders[i].ID == id {
				out += "/" + p.folderName(&p.tree.Folders[i], privKey)
				break
			}
		}
	}
	if out == "" {
		return "/"
	}
	return out
}

// sameParent compares an entry's parent id pointer (nullable for
// "I'm at root") with the pane's current parent. Both nil = root
// match; both pointing at the same string = nested match.
func sameParent(a, b *string) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

