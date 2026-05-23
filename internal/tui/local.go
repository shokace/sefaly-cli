package tui

import (
	"errors"
	"os"
	"path/filepath"
	"sort"

	tea "github.com/charmbracelet/bubbletea"
)

// LocalEntry is one row in the local pane — a directory entry on
// the OS filesystem. Symlinks resolve to their target's mode for
// display (so a symlink to a directory shows with the folder
// icon).
type LocalEntry struct {
	Name  string
	IsDir bool
	Size  int64
	// IsParent is true for the synthetic ".." row we always
	// render at the top of every non-root directory. Helps the
	// renderer skip the size column for it.
	IsParent bool
}

// LocalPane tracks the local pane's state — what directory we're
// in, what's in it, where the cursor is, how scrolled the
// viewport is.
type LocalPane struct {
	cwd     string
	entries []LocalEntry
	cursor  int
	// offset is the index of the first visible row. Recomputed by
	// the renderer based on viewport height. Stored here so it
	// persists across renders when the height hasn't changed.
	offset int
	// loading is true between issuing a load() Cmd and receiving
	// the localLoadedMsg. The renderer shows a placeholder
	// instead of stale entries during that window.
	loading bool
}

func newLocalPane(startCwd string) *LocalPane {
	return &LocalPane{
		cwd:     startCwd,
		loading: true,
	}
}

// load returns a tea.Cmd that reads `p.cwd` and sends a
// localLoadedMsg (or localErrMsg) when done. Runs in a goroutine
// off the Bubble Tea event loop so a slow NFS mount can't freeze
// the UI.
func (p *LocalPane) load() tea.Cmd {
	cwd := p.cwd
	return func() tea.Msg {
		entries, err := readDir(cwd)
		if err != nil {
			return localErrMsg{err: err}
		}
		return localLoadedMsg{cwd: cwd, entries: entries}
	}
}

// applyLoaded swaps in a fresh entry list. Called by Update when a
// localLoadedMsg arrives. Resets the cursor / offset only when
// the cwd actually changed — staying-put refreshes (Phase C: F5)
// preserve the cursor.
func (p *LocalPane) applyLoaded(cwd string, entries []LocalEntry) {
	if p.cwd != cwd {
		p.cursor = 0
		p.offset = 0
	}
	p.cwd = cwd
	p.entries = entries
	p.loading = false
}

// handleKey applies a navigation key to the local pane. Returns a
// tea.Cmd if the key triggered a directory change (i.e. needs an
// async re-read), otherwise nil.
func (p *LocalPane) handleKey(msg tea.KeyMsg) tea.Cmd {
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
		// Descend into the selected entry if it's a directory.
		// "right" / "d" only descend (never ascend) — to keep the
		// mental model "right = go deeper" consistent with the
		// remote pane.
		if len(p.entries) == 0 {
			return nil
		}
		sel := p.entries[p.cursor]
		switch {
		case sel.IsParent:
			return p.ascend()
		case sel.IsDir:
			return p.descend(sel.Name)
		}
		// Selecting a file does nothing in Phase A; Phase B will
		// wire this up to preview / open.
		return nil

	case "backspace", "left", "a", "esc":
		return p.ascend()
	}
	return nil
}

func (p *LocalPane) descend(name string) tea.Cmd {
	p.cwd = filepath.Join(p.cwd, name)
	p.loading = true
	return p.load()
}

func (p *LocalPane) ascend() tea.Cmd {
	parent := filepath.Dir(p.cwd)
	if parent == p.cwd {
		// Already at root — no-op rather than crash.
		return nil
	}
	p.cwd = parent
	p.loading = true
	return p.load()
}

// readDir reads `path` and returns sorted entries. Folders first,
// then files, alphabetical within each group, case-insensitive.
// Adds a synthetic ".." entry at the top for every non-root path
// so Enter on the cursor row is always a navigation action.
func readDir(path string) ([]LocalEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, errors.New("permission denied")
		}
		return nil, err
	}

	out := make([]LocalEntry, 0, len(entries)+1)
	// Add ".." unless we're at the filesystem root. On Unix the
	// root's parent is itself ("/" == filepath.Dir("/")); on
	// Windows the same applies to drive letters.
	if filepath.Dir(path) != path {
		out = append(out, LocalEntry{Name: "..", IsDir: true, IsParent: true})
	}

	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			// Skip entries we can't stat (race with another process
			// deleting / renaming). Better to silently omit than
			// to fail the whole listing.
			continue
		}
		isDir := e.IsDir()
		// Resolve symlink target type so a link-to-directory shows
		// with the directory icon. Best-effort: a broken symlink
		// keeps its non-dir status and shows as a file.
		if !isDir && info.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Stat(filepath.Join(path, e.Name())); err == nil && target.IsDir() {
				isDir = true
			}
		}
		out = append(out, LocalEntry{
			Name:  e.Name(),
			IsDir: isDir,
			Size:  info.Size(),
		})
	}

	// Folders first, then files. Within each group: case-
	// insensitive alphabetical. ".." always stays at index 0 if
	// it exists (we added it before the loop above, so we skip it
	// in the sort).
	startIdx := 0
	if len(out) > 0 && out[0].IsParent {
		startIdx = 1
	}
	tail := out[startIdx:]
	sort.SliceStable(tail, func(i, j int) bool {
		if tail[i].IsDir != tail[j].IsDir {
			return tail[i].IsDir
		}
		return foldLower(tail[i].Name) < foldLower(tail[j].Name)
	})
	return out, nil
}

// foldLower is a tiny case-fold helper for sort comparisons. Pure
// ASCII fast path; Unicode is rare in filenames and the worst
// case is just out-of-order sorting of accented-name siblings,
// which is fine.
func foldLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
