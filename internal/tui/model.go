// Package tui implements `sef gui` — a two-pane file-manager
// terminal UI in the spirit of Midnight Commander, with one pane
// browsing the OS filesystem and the other browsing the user's
// Sefaly account. Built on Bubble Tea (Elm-architecture TUI
// framework from Charm), Lip Gloss for styling, and the existing
// internal/api + internal/cryptox packages for the actual data.
//
// Phase A scope: read-only browsing. No transfers, no mutations.
// Phase B (uploads + downloads) and Phase C (mkdir / rm / rename)
// will layer on without touching the navigation model.
package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/shokace/sefaly-cli/internal/api"
)

// Pane discriminates which side currently has keyboard focus.
type Pane int

const (
	PaneLocal Pane = iota
	PaneRemote
)

// narrowCutoff is the terminal-width threshold below which we
// collapse to single-pane mode. Two panes need ~50 cols each
// minimum to be useful (path + entries + scrollbar). Below this
// the focused pane gets the whole width and Tab swaps which side
// is shown.
const narrowCutoff = 100

// Model is the Bubble Tea Elm-style model — the whole TUI state
// lives here. Update returns a new Model + optional command; View
// renders this struct to a string.
type Model struct {
	// Terminal dimensions, updated on every WindowSizeMsg.
	width, height int

	// Which pane has keyboard focus.
	focused Pane

	// Narrow-terminal mode. When true, only the focused pane is
	// rendered (full width); Tab swaps which side is shown.
	collapsed bool

	// The two panes themselves. Each tracks its own cwd / cursor /
	// scroll offset; Update routes key events to whichever has
	// focus.
	local  *LocalPane
	remote *RemotePane

	// Top-level error to surface in the status bar. Cleared on the
	// next successful action.
	statusErr error

	// Private key, decrypted at startup, kept in memory for the
	// session so the remote pane can decrypt folder/file names
	// without re-deriving on every render. Zeroed on quit.
	privKey []byte

	// Public key derived from privKey (substring slice, not a
	// separate KDF), kept so future Phase B/C operations can call
	// EncryptFolderName / EncryptFileForUpload without re-deriving.
	publicKeyB64 string

	// API client, configured with the user's bearer token. Shared
	// across panes (only the remote pane uses it today).
	client *api.Client

	// True once we've finished loading the initial remote tree.
	// While false, the remote pane shows a spinner / "Loading…"
	// placeholder instead of the entry list.
	ready bool

	// Currently-running transfer (one at a time in Phase B v1).
	// Non-nil while a copy is in flight; the status bar shows
	// `transfer.label` and the `c` keybinding becomes a no-op.
	transfer *transferState
}

// NewModel constructs a fresh model ready to be handed to
// tea.NewProgram. Caller is responsible for closing creds.Load
// and decrypting the private key beforehand — we take both as
// arguments so the TUI itself never touches the password-derived
// state. The startCwd is the OS filesystem cwd the local pane
// should open in (typically os.Getwd()).
func NewModel(
	client *api.Client,
	privKey []byte,
	publicKeyB64 string,
	startCwd string,
) *Model {
	return &Model{
		focused:      PaneLocal,
		local:        newLocalPane(startCwd),
		remote:       newRemotePane(),
		client:       client,
		privKey:      privKey,
		publicKeyB64: publicKeyB64,
	}
}

// Init kicks off any async work the model needs at startup. Bubble
// Tea calls this exactly once. We fetch the remote tree here so
// the user sees the local pane immediately while the network
// round-trip happens in the background.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		m.local.load(),
		m.fetchTree(),
	)
}

// fetchTree is a tea.Cmd that pulls /api/files?tree=1 and returns
// either a treeLoadedMsg or a treeErrMsg. Runs in its own goroutine
// — Bubble Tea handles the scheduling.
func (m *Model) fetchTree() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tree, err := m.client.Tree(ctx)
		if err != nil {
			return treeErrMsg{err: err}
		}
		return treeLoadedMsg{tree: tree}
	}
}

// --- messages -----------------------------------------------------

// treeLoadedMsg is delivered when the initial tree fetch succeeds.
type treeLoadedMsg struct{ tree *api.TreeResponse }

// treeErrMsg is delivered when the initial tree fetch fails. The
// user sees this in the status bar and can retry with F5 (Phase C)
// or just restart the TUI.
type treeErrMsg struct{ err error }

// localLoadedMsg is delivered when the local pane finishes reading
// a directory. Carries the entries already sorted.
type localLoadedMsg struct {
	cwd     string
	entries []LocalEntry
}

// localErrMsg is delivered when the local pane can't read a
// directory (permission denied, deleted, etc.).
type localErrMsg struct{ err error }

// --- Update + View ------------------------------------------------

// Update is Bubble Tea's reducer: takes the current state + an
// event, returns the new state + any commands to run. Routes
// key events to whichever pane has focus.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.collapsed = m.width < narrowCutoff
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case treeLoadedMsg:
		m.remote.setTree(msg.tree, m.privKey)
		m.ready = true
		return m, nil

	case treeErrMsg:
		m.statusErr = fmt.Errorf("loading remote tree: %w", msg.err)
		return m, nil

	case localLoadedMsg:
		m.local.applyLoaded(msg.cwd, msg.entries)
		return m, nil

	case localErrMsg:
		m.statusErr = fmt.Errorf("reading local directory: %w", msg.err)
		return m, nil

	case transferCompletedMsg:
		m.transfer = nil
		m.statusErr = nil
		// Refresh the DESTINATION pane (opposite of the source).
		// Upload → refetch remote tree so the new file shows up.
		// Download → re-read local cwd so the new file shows up.
		if msg.source == PaneLocal {
			return m, m.fetchTree()
		}
		return m, m.local.load()

	case transferFailedMsg:
		m.transfer = nil
		m.statusErr = fmt.Errorf("transfer failed: %w", msg.err)
		return m, nil
	}
	return m, nil
}

// handleKey dispatches keyboard input to navigation, focus
// switching, or quit. Unknown keys are dropped on the floor.
func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, m.quit()

	case "tab":
		if m.focused == PaneLocal {
			m.focused = PaneRemote
		} else {
			m.focused = PaneLocal
		}
		return m, nil

	case "c", "f5":
		// Copy the focused pane's selection to the OTHER pane's
		// current directory. Ignored if a transfer is already in
		// flight (status bar already shows what's happening).
		if m.transfer != nil {
			return m, nil
		}
		return m, m.startCopy()
	}

	// Route remaining keys to the focused pane.
	if m.focused == PaneLocal {
		cmd := m.local.handleKey(msg)
		return m, cmd
	}
	if !m.ready {
		// Remote pane not loaded yet — drop the key. (Could buffer
		// but Phase A doesn't bother.)
		return m, nil
	}
	cmd := m.remote.handleKey(msg, m.privKey)
	return m, cmd
}

// quit zeros the private key and asks Bubble Tea to exit. Wrapping
// it as a tea.Cmd keeps the wipe sequenced with the program's
// shutdown rather than racing.
func (m *Model) quit() tea.Cmd {
	for i := range m.privKey {
		m.privKey[i] = 0
	}
	return tea.Quit
}
