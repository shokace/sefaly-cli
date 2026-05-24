package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Reserve some rows for chrome: 1 top spacing + 2 border + 1 header +
// 1 bottom border + 1 status bar = roughly 6 lines of non-entry
// real estate. The renderer recomputes from actual content but
// uses this as the lower bound when sizing the entry viewport.
const chromeRows = 6

// View renders the entire UI to a string. Bubble Tea calls this
// after every Update; we should NOT do any I/O here.
func (m *Model) View() string {
	// Pre-startup: terminal size hasn't arrived yet. Render nothing
	// — Bubble Tea sends WindowSizeMsg as the first message in
	// practice, but the gate avoids a flicker frame.
	if m.width == 0 || m.height == 0 {
		return ""
	}

	// Reserve one row for the status bar at the very bottom.
	bodyHeight := m.height - 1
	if bodyHeight < 5 {
		bodyHeight = 5
	}

	var body string
	if m.collapsed {
		body = m.renderSinglePane(m.width, bodyHeight)
	} else {
		// Two panes split 50/50. The middle gap is one column so
		// the borders don't overlap visually.
		leftWidth := m.width / 2
		rightWidth := m.width - leftWidth - 1
		left := m.renderPane(PaneLocal, leftWidth, bodyHeight)
		right := m.renderPane(PaneRemote, rightWidth, bodyHeight)
		body = lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	}

	return lipgloss.JoinVertical(lipgloss.Left, body, m.renderStatus(m.width))
}

// renderSinglePane is the narrow-terminal fallback. Only the
// focused pane is shown, full width.
func (m *Model) renderSinglePane(width, height int) string {
	return m.renderPane(m.focused, width, height)
}

// renderPane draws ONE pane — border, header (cwd / breadcrumb),
// entry list. The border thickness depends on focus: the focused
// pane gets a bright border so the user can tell where keystrokes
// will land.
func (m *Model) renderPane(which Pane, width, height int) string {
	focused := which == m.focused

	header, rows, footer := m.paneContent(which, width-2, height-chromeRows+2)

	// Layout: header line, separator, body rows.
	body := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		strings.Repeat("─", width-2),
		rows,
	)

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Width(width - 2).
		Height(height - 2)
	if focused {
		borderStyle = borderStyle.BorderForeground(lipgloss.Color("#7aa2f7"))
	} else {
		borderStyle = borderStyle.BorderForeground(lipgloss.Color("#414868"))
	}

	rendered := borderStyle.Render(body)

	// Footer (entry count) sits OUTSIDE the border, right-aligned.
	// Skipped if the terminal is too short to spare a row.
	if footer != "" && height > chromeRows+1 {
		footerStyle := lipgloss.NewStyle().
			Width(width).
			Align(lipgloss.Right).
			Foreground(lipgloss.Color("#565f89"))
		return lipgloss.JoinVertical(lipgloss.Left, rendered, footerStyle.Render(footer))
	}
	return rendered
}

// paneContent returns the three rendered chunks of a pane:
// header (path / breadcrumb), rows (entry list), footer (count).
func (m *Model) paneContent(which Pane, innerWidth, rowsHeight int) (header, rows, footer string) {
	if rowsHeight < 1 {
		rowsHeight = 1
	}
	switch which {
	case PaneLocal:
		header = formatHeader("LOCAL", m.local.cwd, innerWidth)
		if m.local.loading {
			rows = mutedLine("loading…", rowsHeight, innerWidth)
		} else if len(m.local.entries) == 0 {
			rows = mutedLine("(empty)", rowsHeight, innerWidth)
		} else {
			rows = renderEntries(m.local.entries, m.local.cursor, &m.local.offset,
				rowsHeight, innerWidth, which == m.focused, localEntryRow)
			footer = fmt.Sprintf("%d items", localEntryCount(m.local.entries))
		}
	case PaneRemote:
		if !m.ready {
			header = formatHeader("SEFALY", "loading…", innerWidth)
			rows = mutedLine("fetching remote tree…", rowsHeight, innerWidth)
			return
		}
		header = formatHeader("SEFALY", m.remote.breadcrumb(m.privKey), innerWidth)
		if len(m.remote.entries) == 0 {
			rows = mutedLine("(empty)", rowsHeight, innerWidth)
		} else {
			rows = renderEntries(m.remote.entries, m.remote.cursor, &m.remote.offset,
				rowsHeight, innerWidth, which == m.focused, remoteEntryRow)
			footer = fmt.Sprintf("%d items", remoteEntryCount(m.remote.entries))
		}
	}
	return
}

// formatHeader builds the per-pane label + path line. Truncates
// the path from the left if it's too long so the rightmost
// (current) folder is always visible.
func formatHeader(label, path string, width int) string {
	labelStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#bb9af7"))
	pathStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#c0caf5"))

	rendered := labelStyle.Render(label) + "  " + pathStyle.Render(path)
	plain := label + "  " + path
	// Truncate from the LEFT if too wide — keep the deepest dir
	// visible. Lipgloss doesn't have a built-in for this so we
	// do it on the plain string then re-render with prefixed "…".
	if len(plain) > width {
		over := len(plain) - width + 1
		path = "…" + path[over+1:]
		rendered = labelStyle.Render(label) + "  " + pathStyle.Render(path)
	}
	return rendered
}

// renderEntries is the workhorse — turns an entry list + cursor +
// viewport into a styled multi-line string. Generic over LocalEntry
// vs RemoteEntry via a per-pane row formatter callback.
func renderEntries[T any](
	entries []T,
	cursor int,
	offset *int,
	height, width int,
	paneFocused bool,
	rowFn func(T, int, bool, bool) string,
) string {
	// Ensure the cursor is visible: scroll offset = clamp so
	// cursor sits inside [offset, offset+height).
	if cursor < *offset {
		*offset = cursor
	}
	if cursor >= *offset+height {
		*offset = cursor - height + 1
	}
	if *offset < 0 {
		*offset = 0
	}
	maxOffset := len(entries) - height
	if maxOffset < 0 {
		maxOffset = 0
	}
	if *offset > maxOffset {
		*offset = maxOffset
	}

	var lines []string
	end := *offset + height
	if end > len(entries) {
		end = len(entries)
	}
	for i := *offset; i < end; i++ {
		selected := i == cursor
		lines = append(lines, rowFn(entries[i], width, selected, paneFocused))
	}
	// Pad with blank lines so the pane stays a fixed height.
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", width))
	}
	return strings.Join(lines, "\n")
}

// localEntryRow renders one LocalEntry as a single styled line.
// Layout: " <icon> <name> ..... <size>".
func localEntryRow(e LocalEntry, width int, selected, paneFocused bool) string {
	icon := "📄"
	if e.IsDir {
		icon = "📁"
	}
	if e.IsParent {
		icon = "↩ "
	}
	name := e.Name
	size := ""
	if !e.IsDir && !e.IsParent {
		size = humanSize(e.Size)
	}
	return styleEntryRow(icon, name, size, width, selected, paneFocused, e.IsDir)
}

// remoteEntryRow renders one RemoteEntry. Lock icon on encrypted
// files emphasizes that the name was decrypted locally — handy
// visual signal during demos.
func remoteEntryRow(e RemoteEntry, width int, selected, paneFocused bool) string {
	icon := "🔒"
	if e.IsDir {
		icon = "📁"
	}
	if e.IsParent {
		icon = "↩ "
	}
	size := ""
	if !e.IsDir && !e.IsParent {
		size = humanSize(e.Size)
	}
	return styleEntryRow(icon, e.DisplayName, size, width, selected, paneFocused, e.IsDir)
}

// styleEntryRow does the per-row Lipgloss styling. Folders show in
// a slightly bolder color than files; the selected row gets a
// highlight bar; the highlight only "lights up" when the pane is
// focused (otherwise it's a dim placeholder so the user can tell
// at a glance which side is active).
func styleEntryRow(icon, name, size string, width int, selected, paneFocused, isDir bool) string {
	// Layout: " <icon> <name> ..... <size>". The icon column is
	// 3 cols wide (most emojis are 2 cols + trailing space; the
	// ".." up-arrow is 2 cols + space). Anything weirder would
	// need a real grapheme-width library; not worth pulling one
	// in for Phase A.
	iconCell := icon + " "
	const iconWidth = 3
	nameWidth := width - iconWidth - len(size) - 1 // -1 for the separating space
	if nameWidth < 4 {
		nameWidth = 4
	}
	if len(name) > nameWidth {
		name = name[:nameWidth-1] + "…"
	}
	padding := nameWidth - len(name)
	if padding < 0 {
		padding = 0
	}

	body := iconCell + name + strings.Repeat(" ", padding) + " " + size

	var style lipgloss.Style
	switch {
	case selected && paneFocused:
		style = lipgloss.NewStyle().
			Background(lipgloss.Color("#3d59a1")).
			Foreground(lipgloss.Color("#ffffff")).
			Bold(true)
	case selected:
		// Pane not focused — show a muted highlight so the user
		// still knows where the cursor will be when they Tab back.
		style = lipgloss.NewStyle().
			Background(lipgloss.Color("#1a1b26")).
			Foreground(lipgloss.Color("#c0caf5"))
	case isDir:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7dcfff"))
	default:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("#c0caf5"))
	}
	return style.Render(body)
}

// mutedLine is a single muted-italic line (loading / empty
// states), padded to `height` lines so the pane keeps its fixed
// height even with no entries to render.
func mutedLine(text string, height, width int) string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#565f89")).
		Italic(true)
	lines := []string{style.Render(text)}
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", width))
	}
	return strings.Join(lines, "\n")
}

// renderStatus draws the bottom status bar — priority order:
//
//   1. In-flight transfer (blue, "⟳ Uploading foo.txt → /Photos")
//   2. Most recent error (red banner)
//   3. Context keybinds
//
// Errors get displaced by a fresh transfer because a new "Copy
// started" signal is more useful than a stale failure message.
func (m *Model) renderStatus(width int) string {
	if m.transfer != nil {
		return lipgloss.NewStyle().
			Background(lipgloss.Color("#3d59a1")).
			Foreground(lipgloss.Color("#ffffff")).
			Width(width).
			Padding(0, 1).
			Render("⟳ " + m.transfer.label)
	}

	if m.statusErr != nil {
		return lipgloss.NewStyle().
			Background(lipgloss.Color("#7c3a3a")).
			Foreground(lipgloss.Color("#ffffff")).
			Width(width).
			Padding(0, 1).
			Render("⚠ " + m.statusErr.Error())
	}

	keys := "[Tab] switch  [↑↓/WS] move  [Enter/→] open  [Backspace/←] up  [c] copy  [q] quit"
	if m.collapsed {
		keys = "[Tab] swap pane  " + keys
	}

	return lipgloss.NewStyle().
		Background(lipgloss.Color("#1a1b26")).
		Foreground(lipgloss.Color("#a9b1d6")).
		Width(width).
		Padding(0, 1).
		Render(keys)
}

// --- small helpers ------------------------------------------------

func humanSize(n int64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%dB", n)
	case n < k*k:
		return fmt.Sprintf("%.0fK", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1fM", float64(n)/(k*k))
	default:
		return fmt.Sprintf("%.1fG", float64(n)/(k*k*k))
	}
}

// localEntryCount / remoteEntryCount return the user-meaningful
// entry count — i.e. the slice length, minus the ".." nav row if
// it's present. Used by the footer count.
func localEntryCount(entries []LocalEntry) int {
	n := len(entries)
	if n > 0 && entries[0].IsParent {
		return n - 1
	}
	return n
}

func remoteEntryCount(entries []RemoteEntry) int {
	n := len(entries)
	if n > 0 && entries[0].IsParent {
		return n - 1
	}
	return n
}
