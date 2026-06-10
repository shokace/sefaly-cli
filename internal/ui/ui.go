// Package ui centralizes the CLI's visual language: the accent palette,
// reusable lipgloss styles, the startup banner + ASCII logo, and small
// output helpers (headings, key/value rows, status lines, tables). Every
// command renders through here so the tool looks cohesive — closer to a
// polished interactive tool than a pile of fmt.Printf calls.
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Brand palette — mirrors the web app's indigo accent so the CLI and the
// site feel like one product. lipgloss degrades these gracefully on
// 256-color and no-color terminals.
var (
	Accent  = lipgloss.Color("#818cf8") // indigo-400, reads well on dark terminals
	Accent2 = lipgloss.Color("#6366f1") // indigo-500
	FgColor = lipgloss.Color("#e2e8f0")
	Muted   = lipgloss.Color("#94a3b8")
	Faint   = lipgloss.Color("#64748b")
	Success = lipgloss.Color("#34d399")
	Danger  = lipgloss.Color("#f87171")
	Warn    = lipgloss.Color("#fbbf24")
)

var (
	accentStyle = lipgloss.NewStyle().Foreground(Accent)
	boldAccent  = lipgloss.NewStyle().Foreground(Accent).Bold(true)
	mutedStyle  = lipgloss.NewStyle().Foreground(Muted)
	faintStyle  = lipgloss.NewStyle().Foreground(Faint)
	fgStyle     = lipgloss.NewStyle().Foreground(FgColor)
	successSt   = lipgloss.NewStyle().Foreground(Success)
	dangerSt    = lipgloss.NewStyle().Foreground(Danger)
	warnSt      = lipgloss.NewStyle().Foreground(Warn)
	boldStyle   = lipgloss.NewStyle().Bold(true)
)

// asciiLogo is the "SEFALY" wordmark (figlet ANSI-Shadow style). Shown
// in the welcome banner. Kept as a raw literal so it renders identically
// everywhere.
const asciiLogo = `
███████╗███████╗███████╗ █████╗ ██╗     ██╗   ██╗
██╔════╝██╔════╝██╔════╝██╔══██╗██║     ╚██╗ ██╔╝
███████╗█████╗  █████╗  ███████║██║      ╚████╔╝
╚════██║██╔══╝  ██╔══╝  ██╔══██║██║       ╚██╔╝
███████║███████╗██║     ██║  ██║███████╗   ██║
╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   `

// Banner renders the startup banner: the accented ASCII logo, a tagline,
// version, and a contextual status line (signed-in identity, or a nudge
// to log in). `who` is shown verbatim under the logo when non-empty.
func Banner(version, statusLine string) string {
	logo := boldAccent.Render(asciiLogo)
	tagline := mutedStyle.Render("  End-to-end, post-quantum encrypted cloud storage")
	ver := faintStyle.Render("  " + version)

	body := lipgloss.JoinVertical(lipgloss.Left, logo, "", tagline, ver)
	if statusLine != "" {
		body = lipgloss.JoinVertical(lipgloss.Left, body, "", "  "+statusLine)
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(Accent2).
		Padding(1, 3).
		Render(body)
	return "\n" + box + "\n"
}

// --- output helpers ---

// Heading prints a bold accented section heading.
func Heading(s string) string { return boldAccent.Render(s) }

// Accentf / Mutedf / Faintf / Bold style a string inline.
func Accentf(s string) string { return accentStyle.Render(s) }
func Mutedf(s string) string  { return mutedStyle.Render(s) }
func Faintf(s string) string  { return faintStyle.Render(s) }
func Boldf(s string) string   { return boldStyle.Render(s) }
func Fg(s string) string      { return fgStyle.Render(s) }

// Success/Error/Warn/Info status lines with a leading glyph. Returned as
// strings so callers decide stdout vs stderr.
func Success_(s string) string { return successSt.Render("✓ ") + s }
func Error_(s string) string   { return dangerSt.Render("✗ ") + s }
func Warn_(s string) string    { return warnSt.Render("! ") + s }
func Info_(s string) string    { return accentStyle.Render("• ") + s }

// Prompt is the interactive-shell prompt string for a given cloud path
// (e.g. "sefaly /Photos/2026 ❯ ").
func Prompt(path string) string {
	if path == "" || path == "/" {
		path = "/"
	}
	return accentStyle.Render("sefaly ") + faintStyle.Render(path) + boldAccent.Render(" ❯ ")
}

// KV renders an aligned key/value block (used by `info`, `whoami`). Keys
// are right-padded to the widest key so values line up.
func KV(pairs [][2]string) string {
	width := 0
	for _, p := range pairs {
		if len(p[0]) > width {
			width = len(p[0])
		}
	}
	var b strings.Builder
	for _, p := range pairs {
		key := faintStyle.Render(fmt.Sprintf("%-*s", width, p[0]))
		b.WriteString("  " + key + "  " + p[1] + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
