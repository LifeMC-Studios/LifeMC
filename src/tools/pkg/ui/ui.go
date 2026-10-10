// Package ui renders the LifeMC Studios terminal identity with Lipgloss.
package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Brand colour palette.
var (
	Primary   = lipgloss.Color("#00FF66") // green
	Secondary = lipgloss.Color("#00D7FF") // cyan
	Accent    = lipgloss.Color("#FFD700") // yellow
	Danger    = lipgloss.Color("#FF5555") // red

	muted   = lipgloss.Color("#7D8590")
	onBrand = lipgloss.Color("#04120A")
)

// Status badge names.
const (
	StatusSuccess = "SUCCESS"
	StatusWarning = "WARNING"
	StatusError   = "ERROR"
	StatusDryRun  = "DRY-RUN"
)

// banner is the official LifeMC Studios ASCII wordmark.
var banner = strings.Join([]string{
	"  _     _  __      __  __  ____   ____  _             _ _           ",
	" | |   (_)/ _| ___|  \\/  |/ ___| / ___|| |_ _   _  __| (_) ___  ___ ",
	" | |   | | |_ / _ \\ |\\/| | |     \\___ \\| __| | | |/ _` | |/ _ \\/ __|",
	" | |___| |  _|  __/ |  | | |___   ___) | |_| |_| | (_| | | (_) \\__ \\",
	" |_____|_|_|  \\___|_|  |_|\\____| |____/ \\__|\\__,_|\\__,_|_|\\___/|___/",
}, "\n")

// Pre-rendered styles.
var (
	bannerStyle = lipgloss.NewStyle().Foreground(Primary).Bold(true)
	titleStyle  = lipgloss.NewStyle().Foreground(Primary).Bold(true)
	mutedStyle  = lipgloss.NewStyle().Foreground(muted)
	strongStyle = lipgloss.NewStyle().Foreground(Accent).Bold(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(Secondary).
			Padding(0, 1)
	boxTitleStyle = lipgloss.NewStyle().Foreground(Primary).Bold(true)

	badgeBase    = lipgloss.NewStyle().Bold(true).Foreground(onBrand).Padding(0, 1)
	successBadge = badgeBase.Background(Primary)
	warningBadge = badgeBase.Background(Accent)
	errorBadge   = badgeBase.Background(Danger)
	dryRunBadge  = badgeBase.Background(Secondary)
	neutralBadge = lipgloss.NewStyle().Bold(true).Foreground(muted)
)

// Banner returns the wordmark rendered in the primary brand colour.
func Banner() string {
	return bannerStyle.Render(banner)
}

// Header returns the banner followed by a section title.
func Header(title string) string {
	return Banner() + "\n" + titleStyle.Render(title)
}

// Title renders a bold, primary-coloured title.
func Title(text string) string {
	return titleStyle.Render(text)
}

// Subtle renders dimmed text for secondary information.
func Subtle(text string) string {
	return mutedStyle.Render(text)
}

// Strong renders bold, accent-coloured text for values.
func Strong(text string) string {
	return strongStyle.Render(text)
}

// Badge renders a bracketed status badge in its brand colour.
func Badge(status string) string {
	label := "[" + status + "]"
	switch status {
	case StatusSuccess:
		return successBadge.Render(label)
	case StatusWarning:
		return warningBadge.Render(label)
	case StatusError:
		return errorBadge.Render(label)
	case StatusDryRun:
		return dryRunBadge.Render(label)
	default:
		return neutralBadge.Render(label)
	}
}

// Box renders content inside a rounded border with an optional title.
func Box(title string, lines []string) string {
	body := strings.Join(lines, "\n")
	if title == "" {
		return boxStyle.Render(body)
	}
	return boxStyle.Render(boxTitleStyle.Render(title) + "\n" + body)
}

// Report renders a titled box with a coloured status badge, a summary line and
// optional detail rows.
func Report(title, status, summary string, details []string) string {
	lines := make([]string, 0, len(details)+1)
	lines = append(lines, Badge(status)+" "+summary)
	lines = append(lines, details...)
	return Box(title, lines)
}
