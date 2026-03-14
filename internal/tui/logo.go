package tui

import "github.com/charmbracelet/lipgloss"

var (
	logoPromptStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("34")).Bold(true)  // green $
	logoWordStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Bold(true) // white "sub"
	logoAccentStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)  // blue "enum"
	logoCursorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)  // blue cursor block
	logoTaglineStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))            // muted tagline
)

// logo returns the styled wordmark as a single string ready to embed in a View.
//
//	$ subenum▌
//	fast concurrent subdomain enumeration // written in Go
func logo() string {
	line1 := logoPromptStyle.Render("$ ") +
		logoWordStyle.Render("sub") +
		logoAccentStyle.Render("enum") +
		logoCursorStyle.Render("▌")

	line2 := logoTaglineStyle.Render("fast concurrent subdomain enumeration // written in Go")

	return line1 + "\n" + line2
}
