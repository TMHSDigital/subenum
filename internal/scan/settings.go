package scan

import (
	"regexp"
	"strings"
)

// Setting names a scan setting inside an engine message (#100). The engine
// has no idea whether it runs under the CLI (flags), the TUI (form fields) or
// pkg/subenum (Config fields), so messages carry a setting as a {token}, and
// each front end renders tokens in its own terms with Render.
type Setting string

// Settings the engine refers to in messages.
const (
	SettingConcurrency Setting = "concurrency"
	SettingTimeout     Setting = "timeout"
	SettingAttempts    Setting = "attempts"
	SettingHitRate     Setting = "hit_rate"
	SettingDepth       Setting = "depth"
	SettingRate        Setting = "rate"
	SettingMaxQueries  Setting = "max_queries"
	SettingExclude     Setting = "exclude"
	SettingRecursive   Setting = "recursive"
	SettingForce       Setting = "force"
)

// Settings lists every Setting, for front ends to check their name tables.
var Settings = []Setting{
	SettingConcurrency, SettingTimeout, SettingAttempts, SettingHitRate, SettingDepth,
	SettingRate, SettingMaxQueries, SettingExclude, SettingRecursive, SettingForce,
}

// Ref is the setting's token, to put in a message.
func (s Setting) Ref() string { return "{" + string(s) + "}" }

var settingToken = regexp.MustCompile(`\{([a-z_]+)\}`)

// Render replaces every setting token in msg with name(setting). A token for
// an unknown setting, or one name returns "" for, is left as it is.
func Render(msg string, name func(Setting) string) string {
	if !strings.Contains(msg, "{") {
		return msg
	}
	return settingToken.ReplaceAllStringFunc(msg, func(tok string) string {
		if n := name(Setting(tok[1 : len(tok)-1])); n != "" {
			return n
		}
		return tok
	})
}

// FlagName names a setting as the command-line flag that sets it, or ""
// for a setting it does not know, which Render then leaves as a token.
func FlagName(s Setting) string {
	switch s {
	case SettingConcurrency:
		return "-t"
	case SettingHitRate:
		return "-hit-rate"
	case SettingMaxQueries:
		return "-max-queries"
	case SettingTimeout, SettingAttempts, SettingDepth, SettingRate, SettingExclude, SettingRecursive, SettingForce:
		return "-" + string(s)
	}
	return ""
}
