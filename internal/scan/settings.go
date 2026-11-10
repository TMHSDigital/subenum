package scan

import (
	"regexp"
	"slices"
	"strings"
)

// Setting names a scan setting inside an engine message (#100). The engine
// has no idea whether it runs under the CLI (flags), the TUI (form fields) or
// pkg/subenum (Config fields), so messages carry a setting as a {token}, and
// each front end renders tokens in its own terms with Render, naming the
// setting from settingTable.
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
	SettingMaxDuration Setting = "max_duration"
	SettingExclude     Setting = "exclude"
	SettingRecursive   Setting = "recursive"
	SettingForce       Setting = "force"
)

// SettingNames is how each front end names a Setting (#160).
type SettingNames struct {
	Flag  string // CLI flag without the dash; also the config file key and SUBENUM_* suffix
	Field string // pkg/subenum Config field
	Label string // TUI form label
}

// settingTable is the one place a Setting is named. Adding a Setting means
// adding a row here; tests in each front end check that the flag, Config
// field and form row it names exist.
var settingTable = []struct {
	Setting
	SettingNames
}{
	{SettingConcurrency, SettingNames{"t", "Concurrency", "Concurrency"}},
	{SettingTimeout, SettingNames{"timeout", "Timeout", "Timeout (ms)"}},
	{SettingAttempts, SettingNames{"attempts", "Attempts", "Attempts"}},
	{SettingHitRate, SettingNames{"hit-rate", "HitRate", "Hit Rate (%)"}},
	{SettingDepth, SettingNames{"depth", "Depth", "Depth"}},
	{SettingRate, SettingNames{"rate", "Rate", "Rate (qps)"}},
	{SettingMaxQueries, SettingNames{"max-queries", "MaxQueries", "Max Names"}},
	{SettingMaxDuration, SettingNames{"max-duration", "MaxDuration", "Max Duration"}},
	{SettingExclude, SettingNames{"exclude", "Exclude", "Exclude"}},
	{SettingRecursive, SettingNames{"recursive", "Recursive", "Recursive"}},
	{SettingForce, SettingNames{"force", "Force", "Force"}},
}

// Settings lists every Setting, in settingTable order.
var Settings = func() []Setting {
	out := make([]Setting, len(settingTable))
	for i, row := range settingTable {
		out[i] = row.Setting
	}
	return out
}()

// Names returns the setting's names, or zero names for a setting it does
// not know.
func (s Setting) Names() SettingNames {
	for _, row := range settingTable {
		if row.Setting == s {
			return row.SettingNames
		}
	}
	return SettingNames{}
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

// SettingsIn lists the known settings msg refers to as tokens, in order of
// first appearance and without repeats, so structured output can carry them
// as codes beside the rendered text (#198).
func SettingsIn(msg string) []Setting {
	var out []Setting
	for _, m := range settingToken.FindAllStringSubmatch(msg, -1) {
		s := Setting(m[1])
		if s.Names().Flag == "" || slices.Contains(out, s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// FlagName names a setting as the command-line flag that sets it, or ""
// for a setting it does not know, which Render then leaves as a token.
func FlagName(s Setting) string {
	if f := s.Names().Flag; f != "" {
		return "-" + f
	}
	return ""
}

// FieldName names a setting as the pkg/subenum Config field that sets it.
func FieldName(s Setting) string { return s.Names().Field }

// Label names a setting as the TUI form field that sets it.
func Label(s Setting) string { return s.Names().Label }
