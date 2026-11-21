package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type savedConfig struct {
	Domain    string `json:"domain"`
	Wordlist  string `json:"wordlist"`
	DNSServer string `json:"dns_server"`
	// Resolvers is the resolver pool file (-r) and RatePerResolver its
	// per-member cap (-rate-per-resolver) (#195).
	Resolvers       string `json:"resolvers,omitempty"`
	RatePerResolver int    `json:"rate_per_resolver,omitempty"`
	Concurrency     int    `json:"concurrency"`
	TimeoutMs       int    `json:"timeout_ms"`
	Attempts        int    `json:"attempts"`
	HitRate         int    `json:"hit_rate"`
	Types           string `json:"types"`
	Depth           int    `json:"depth"`
	Rate            int    `json:"rate"`
	MaxQueries      int    `json:"max_queries"`
	Exclude         string `json:"exclude,omitempty"`
	Output          string `json:"output"`
	Format          string `json:"format"`
	Simulate        bool   `json:"simulate"`
	Force           bool   `json:"force"`
	Recursive       bool   `json:"recursive"`
	NoAbort         bool   `json:"no_abort"`
	// AutoRate, MaxDuration and RetryInconclusive are -auto-rate,
	// -max-duration (as Go prints a duration, e.g. "20m0s") and
	// -retry-inconclusive (#274).
	AutoRate          bool   `json:"auto_rate,omitempty"`
	MaxDuration       string `json:"max_duration,omitempty"`
	RetryInconclusive bool   `json:"retry_inconclusive,omitempty"`
	// Sources is -sources as a comma-separated list, and Permute is -permute
	// (#274).
	Sources string `json:"sources,omitempty"`
	Permute bool   `json:"permute,omitempty"`
	// AXFR, NSECWalk and Stats are -axfr, -nsec-walk and the -stats file
	// (#418).
	AXFR     bool   `json:"axfr,omitempty"`
	NSECWalk bool   `json:"nsec_walk,omitempty"`
	Stats    string `json:"stats,omitempty"`
}

// durationText is how a max duration is saved: "" for none, so the form
// shows its placeholder again, else the duration as Go prints it.
func durationText(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "subenum", "last.json"), nil
}

func loadSavedConfig() (savedConfig, bool) {
	p, err := configPath()
	if err != nil {
		return savedConfig{}, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return savedConfig{}, false
	}
	var sc savedConfig
	if err := json.Unmarshal(data, &sc); err != nil {
		return savedConfig{}, false
	}
	return sc, true
}

// saveConfig writes sc, the form as validate remembered it, to last.json.
func saveConfig(sc savedConfig) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	// Write a temp file and rename it into place, so a second instance
	// reading at the same moment never sees half-written JSON (#80). Not
	// output.WriteFile on purpose: os.CreateTemp makes the file 0600 whatever
	// the umask, since the saved form can name the user's files and resolvers
	// (#331).
	tmp, err := os.CreateTemp(filepath.Dir(p), ".last-*.json")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr == nil && cerr == nil {
		if werr = os.Rename(tmp.Name(), p); werr == nil {
			return nil
		}
	}
	_ = os.Remove(tmp.Name())
	if werr != nil {
		return werr
	}
	return cerr
}

// withSettings overlays flag values from SUBENUM_* variables or the config
// file (keyed by flag name) on the remembered form values (#118), using each
// form field's flag (#160).
func withSettings(sc savedConfig, settings map[string]string) savedConfig {
	for _, spec := range formFields {
		if v, ok := settings[spec.flagName()]; ok && spec.flagName() != "" {
			spec.set(&sc, v)
		}
	}
	return sc
}

// Flags lists the flags whose SUBENUM_* or config file value seeds the form,
// so the CLI can check that every flag is either wired here or deliberately
// left out of the TUI.
func Flags() []string {
	var out []string
	for _, spec := range formFields {
		if f := spec.flagName(); f != "" {
			out = append(out, f)
		}
	}
	return out
}
