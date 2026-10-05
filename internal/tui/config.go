package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type savedConfig struct {
	Domain      string `json:"domain"`
	Wordlist    string `json:"wordlist"`
	DNSServer   string `json:"dns_server"`
	Concurrency int    `json:"concurrency"`
	TimeoutMs   int    `json:"timeout_ms"`
	Attempts    int    `json:"attempts"`
	HitRate     int    `json:"hit_rate"`
	Types       string `json:"types"`
	Depth       int    `json:"depth"`
	Rate        int    `json:"rate"`
	MaxQueries  int    `json:"max_queries"`
	Exclude     string `json:"exclude,omitempty"`
	Output      string `json:"output"`
	Format      string `json:"format"`
	Simulate    bool   `json:"simulate"`
	Force       bool   `json:"force"`
	Recursive   bool   `json:"recursive"`
	NoAbort     bool   `json:"no_abort"`
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

func saveConfig(fv formValues) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	sc := savedConfig{
		Domain:      fv.domain,
		Wordlist:    fv.wordlist,
		DNSServer:   fv.dnsServer,
		Concurrency: fv.concurrency,
		TimeoutMs:   fv.timeoutMs,
		Attempts:    fv.attempts,
		HitRate:     fv.hitRate,
		Types:       strings.Join(fv.recordTypes, ","),
		Depth:       fv.depth,
		Rate:        fv.rate,
		MaxQueries:  fv.maxQueries,
		Exclude:     strings.Join(fv.exclude, ","),
		Output:      fv.outputFile,
		Format:      fv.formatName,
		Simulate:    fv.simulate,
		Force:       fv.force,
		Recursive:   fv.recursive,
		NoAbort:     fv.noAbort,
	}
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	// Write a temp file and rename it into place, so a second instance
	// reading at the same moment never sees half-written JSON (#80).
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
