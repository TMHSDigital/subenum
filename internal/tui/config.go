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
	Output      string `json:"output"`
	Format      string `json:"format"`
	Simulate    bool   `json:"simulate"`
	Force       bool   `json:"force"`
	Recursive   bool   `json:"recursive"`
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
		Output:      fv.outputFile,
		Format:      fv.formatName,
		Simulate:    fv.simulate,
		Force:       fv.force,
		Recursive:   fv.recursive,
	}
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}
