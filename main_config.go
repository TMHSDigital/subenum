package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Defaults beyond the built-in ones come from a JSON config file and from
// SUBENUM_* environment variables (#88). Precedence, highest first:
// command-line flag > environment > config file > built-in default.

// configEnv overrides the config file location (also used by tests).
const configEnv = "SUBENUM_CONFIG"

// errConfig marks an invalid config file or environment value; run reports
// it as a usage error.
var errConfig = errors.New("invalid configuration")

// Setting sources, as -print-config reports them.
const (
	sourceDefault = "default"
	sourceConfig  = "config"
	sourceEnv     = "env"
	sourceFlag    = "flag"
)

// noDefaultFlags are never taken from the config file or environment: they
// select a mode or an action rather than a setting.
var noDefaultFlags = map[string]bool{"tui": true, "version": true, "print-config": true, "h": true, "help": true}

// defaultsLoader applies config-file and environment defaults to a FlagSet
// and remembers where each value came from.
type defaultsLoader struct {
	path    string              // config file; "" means none
	getenv  func(string) string // os.Getenv, or a fake in tests
	sources map[string]string   // flag name -> source
	values  map[string]string   // flag name -> raw value applied
}

// newDefaultsLoader uses $SUBENUM_CONFIG, else <user config dir>/subenum/config.json.
func newDefaultsLoader() *defaultsLoader {
	path := os.Getenv(configEnv)
	if path == "" {
		if dir, err := os.UserConfigDir(); err == nil {
			path = filepath.Join(dir, "subenum", "config.json")
		}
	}
	return &defaultsLoader{path: path, getenv: os.Getenv}
}

// envName maps a flag to its environment variable: dns-server -> SUBENUM_DNS_SERVER.
func envName(flagName string) string {
	return "SUBENUM_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// apply sets config-file, then environment values on fs without marking
// them as given on the command line, so explicit-only checks keep working.
func (d *defaultsLoader) apply(fs *flag.FlagSet) error {
	d.sources = map[string]string{}
	d.values = map[string]string{}
	set := func(name, value, source string) error {
		fl := fs.Lookup(name)
		if fl == nil || noDefaultFlags[name] {
			return fmt.Errorf("%w: %s sets unknown setting %q", errConfig, source, name)
		}
		if err := fl.Value.Set(value); err != nil {
			return fmt.Errorf("%w: %s value %q for %s: %w", errConfig, source, value, name, err)
		}
		d.sources[name] = source
		d.values[name] = value
		return nil
	}

	if d.path != "" {
		data, err := os.ReadFile(d.path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return fmt.Errorf("%w: reading %s: %w", errConfig, d.path, err)
		default:
			var cfg map[string]any
			// UseNumber keeps 1000000 as "1000000", not float64's "1e+06".
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.UseNumber()
			if err := dec.Decode(&cfg); err != nil {
				return fmt.Errorf("%w: %s: %w", errConfig, d.path, err)
			}
			names := make([]string, 0, len(cfg))
			for name := range cfg {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if err := set(name, fmt.Sprint(cfg[name]), sourceConfig+" "+d.path); err != nil {
					return err
				}
				d.sources[name] = sourceConfig
			}
		}
	}

	var err error
	fs.VisitAll(func(fl *flag.Flag) {
		if err != nil || noDefaultFlags[fl.Name] {
			return
		}
		if v := d.getenv(envName(fl.Name)); v != "" {
			if e := set(fl.Name, v, envName(fl.Name)); e != nil {
				err = e
				return
			}
			d.sources[fl.Name] = sourceEnv
		}
	})
	return err
}

// printConfig writes every setting's effective value and its source.
func (d *defaultsLoader) printConfig(w io.Writer, fset *flag.FlagSet) {
	given := map[string]bool{}
	fset.Visit(func(fl *flag.Flag) { given[fl.Name] = true })
	if d.path != "" {
		_, _ = fmt.Fprintf(w, "# config file: %s\n", d.path)
	}
	fset.VisitAll(func(fl *flag.Flag) {
		if noDefaultFlags[fl.Name] {
			return
		}
		source := sourceDefault
		if s, ok := d.sources[fl.Name]; ok {
			source = s
		}
		if given[fl.Name] {
			source = sourceFlag
		}
		_, _ = fmt.Fprintf(w, "%-14s = %-24q (%s)\n", fl.Name, fl.Value.String(), source)
	})
}
