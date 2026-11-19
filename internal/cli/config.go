package cli

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
	"strconv"
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
var noDefaultFlags = map[string]bool{"tui": true, "version": true, "print-config": true, "dry-run": true, "resume": true, "h": true, "help": true}

// listFlags take comma-separated values, so the config file may also give
// them as a JSON array of strings.
var listFlags = map[string]bool{"exclude": true, "type": true, "sources": true}

// repeatFlags may be given more than once on the command line (-w, -o). Like
// the listFlags, a config-file or SUBENUM_* string is a comma-separated list
// and the config file may give a JSON array; each array entry is one value,
// commas and all (#353).
var repeatFlags = map[string]bool{"w": true, "o": true, "recursive-w": true}

// repeatValue is the Value of a repeatFlag: the values given, in order.
type repeatValue interface{ list() []string }

// sourceRank orders sources by precedence, highest last.
var sourceRank = map[string]int{sourceDefault: 0, sourceConfig: 1, sourceEnv: 2, sourceFlag: 3}

// splitRepeat splits a config-file or environment string for a repeatFlag
// into the values to Set, one per comma-separated entry.
func splitRepeat(name, v string) []string {
	if !repeatFlags[name] {
		return []string{v}
	}
	parts := strings.Split(v, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// configValues turns one config-file value into the flag values to Set: one
// value, or one per entry for a repeatFlag. Only strings, numbers and
// booleans are settings; fmt.Sprint of null or an object would silently
// become a bogus value such as "<nil>".
func configValues(name string, v any) ([]string, error) {
	list := listFlags[name] || repeatFlags[name]
	switch v := v.(type) {
	case string:
		return splitRepeat(name, v), nil
	case json.Number, bool:
		return []string{fmt.Sprint(v)}, nil
	case []any:
		if list {
			parts := make([]string, len(v))
			for i, p := range v {
				s, ok := p.(string)
				if !ok {
					return nil, fmt.Errorf("list entries must be strings")
				}
				parts[i] = s
			}
			if repeatFlags[name] {
				return parts, nil
			}
			return []string{strings.Join(parts, ",")}, nil
		}
	}
	if list {
		return nil, fmt.Errorf("must be a string or a list of strings")
	}
	return nil, fmt.Errorf("must be a string, number or boolean")
}

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
// A bad value does not stop the others from being applied: every problem is
// returned, joined, so one run reports them all.
func (d *defaultsLoader) apply(fs *flag.FlagSet) error {
	d.sources = map[string]string{}
	d.values = map[string]string{}
	var errs []error
	// set applies values in order: one, or each entry of a repeatFlag list.
	set := func(name string, values []string, source string) bool {
		for _, value := range values {
			if err := fs.Lookup(name).Value.Set(value); err != nil {
				errs = append(errs, fmt.Errorf("%w: %s value %q for %s: %w", errConfig, source, value, name, err))
				return false
			}
		}
		if v, ok := fs.Lookup(name).Value.(interface{ markDefault() }); ok {
			v.markDefault()
		}
		d.values[name] = strings.Join(values, ",")
		return true
	}

	if d.path != "" {
		data, err := os.ReadFile(d.path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			errs = append(errs, fmt.Errorf("%w: reading %s: %w", errConfig, d.path, err))
		default:
			var cfg map[string]any
			// UseNumber keeps 1000000 as "1000000", not float64's "1e+06".
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.UseNumber()
			if err := dec.Decode(&cfg); err != nil {
				errs = append(errs, fmt.Errorf("%w: %s: %w", errConfig, d.path, err))
				break
			}
			names := make([]string, 0, len(cfg))
			for name := range cfg {
				names = append(names, name)
			}
			sort.Strings(names)
			source := sourceConfig + " " + d.path
			for _, name := range names {
				switch {
				case noDefaultFlags[name]:
					errs = append(errs, fmt.Errorf("%w: %s sets %q, which is not allowed in a config file (give it on the command line)", errConfig, source, name))
					continue
				case fs.Lookup(name) == nil:
					errs = append(errs, fmt.Errorf("%w: %s sets unknown setting %q", errConfig, source, name))
					continue
				}
				values, err := configValues(name, cfg[name])
				if err != nil {
					errs = append(errs, fmt.Errorf("%w: %s value for %s %w", errConfig, source, name, err))
					continue
				}
				if set(name, values, source) {
					d.sources[name] = sourceConfig
				}
			}
		}
	}

	fs.VisitAll(func(fl *flag.Flag) {
		if noDefaultFlags[fl.Name] {
			return
		}
		if v := d.getenv(envName(fl.Name)); v != "" && set(fl.Name, splitRepeat(fl.Name, v), envName(fl.Name)) {
			d.sources[fl.Name] = sourceEnv
		}
	})
	return errors.Join(errs...)
}

// source reports where a flag's effective value came from: flag, env,
// config or default.
func (d *defaultsLoader) source(fs *flag.FlagSet, name string) string {
	if flagSet(fs, name) {
		return sourceFlag
	}
	if d != nil {
		if s, ok := d.sources[name]; ok {
			return s
		}
	}
	return sourceDefault
}

// describe names where a non-default setting came from, for error messages:
// "-r", "SUBENUM_R" or "r in the config file".
func (d *defaultsLoader) describe(fs *flag.FlagSet, name string) string {
	switch d.source(fs, name) {
	case sourceEnv:
		return envName(name)
	case sourceConfig:
		return fmt.Sprintf("%q in the config file", name)
	default:
		return "-" + name
	}
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
		if rv, ok := fl.Value.(repeatValue); ok {
			// A JSON array, so ["a,b"] (one file) and ["a","b"] differ (#353).
			list, _ := json.Marshal(append([]string{}, rv.list()...))
			_, _ = fmt.Fprintf(w, "%-14s = %-24s (%s)\n", fl.Name, list, source)
			return
		}
		value := fl.Value.String()
		if fl.Name == "attempts" {
			value, source = d.effectiveAttempts(fset, value, source)
		}
		_, _ = fmt.Fprintf(w, "%-14s = %-24q (%s)\n", fl.Name, value, source)
	})
}

// effectiveAttempts resolves -attempts, whose flag value 0 means "unset", to
// the value a scan uses, merging the deprecated -retries (#153).
func (d *defaultsLoader) effectiveAttempts(fset *flag.FlagSet, value, source string) (string, string) {
	attempts, aerr := strconv.Atoi(value)
	retries, rerr := strconv.Atoi(fset.Lookup("retries").Value.String())
	if aerr != nil || rerr != nil {
		return value, source
	}
	n, fromRetries, err := effectiveAttempts(attempts, retries, d.source(fset, "attempts"), d.source(fset, "retries"))
	if err != nil {
		return value, source
	}
	if fromRetries {
		source = d.source(fset, "retries") + ", from retries"
	}
	return strconv.Itoa(n), source
}

// settings returns the effective value of every setting that came from the
// environment or the config file, keyed by flag name, for the TUI's form.
func (d *defaultsLoader) settings(fs *flag.FlagSet) map[string]string {
	out := map[string]string{}
	for name, src := range d.sources {
		if src == sourceEnv || src == sourceConfig {
			out[name] = fs.Lookup(name).Value.String()
		}
	}
	return out
}
