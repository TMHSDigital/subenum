package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/labzone"
	"github.com/TMHSDigital/subenum/internal/output"
)

// builtinLab resolves a -simulate-zone value to a scenario compiled into the
// binary (#354), so a release, container or go install user can run the labs
// without the repository: "lab1", "lab1-first-scan" and
// "lab1-first-scan.zone" all name examples/labs/lab1-first-scan.zone. A value
// with a path separator, or one naming a file that exists, stays a path, so
// custom scenarios keep working.
func builtinLab(value string) (name string, ok bool) {
	if value == "" || strings.ContainsAny(value, `/\`) {
		return "", false
	}
	if _, err := os.Stat(value); err == nil {
		return "", false
	}
	value = strings.TrimSuffix(value, ".zone")
	for _, name := range labScenarios() {
		if name == value || strings.HasPrefix(name, value+"-") {
			return name, true
		}
	}
	return "", false
}

// loadLabZone reads the -simulate-zone scenario, from the binary when the
// value names a built-in one and from the file system otherwise. desc names
// it for the LAB MODE notice.
func loadLabZone(value string) (zone *labzone.Zone, desc string, err error) {
	if name, ok := builtinLab(value); ok {
		b, err := labFiles.ReadFile(path.Join(labDir, name+".zone"))
		if err != nil {
			return nil, "", err
		}
		zone, err := labzone.Parse(bytes.NewReader(b))
		if err != nil {
			return nil, "", fmt.Errorf("built-in scenario %s: %w", name, err)
		}
		return zone, "the built-in scenario " + name, nil
	}
	zone, err = labzone.Load(value)
	if errors.Is(err, fs.ErrNotExist) && !strings.ContainsAny(value, `/\`) {
		err = fmt.Errorf("%w; the built-in scenarios are %s", err, strings.Join(labScenarios(), ", "))
	}
	return zone, value, err
}

// startLabZone serves the -simulate-zone scenario from a loopback DNS server
// and points -dns-server at it (#76). Unlike -simulate, the scan then runs
// the real resolver, wildcard detection, -rate pacing and reliability guard.
// It reports its own errors; stop shuts the server down.
func startLabZone(f *cliFlags, targets []string, out *output.Writer) (stop func(), ok bool) {
	zone, desc, err := loadLabZone(f.simZone)
	if err != nil {
		out.Error("-simulate-zone: %v", err)
		return nil, false
	}
	srv, err := dnsserver.Listen(dnsserver.Options{}, zone.Handler(targets))
	if err != nil {
		out.Error("-simulate-zone: starting the local DNS server: %v", err)
		return nil, false
	}
	f.dnsServer = srv.Addr
	out.Info("")
	out.Info("LAB MODE: answers come from %s, served on %s.", desc, srv.Addr)
	out.Info("No DNS traffic leaves this machine.")
	out.Info("")
	return srv.Close, true
}
