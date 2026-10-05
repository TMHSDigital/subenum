package main

import (
	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/labzone"
	"github.com/TMHSDigital/subenum/internal/output"
)

// startLabZone serves the -simulate-zone scenario from a loopback DNS server
// and points -dns-server at it (#76). Unlike -simulate, the scan then runs
// the real resolver, wildcard detection, -rate pacing and reliability guard.
// It reports its own errors; stop shuts the server down.
func startLabZone(f *cliFlags, targets []string, out *output.Writer) (stop func(), ok bool) {
	zone, err := labzone.Load(f.simZone)
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
	out.Info("LAB MODE: answers come from %s, served on %s.", f.simZone, srv.Addr)
	out.Info("No DNS traffic leaves this machine.")
	out.Info("")
	return srv.Close, true
}
