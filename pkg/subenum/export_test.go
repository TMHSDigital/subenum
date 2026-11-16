package subenum

import "time"

// SetZonePort sends ProbeZone's transfers and DNSSEC probe to port, a local
// test server's. Call it from a test that is not parallel.
func SetZonePort(port string) func() {
	old := zonePort
	zonePort = port
	return func() { zonePort = old }
}

// SetDoneGrace shortens how long Run waits to deliver the final event after
// cancellation, so leak tests need not wait; it returns a restore function.
func SetDoneGrace(d time.Duration) func() {
	old := doneGrace.Swap(int64(d))
	return func() { doneGrace.Store(old) }
}
