package subenum

import "time"

// SetDoneGrace shortens how long Run waits to deliver the final event after
// cancellation, so leak tests need not wait; it returns a restore function.
func SetDoneGrace(d time.Duration) func() {
	old := doneGrace
	doneGrace = d
	return func() { doneGrace = old }
}
