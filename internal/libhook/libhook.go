// Package libhook gives subenum's own front ends a pkg/subenum scan with
// engine settings the library's Config does not expose, without putting them
// in the library's API (#367). pkg/subenum registers its scan in an init
// function, so Run works in any program that imports the library.
package libhook

import (
	"context"

	"github.com/TMHSDigital/subenum/internal/scan"
)

// run is pkg/subenum's scan, a func(context.Context, subenum.Config,
// func(*scan.Options)) (<-chan subenum.Event, error). It is held as any
// because this package cannot import pkg/subenum, which imports it.
var run any

// Register records pkg/subenum's scan; its init calls it.
func Register[C, E any](f func(context.Context, C, func(*scan.Options)) (<-chan E, error)) {
	run = f
}

// Run is subenum.Run(ctx, cfg) with tweak applied to the engine's options
// once cfg's have been set. C and E are subenum.Config and subenum.Event.
func Run[C, E any](ctx context.Context, cfg C, tweak func(*scan.Options)) (<-chan E, error) {
	return run.(func(context.Context, C, func(*scan.Options)) (<-chan E, error))(ctx, cfg, tweak)
}
