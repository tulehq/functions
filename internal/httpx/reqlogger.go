package httpx

import (
	"context"

	"github.com/gasmod/gas"
)

// RequestLogger is the request-scoped logger. It is a type of its own rather
// than a plain gas.Logger so the container can resolve a per-request logger
// separately from the application-wide one.
type RequestLogger interface{ gas.Logger }

var nop = &gas.NopLogger{}

// Logger returns the logger carried by ctx. It falls back to a no-op logger so
// callers never have to nil-check the result.
func Logger(ctx context.Context) gas.Logger {
	if l := gas.LoggerFromContext(ctx); l != nil {
		return l
	}
	return nop
}
