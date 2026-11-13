package app

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"
	gaszerolog "github.com/gasmod/gas/log/zerolog"
	"github.com/rs/zerolog"

	"tule.dev/functions/internal/httpx"
	"tule.dev/functions/internal/util/buildinfo"
)

// newLogger returns the logger for env. Logs go to the console and nowhere
// else: there is no shipping sink here until Tule has a logging service to
// ship to.
func newLogger(env config.Environment) (gas.Logger, error) {
	if env.IsTesting() {
		return &gas.NopLogger{}, nil
	}
	if env.IsProductionLike() {
		return newProdLogger()
	}
	return newDevLogger()
}

func newProdLogger() (gas.Logger, error) {
	out := zerolog.ConsoleWriter{Out: os.Stderr}

	zl := zerolog.New(out).Level(zerolog.WarnLevel).With().Timestamp().
		Str("app_ver", buildinfo.Version).Logger()

	return newZeroLogger(&zl)
}

func newDevLogger() (gas.Logger, error) {
	out := zerolog.ConsoleWriter{Out: os.Stderr}

	zl := zerolog.New(out).Level(zerolog.TraceLevel).With().Timestamp().
		Str("app_ver", buildinfo.Version).Logger()

	return newZeroLogger(&zl)
}

// newZeroLogger returns a gas.Logger over zl. It returns a nil interface
// rather than a nil *gaszerolog.Logger when it fails.
func newZeroLogger(zl *zerolog.Logger) (gas.Logger, error) {
	l, err := gaszerolog.New(gaszerolog.WithLogger(zl))()
	if err != nil {
		return nil, err
	}
	return l, nil
}

func resolveRequestLogger(l gas.Logger) httpx.RequestLogger {
	return l.With().Logger()
}

// withRequestLogger puts the request-scoped logger on the request context.
// When it cannot be resolved the request fails with the service's internal
// error, logged through appLogger, since there is no request logger to log it
// with.
func withRequestLogger(appLogger gas.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger, err := gas.ResolveFromRequestScope[httpx.RequestLogger](r)
			if err != nil {
				ctx := gas.WithLogger(r.Context(), appLogger)
				writeError(w, r.WithContext(ctx),
					fmt.Errorf("resolve the request logger: %w", err))
				return
			}

			ctx := gas.WithLogger(r.Context(), logger)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
