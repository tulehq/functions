// Package app loads the configuration and wires the services, modules and
// middleware into a gas application.
package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"
	"tule.dev/sigv4"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/engine"
	"tule.dev/functions/internal/httpx"
	"tule.dev/functions/internal/modules/health"
	"tule.dev/functions/internal/modules/history"
	"tule.dev/functions/internal/modules/lambda"
	"tule.dev/functions/internal/services/functions/sqlimpl"
)

// startTimeout bounds the engine's start: the removal of the containers a
// previous run left behind, and the first look at the store.
const startTimeout = 2 * time.Minute

// New builds the application from cfg. extra options are applied after the
// app's own.
func New(cfg *Config, extra ...gas.Option) (*gas.App, error) {
	logger, lErr := newLogger(cfg.Env)
	if lErr != nil {
		return nil, lErr
	}

	// SQLite creates the database file but not the directory it sits in.
	if err := os.MkdirAll(filepath.Dir(cfg.Store.Path), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create the store directory: %w", err)
	}

	// Every request is authenticated by its signature, not by a cookie, so
	// the cross-origin protection meant for browser sessions would reject
	// every POST, PUT and DELETE an SDK makes.
	opts := append([]gas.Option{gas.WithCSRFInsecureBypassPattern("/")}, extra...)
	app := gas.NewApp(opts...)

	registerInfraServices(app, cfg, logger)
	registerAppServices(app, cfg)
	registerAppModules(app, cfg)

	// The engine starts once the store's schema is applied, which gas does
	// after every service's Init.
	app.ReadyFunc(func(c *gas.ServiceContainer) error {
		eng, err := c.Resolve[*engine.Engine]()
		if err != nil {
			return fmt.Errorf("resolve the engine: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
		defer cancel()
		return eng.Start(ctx)
	})

	verifier, err := newVerifier(cfg)
	if err != nil {
		return nil, err
	}
	installMiddleware(app.Router(), cfg, logger, verifier)

	return app, nil
}

func registerInfraServices(app *gas.App, cfg *Config, logger gas.Logger) {
	app.RegisterServiceInstance[gas.ConfigProvider](cfg.store)
	app.RegisterServiceInstance[gas.Logger](logger)
	app.RegisterScopedService[httpx.RequestLogger](resolveRequestLogger)
	app.RegisterSingletonService[gas.DatabaseProvider](
		database.New(database.WithConfig(databaseConfig(cfg.Store))))
	app.RegisterSingletonService[gas.MigrationManager](migrate.New())
}

// databaseConfig is the gas/database configuration of the store's SQLite
// file.
//
// The pool holds one connection. SQLite lets one writer in at a time, and a
// second connection that starts a transaction as a reader and then writes
// fails with SQLITE_BUSY at once rather than waiting, so every transaction
// goes through the one connection and waits its turn there. Each operation
// is one short transaction, so the queue is short.
func databaseConfig(store *sqlimpl.Settings) *database.Config {
	cfg := database.DefaultConfig()
	cfg.Database.Dialect = database.DialectSQLite
	cfg.Database.DSN = gas.Secret("file:" + store.Path)
	cfg.Database.MaxOpenConns = 1
	cfg.Database.MaxIdleConns = 1
	// The one connection is kept for as long as gas/database allows, rather
	// than reopened every 30 minutes, since nothing is gained by recycling a
	// connection to a local file.
	cfg.Database.ConnMaxLifetime = 2 * time.Hour
	cfg.Database.ConnMaxIdleTime = time.Hour
	return cfg
}

func registerAppServices(app *gas.App, cfg *Config) {
	app.RegisterSingletonService[contracts.Store](sqlimpl.NewService)
	app.RegisterSingletonService[*engine.Engine](
		engine.New(cfg.Functions, cfg.Auth.AccessKeyID, cfg.Auth.SecretAccessKey))
}

func registerAppModules(app *gas.App, cfg *Config) {
	app.RegisterSingletonService[*lambda.Module](lambda.NewModule(cfg.Functions))
	app.RegisterSingletonService[*history.Module](history.NewModule)
	app.RegisterSingletonService[*health.Module](health.NewModule)
}

func installMiddleware(r *gas.Router, cfg *Config, logger gas.Logger, verifier *sigv4.Verifier) {
	r.UseMiddlewareFunc(nil, httpx.RequestID(cfg.Env))

	// No X-Forwarded-For handling: nothing is expected in front of this
	// service, and the header is unsigned, so trusting a hop would only let a
	// caller choose the client IP that ends up in the logs.

	r.UseMiddlewareFunc(nil, withRequestLogger(logger))

	r.UseMiddlewareFunc(nil, gas.RequestLogger[httpx.RequestLogger]())

	r.UseMiddlewareFunc(nil, verifySignature(verifier))

	var hsts string
	if cfg.HSTS != nil && cfg.HSTS.MaxAge > 0 {
		hsts = fmt.Sprintf("max-age=%0.f", cfg.HSTS.MaxAge.Seconds())
	}
	r.UseMiddlewareFunc(nil, gas.SecurityHeaders(
		gas.WithSecurityHeadersStrictTransportSecurity(hsts),
	))

	installUnrouted(r)
}
