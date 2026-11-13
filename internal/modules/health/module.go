// Package health serves the liveness and readiness probes, built on the
// health and readiness reports gas aggregates across its services.
package health

import (
	"context"
	"net/http"

	"github.com/gasmod/gas"
)

const moduleName = "tule/modules/health"

// The probe paths. The Lambda API lives under its dated prefixes
// (/2015-03-31/ and /2017-03-31/) and the retrieval API under /_functions/,
// so nothing they serve can shadow these.
const (
	HealthPath = "/_health"
	ReadyPath  = "/_ready"
)

// Module registers the probe routes and serves them.
type Module struct {
	router *gas.Router
	health gas.HealthProvider
	ready  gas.ReadyProvider
}

// NewModule returns a Module reporting from health and ready. It registers its
// routes when the app initializes it.
func NewModule(router *gas.Router, health gas.HealthProvider, ready gas.ReadyProvider) *Module {
	return &Module{router: router, health: health, ready: ready}
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// Init registers the module's routes.
func (m *Module) Init(context.Context) error {
	m.router.Handle(m, http.MethodGet, HealthPath, m.checkHealth) // Liveness
	m.router.Handle(m, http.MethodGet, ReadyPath, m.checkReady)   // Readiness
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

func (m *Module) checkHealth(ctx gas.Context) error {
	return writeReport(ctx, m.health.CheckHealth(ctx))
}

func (m *Module) checkReady(ctx gas.Context) error {
	return writeReport(ctx, m.ready.CheckReady(ctx))
}

// writeReport responds 200 when every service in results passed and 503
// otherwise, with each service's status as JSON.
func writeReport(ctx gas.Context, results map[string]error) error {
	status := http.StatusOK
	report := make(map[string]string, len(results))
	for name, err := range results {
		if err != nil {
			status = http.StatusServiceUnavailable
			report[name] = err.Error()
			continue
		}
		report[name] = "ok"
	}

	return ctx.JSON(status, report)
}
