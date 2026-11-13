// Package engine runs the functions: it checks their images, runs their
// invocations through the runner, synchronously, asynchronously with
// Lambda's retries, and from their event source mappings' pollers, and
// records every invocation in the history. It owns the Docker client, the
// Runtime API listener and the runner, as one gas service.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/runner"
	"tule.dev/functions/internal/runtimeapi"
)

// Engine is the functions service's runtime side.
type Engine struct {
	listener net.Listener
	logger   gas.Logger
	// ctx ends when the engine closes; the background work derives from it.
	ctx      context.Context
	store    contracts.Store
	server   *http.Server
	runtime  *runtimeapi.Server
	docker   *docker.Client
	runner   *runner.Runner
	settings *contracts.Settings
	bus      *gas.EventBus
	cancel   context.CancelFunc
	// mappingLocks serialize each mapping's state changes with its
	// poller's start and stop.
	mappingLocks map[string]*sync.Mutex
	pollers      map[string]context.CancelFunc
	// accessKeyID and secretAccessKey are the key the pollers sign with.
	accessKeyID     string
	secretAccessKey string
	wg              sync.WaitGroup
	mu              sync.Mutex
}

var _ gas.Service = (*Engine)(nil)

// New returns the constructor gas builds the Engine with. The pollers sign
// their SQS calls with the given key.
func New(settings *contracts.Settings, accessKeyID, secretAccessKey string) func(
	store contracts.Store, logger gas.Logger, bus *gas.EventBus,
) *Engine {
	return func(store contracts.Store, logger gas.Logger, bus *gas.EventBus) *Engine {
		return &Engine{
			store:           store,
			logger:          logger,
			bus:             bus,
			settings:        settings,
			runtime:         runtimeapi.NewServer(),
			pollers:         map[string]context.CancelFunc{},
			mappingLocks:    map[string]*sync.Mutex{},
			accessKeyID:     accessKeyID,
			secretAccessKey: secretAccessKey,
		}
	}
}

// Name identifies the service to gas.
func (e *Engine) Name() string {
	return "tule/services/functions/engine"
}

// Init connects to Docker and opens the Runtime API listener. The rest
// waits for Start, once the store's schema is applied.
func (e *Engine) Init(ctx context.Context) error {
	dc, err := docker.New(e.settings.DockerHost)
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	if err = dc.Ping(ctx); err != nil {
		return fmt.Errorf("engine: Docker at %s does not answer: %w", e.settings.DockerHost, err)
	}
	e.docker = dc
	bind := e.settings.RuntimeAPIBind
	if bind == "" {
		if bind, err = dc.HostAddress(ctx); err != nil {
			return fmt.Errorf("engine: find the address to serve the Runtime API on "+
				"(set TULE_Functions_RuntimeAPIBind): %w", err)
		}
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp",
		net.JoinHostPort(bind, strconv.Itoa(e.settings.RuntimeAPIPort)))
	if err != nil {
		return fmt.Errorf("engine: listen for the Runtime API: %w", err)
	}
	e.listener = ln
	e.server = runtimeapi.NewHTTPServer(e.runtime, e.settings.IdleTimeout)
	// The in-flight invocations end when the server begins to shut down,
	// with their containers removed, so the shutdown does not wait out a
	// synchronous invocation's timeout.
	e.bus.SubscribeWithOwner[gas.SystemServerShuttingDown](e,
		func(gas.SystemServerShuttingDownPayload) {
			if e.runner != nil {
				e.runner.Shutdown()
			}
		})
	go func() {
		if sErr := e.server.Serve(ln); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			e.logger.Error("the Runtime API server failed").Err("error", sErr).Send()
		}
	}()
	e.ctx, e.cancel = context.WithCancel(context.WithoutCancel(ctx))
	return nil
}

// RuntimeAPIPort returns the port the Runtime API listens on.
func (e *Engine) RuntimeAPIPort() int {
	return e.listener.Addr().(*net.TCPAddr).Port
}

// extraHosts maps host.docker.internal to the host's gateway when the
// containers are to reach the Runtime API by that name: Docker Desktop
// resolves it itself, a Linux daemon only with this mapping.
func (e *Engine) extraHosts() []string {
	if e.settings.RuntimeAPIHost == "host.docker.internal" {
		return []string{"host.docker.internal:host-gateway"}
	}
	return nil
}

// Start runs once the store is ready: it removes the containers a previous
// run on this store left behind, checks the images of the functions an
// interrupted run left pending, and starts the enabled mappings' pollers.
func (e *Engine) Start(ctx context.Context) error {
	instance, err := e.store.InstanceID(ctx)
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	cfg := runner.Config{
		Logger:  e.logger,
		Docker:  e.docker,
		Runtime: e.runtime,
		RuntimeAddr: net.JoinHostPort(
			e.settings.RuntimeAPIHost,
			strconv.Itoa(e.RuntimeAPIPort()),
		),
		ExtraHosts:         e.extraHosts(),
		InstanceID:         instance,
		Region:             e.settings.Region,
		MaxContainers:      e.settings.MaxContainers,
		MaxTotalContainers: e.settings.MaxTotalContainers,
		PidsLimit:          int64(e.settings.PidsLimit),
		IdleTimeout:        e.settings.IdleTimeout,
	}
	switch e.settings.FunctionCredentials {
	case contracts.CredentialsRoot:
		cfg.AccessKeyID, cfg.SecretAccessKey = e.accessKeyID, e.secretAccessKey
	case contracts.CredentialsCustom:
		cfg.AccessKeyID = e.settings.FunctionAccessKeyID
		cfg.SecretAccessKey = e.settings.FunctionSecretAccessKey
	}
	e.runner = runner.New(ctx, cfg)
	if err = e.runner.RemoveLeftovers(ctx); err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	if err = e.resumeFunctions(ctx); err != nil {
		return err
	}
	return e.resumeMappings(ctx)
}

// Close stops the pollers and the asynchronous invocations, removes every
// container, and closes the Runtime API listener.
func (e *Engine) Close(ctx context.Context) error {
	if e.cancel == nil {
		return nil
	}
	e.cancel()
	var errs []error
	if e.runner != nil {
		errs = append(errs, e.runner.Close(ctx))
	}
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		errs = append(errs, fmt.Errorf("engine: background work still running: %w", ctx.Err()))
	}
	if err := e.server.Close(); err != nil {
		errs = append(errs, fmt.Errorf("engine: close the Runtime API: %w", err))
	}
	e.docker.Close()
	return errors.Join(errs...)
}

// CheckReady reports the engine not ready until Start has run.
func (e *Engine) CheckReady(context.Context) error {
	if e.runner == nil {
		return errors.New("engine: not started")
	}
	return nil
}

// Containers returns the IDs of the function's live containers.
func (e *Engine) Containers(function string) []string {
	return e.runner.Containers(function)
}

// goBackground runs fn in the background, tracked so Close waits for it.
func (e *Engine) goBackground(fn func(ctx context.Context)) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		fn(e.ctx)
	}()
}
