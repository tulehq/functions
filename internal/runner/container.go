package runner

import (
	"context"
	"errors"
	"sync"
	"time"

	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/runtimeapi"
)

// outcome is how a runtime completed an invocation: with a result, or with
// an error document.
type outcome struct {
	errorType string
	body      []byte
	failed    bool
}

// invocation is the request a container is running.
type invocation struct {
	done chan outcome
	id   string
}

// container is one function container and its side of the Runtime API. It
// runs one invocation at a time.
type container struct {
	lastUsed time.Time
	started  time.Time
	exitErr  error
	exited   chan struct{}
	ready    chan struct{}
	nexted   chan struct{}
	// pool is the function's pool the container holds a slot of, from its
	// registration until its removal completes.
	pool      *pool
	logsDone  chan struct{}
	initFails chan struct{}
	events    chan *runtimeapi.Event
	initFail  *outcome
	current   *invocation
	spec      *Spec
	id        string
	token     string
	logs      logBuffer
	initTime  time.Duration
	exitCode  int
	readyOnce sync.Once
	failOnce  sync.Once
	mu        sync.Mutex
	warm      bool
	// paused is set while the container is frozen between invocations.
	paused bool
	// The fields below are set under the Runner's lock: removing once the
	// container's removal has begun, queued once it has been handed to the
	// remover, which needs the container's ID, finished once its slots are
	// freed.
	removing bool
	queued   bool
	finished bool
}

var _ runtimeapi.Session = (*container)(nil)

func newContainer(spec *Spec, p *pool) *container {
	return &container{
		spec:      spec,
		pool:      p,
		token:     ids.Hex(16),
		events:    make(chan *runtimeapi.Event),
		ready:     make(chan struct{}),
		nexted:    make(chan struct{}, 1),
		exited:    make(chan struct{}),
		logsDone:  make(chan struct{}),
		initFails: make(chan struct{}),
	}
}

// errExited is Next's answer once the container is gone.
var errExited = errors.New("runner: the container is stopping")

// Next hands the runtime its next event. The first call marks the runtime
// initialized.
func (c *container) Next(ctx context.Context) (*runtimeapi.Event, error) {
	c.readyOnce.Do(func() {
		c.mu.Lock()
		c.initTime = time.Since(c.started)
		c.mu.Unlock()
		close(c.ready)
	})
	select {
	case c.nexted <- struct{}{}:
	default:
	}
	select {
	case ev := <-c.events:
		return ev, nil
	case <-c.exited:
		return nil, errExited
	case <-ctx.Done():
		return nil, ctx.Err() //nolint:wrapcheck // the request's own cancellation
	}
}

// complete delivers o to the invocation id names, if it is the one running
// and not yet completed.
func (c *container) complete(id string, o outcome) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil || c.current.id != id {
		return runtimeapi.ErrUnknownRequest
	}
	select {
	case c.current.done <- o:
		return nil
	default:
		// Already completed: a second response for the same request.
		return runtimeapi.ErrUnknownRequest
	}
}

// Respond completes the running invocation with its result.
func (c *container) Respond(id string, body []byte) error {
	return c.complete(id, outcome{body: body})
}

// Fail completes the running invocation with a function error.
func (c *container) Fail(id, errorType string, body []byte) error {
	return c.complete(id, outcome{failed: true, errorType: errorType, body: body})
}

// InitFail records the runtime's initialization error.
func (c *container) InitFail(errorType string, body []byte) {
	c.failOnce.Do(func() {
		c.mu.Lock()
		c.initFail = &outcome{failed: true, errorType: errorType, body: body}
		c.mu.Unlock()
		close(c.initFails)
	})
}

func (c *container) begin(inv *invocation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = inv
}

func (c *container) end() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = nil
	c.lastUsed = time.Now()
	c.warm = true
}

// clearNext drops the signal of the request that took the current event:
// only the signal of the runtime's next request tells that it is done.
func (c *container) clearNext() {
	select {
	case <-c.nexted:
	default:
	}
}

// initDuration is how long the runtime took to initialize, for the first
// invocation it runs, and 0 after.
func (c *container) initDuration() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.warm {
		return 0
	}
	return c.initTime
}

func (c *container) isExited() bool {
	select {
	case <-c.exited:
		return true
	default:
		return false
	}
}

func (c *container) exitStatus() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitCode, c.exitErr
}
