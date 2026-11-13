// Package runner runs function invocations in Docker containers that speak
// the Lambda Runtime API.
//
// A function's containers are kept warm and reused, one invocation at a
// time each. An invocation takes an idle container of the function's
// current revision, or starts one while the function has fewer than the
// configured cap; at the cap it waits for one or is throttled, as the caller
// asks. Idle containers are removed after the idle timeout, a container of
// an older revision once its invocation ends, and a container that timed
// out, crashed or exited at once. Every container carries the store's
// instance label, so all of them can be found and removed on shutdown, and
// those a crashed run left behind on the next start.
package runner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/runtimeapi"
)

// The labels every container carries.
const (
	LabelInstance = "dev.tule.functions.instance"
	LabelFunction = "dev.tule.functions.function"
)

// initTimeout bounds a runtime's initialization, from the container's start
// to its first invocation/next: Lambda's 10 seconds for an on-demand init.
const initTimeout = 10 * time.Second

// The waits for a completed invocation's output to arrive, as logBuffer's
// settle takes them, and for the runtime to ask for its next event, which
// it does at once once it has written everything.
const (
	logQuiet      = 25 * time.Millisecond
	logSettle     = 500 * time.Millisecond
	nextAfterDone = time.Second
)

// Config configures a Runner.
type Config struct {
	Logger  gas.Logger
	Docker  *docker.Client
	Runtime *runtimeapi.Server
	// RuntimeAddr is the host:port the containers reach the Runtime API at.
	RuntimeAddr string
	InstanceID  string
	Region      string
	// AccessKeyID and SecretAccessKey, when set, are every container's AWS
	// credentials.
	AccessKeyID     string
	SecretAccessKey string
	// ExtraHosts are added to every container's /etc/hosts, in Docker's
	// host:ip form.
	ExtraHosts []string
	// MaxContainers bounds one function's containers, MaxTotalContainers
	// every function's together.
	MaxContainers      int
	MaxTotalContainers int
	// PidsLimit bounds a container's processes and threads.
	PidsLimit   int64
	IdleTimeout time.Duration
}

// Spec is what a function's containers run: the function at one revision.
type Spec struct {
	Env        map[string]string
	Function   string
	ARN        string
	Revision   string
	Image      string
	WorkingDir string
	EntryPoint []string
	Command    []string
	Timeout    time.Duration
	MemorySize int
}

// Request is one invocation. Wait makes it wait for a container when the
// function, or the runner, is at its cap, rather than fail with
// ErrThrottled.
type Request struct {
	RequestID     string
	ClientContext string
	Payload       []byte
	Wait          bool
}

// The statuses of a Result.
const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusTimedOut  = "timedOut"
)

// Result is how an invocation ended. Payload is the function's result, or
// the error document Invoke answers with; FunctionError is "Unhandled" for
// a failed or timed-out invocation and "" otherwise.
type Result struct {
	Start         time.Time
	RequestID     string
	Status        string
	FunctionError string
	ErrorType     string
	ErrorMessage  string
	Log           string
	Payload       []byte
	Duration      time.Duration
}

// The errors Invoke returns when it could not run the invocation.
var (
	ErrThrottled = errors.New("runner: the function is running as many invocations as it may")
	ErrClosed    = errors.New("runner: shutting down")
	ErrRetired   = errors.New("runner: the function was deleted")
)

// Runner runs the invocations of every function.
//
// A container holds a slot of its function's MaxContainers, and of the
// runner's MaxTotalContainers, from the moment it is registered, before it
// is created, until its removal completes: a container being retired keeps
// counting against the caps until it is gone.
type Runner struct {
	pools map[string]*pool
	// changed is closed, and replaced, whenever a slot frees or a container
	// goes idle, which is what a waiting invocation waits for.
	changed chan struct{}
	// wake tells the remover that removals are queued.
	wake chan struct{}
	// done is closed once Close has waited for everything; the remover
	// then exits.
	done chan struct{}
	// removals are the containers queued for removal.
	removals []*container
	stop     chan struct{}
	cfg      Config
	wg       sync.WaitGroup
	// live counts the containers of every function.
	live     int
	doneOnce sync.Once
	mu       sync.Mutex
	closed   bool
}

// pool is one function's containers: idle, and busy (starting or running
// an invocation). live counts them with those being removed. Revisions
// retired by an update are not reused; revisions dead with a deleted
// function are not run at all.
type pool struct {
	busy     map[*container]struct{}
	retired  map[string]bool
	dead     map[string]bool
	seen     map[string]bool
	function string
	idle     []*container
	live     int
}

// New returns a Runner and starts its idle reaper and its remover. The
// containers' removals run on ctx without its cancellation: Close waits
// for them instead.
func New(ctx context.Context, cfg Config) *Runner {
	r := &Runner{
		cfg:     cfg,
		pools:   map[string]*pool{},
		changed: make(chan struct{}),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		wake:    make(chan struct{}, 1),
	}
	r.wg.Add(1)
	go r.reap()
	go r.remover(context.WithoutCancel(ctx))
	return r
}

// poolLocked returns the function's pool, made on first use; r.mu is held.
func (r *Runner) poolLocked(function string) *pool {
	p, ok := r.pools[function]
	if !ok {
		p = &pool{
			function: function,
			busy:     map[*container]struct{}{},
			retired:  map[string]bool{},
			dead:     map[string]bool{},
			seen:     map[string]bool{},
		}
		r.pools[function] = p
	}
	return p
}

// broadcastLocked wakes the invocations waiting for a container; r.mu is
// held.
func (r *Runner) broadcastLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// Invoke runs req on a container of spec's function.
func (r *Runner) Invoke(ctx context.Context, spec *Spec, req *Request) (*Result, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, ErrClosed
	}
	r.wg.Add(1)
	p := r.poolLocked(spec.Function)
	r.mu.Unlock()
	defer r.wg.Done()

	c, err := r.acquire(ctx, p, spec, req.Wait)
	if err != nil {
		return nil, err
	}
	if c.id == "" {
		var res *Result
		if res, err = r.coldStart(ctx, c, req); err != nil || res != nil {
			return res, err
		}
	} else if err = r.unpause(ctx, c); err != nil {
		r.release(c)
		return nil, err
	}
	res, err := r.run(ctx, c, req)
	r.release(c)
	return res, err
}

// acquire returns an idle container of spec's revision, or registers a new
// one, which the caller starts, while the caps allow; otherwise it waits,
// or fails with ErrThrottled when wait is not set.
func (r *Runner) acquire(ctx context.Context, p *pool, spec *Spec, wait bool) (*container, error) {
	for {
		r.mu.Lock()
		c, err := r.takeLocked(p, spec)
		if c != nil || err != nil {
			r.mu.Unlock()
			return c, err
		}
		changed := r.changed
		r.mu.Unlock()
		if !wait {
			return nil, ErrThrottled
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err() //nolint:wrapcheck // the caller's own cancellation
		case <-r.stop:
			return nil, ErrClosed
		}
	}
}

// takeLocked takes an idle container of spec's revision, or registers a
// new one within the caps, evicting another function's idle container when
// only the runner's cap is in the way; r.mu is held. It returns neither
// when the invocation must wait.
func (r *Runner) takeLocked(p *pool, spec *Spec) (*container, error) {
	if r.closed {
		return nil, ErrClosed
	}
	if p.dead[spec.Revision] {
		return nil, ErrRetired
	}
	for i := len(p.idle) - 1; i >= 0; i-- {
		// The most recently used first, so the others go idle long enough
		// to be reaped when the load drops.
		c := p.idle[i]
		if c.spec.Revision != spec.Revision || c.removing {
			continue
		}
		p.idle = append(p.idle[:i], p.idle[i+1:]...)
		if c.isExited() {
			r.removeLocked(c)
			continue
		}
		p.busy[c] = struct{}{}
		return c, nil
	}
	if p.live >= r.cfg.MaxContainers {
		return nil, nil
	}
	if r.live >= r.cfg.MaxTotalContainers {
		r.evictLocked()
		return nil, nil
	}
	c := newContainer(spec, p)
	p.live++
	r.live++
	p.seen[spec.Revision] = true
	p.busy[c] = struct{}{}
	return c, nil
}

// evictLocked removes the least recently used idle container of any
// function, to make room under the runner's cap; r.mu is held.
func (r *Runner) evictLocked() {
	var oldest *container
	for _, p := range r.pools {
		for _, c := range p.idle {
			if !c.removing && (oldest == nil || c.lastUsed.Before(oldest.lastUsed)) {
				oldest = c
			}
		}
	}
	if oldest != nil {
		oldest.pool.idle = slices.DeleteFunc(oldest.pool.idle,
			func(c *container) bool { return c == oldest })
		r.removeLocked(oldest)
	}
}

// release returns c to its pool's idle list, or removes it when it exited,
// timed out, or belongs to a retired revision.
func (r *Runner) release(c *container) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := c.pool
	delete(p.busy, c)
	if r.closed || c.removing || c.isExited() || p.retired[c.spec.Revision] ||
		p.dead[c.spec.Revision] {
		r.removeLocked(c)
		return
	}
	p.idle = append(p.idle, c)
	r.broadcastLocked()
}

// coldStart starts the registered container c and waits for its runtime to
// ask for an event. When the runtime fails to initialize, it returns the
// invocation's result instead.
func (r *Runner) coldStart(ctx context.Context, c *container, req *Request) (*Result, error) {
	start := time.Now()
	if err := r.startContainer(ctx, c); err != nil {
		r.release(c)
		return nil, err
	}
	timer := time.NewTimer(initTimeout)
	defer timer.Stop()
	var (
		res *Result
		err error
	)
	select {
	case <-c.ready:
		return nil, nil
	case <-c.initFails:
		c.mu.Lock()
		o := *c.initFail
		c.mu.Unlock()
		res = r.errorResult(req, start, o)
	case <-c.exited:
		res = r.exitResult(c, req, start)
	case <-timer.C:
		res = r.timedOut(c, req, start, initTimeout)
	case <-ctx.Done():
		err = ctx.Err()
	case <-r.stop:
		err = ErrClosed
	}
	r.remove(c)
	if res != nil {
		res = r.finish(c, "", 0, res)
	}
	r.release(c)
	return res, err
}

// run hands req to c and waits for its outcome, the container's exit or the
// timeout.
func (r *Runner) run(ctx context.Context, c *container, req *Request) (*Result, error) {
	inv := &invocation{id: req.RequestID, done: make(chan outcome, 1)}
	c.begin(inv)
	defer c.end()
	initTime := c.initDuration()
	before := c.logs.take()
	start := time.Now()
	ev := &runtimeapi.Event{
		RequestID:     req.RequestID,
		Deadline:      start.Add(c.spec.Timeout),
		FunctionARN:   c.spec.ARN,
		TraceID:       traceID(start),
		ClientContext: req.ClientContext,
		Payload:       req.Payload,
	}
	timer := time.NewTimer(c.spec.Timeout)
	defer timer.Stop()
	res, err := r.await(ctx, c, inv, ev, timer.C)
	if err != nil {
		return nil, err
	}
	r.pause(ctx, c)
	return r.finish(c, before, initTime, res), nil
}

// pause freezes c, as Lambda freezes an execution environment between
// invocations: what the function left running, a goroutine writing output
// among it, does not run until the next invocation thaws it. A container
// that cannot be paused, or is already going, is removed.
func (r *Runner) pause(ctx context.Context, c *container) {
	if c.isExited() || r.isRemoving(c) {
		return
	}
	if err := r.cfg.Docker.PauseContainer(context.WithoutCancel(ctx), c.id); err != nil {
		r.cfg.Logger.Warn("failed to pause a function container").Str("container", c.id).
			Err("error", err).Send()
		r.remove(c)
		return
	}
	c.mu.Lock()
	c.paused = true
	c.mu.Unlock()
}

// unpause thaws c before it is handed an event. A container that cannot be
// thawed is removed, and the invocation fails.
func (r *Runner) unpause(ctx context.Context, c *container) error {
	c.mu.Lock()
	paused := c.paused
	c.mu.Unlock()
	if !paused {
		return nil
	}
	if err := r.cfg.Docker.UnpauseContainer(ctx, c.id); err != nil {
		r.remove(c)
		return fmt.Errorf("runner: thaw container %s: %w", c.id, err)
	}
	c.mu.Lock()
	c.paused = false
	c.mu.Unlock()
	return nil
}

// await hands ev to c's runtime and waits for its outcome, the container's
// exit or the timeout.
func (r *Runner) await(
	ctx context.Context,
	c *container,
	inv *invocation,
	ev *runtimeapi.Event,
	timeout <-chan time.Time,
) (*Result, error) {
	req := &Request{RequestID: ev.RequestID}
	start := ev.Deadline.Add(-c.spec.Timeout)
	send := c.events
	for {
		select {
		case send <- ev:
			send = nil
			c.clearNext()
		case o := <-inv.done:
			r.afterDone(c)
			return r.completed(req, start, o), nil
		case <-c.exited:
			return r.exitResult(c, req, start), nil
		case <-timeout:
			return r.timedOut(c, req, start, c.spec.Timeout), nil
		case <-ctx.Done():
			r.remove(c)
			return nil, ctx.Err() //nolint:wrapcheck // the caller's own cancellation
		case <-r.stop:
			return nil, ErrClosed
		}
	}
}

// afterDone waits for the output of a completed invocation. The runtime
// asks for its next event once it has written all it will; the output then
// still has to come through the stream. A runtime that neither asks nor
// exits by then is stuck, and is not used again; one that exits, as
// aws-lambda-go does after a panic, is not either.
func (r *Runner) afterDone(c *container) {
	select {
	case <-c.nexted:
	case <-c.exited:
	case <-time.After(nextAfterDone):
		r.remove(c)
	}
	c.logs.settle(time.Now(), logQuiet, logSettle)
}

// finish writes the result's log: the output before the event, START, the
// output during it, END and REPORT.
func (r *Runner) finish(c *container, before string, initTime time.Duration, res *Result) *Result {
	if c.isExited() || r.isRemoving(c) {
		// The stream ends once the container is gone; wait for the rest of
		// its output.
		select {
		case <-c.logsDone:
		case <-time.After(logSettle):
		}
	}
	before, during := capOutput(before, c.logs.take())
	res.Log = invocationLog(before, during, &report{
		requestID:  res.RequestID,
		duration:   res.Duration,
		init:       initTime,
		memorySize: c.spec.MemorySize,
		timedOut:   res.Status == StatusTimedOut,
	})
	return res
}

func (r *Runner) isRemoving(c *container) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return c.removing
}

// traceID returns an X-Ray trace header for an invocation started at t,
// not sampled.
func traceID(t time.Time) string {
	return fmt.Sprintf("Root=1-%08x-%s;Parent=%s;Sampled=0", t.Unix(), ids.Hex(12), ids.Hex(8))
}

// Retire removes the function's containers: the idle ones now, and the
// busy ones once their invocation ends. They keep counting against the
// caps until they are gone. The next invocation starts a fresh container.
func (r *Runner) Retire(function string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.poolLocked(function)
	for rev := range p.seen {
		p.retired[rev] = true
	}
	r.removeIdleLocked(p)
}

// Delete removes the function's containers at once, those starting or
// running an invocation included, and refuses invocations of every
// revision the function has run, or of revision, with ErrRetired.
func (r *Runner) Delete(function, revision string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.poolLocked(function)
	p.seen[revision] = true
	for rev := range p.seen {
		p.dead[rev] = true
	}
	r.removeIdleLocked(p)
	for c := range p.busy {
		r.removeLocked(c)
	}
}

func (r *Runner) removeIdleLocked(p *pool) {
	for _, c := range p.idle {
		r.removeLocked(c)
	}
	p.idle = nil
}

// Containers returns the IDs of the function's containers, created and
// not yet removed, sorted.
func (r *Runner) Containers(function string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pools[function]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(p.idle)+len(p.busy))
	for _, c := range p.idle {
		out = append(out, c.id)
	}
	for c := range p.busy {
		if c.id != "" {
			out = append(out, c.id)
		}
	}
	sort.Strings(out)
	return out
}

// Live returns how many containers count against the function's cap, and
// against the runner's.
func (r *Runner) Live(function string) (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	if p, ok := r.pools[function]; ok {
		n = p.live
	}
	return n, r.live
}

// reap removes the containers idle for longer than the idle timeout.
func (r *Runner) reap() {
	defer r.wg.Done()
	every := min(max(r.cfg.IdleTimeout/4, 100*time.Millisecond), 30*time.Second)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
		}
		r.mu.Lock()
		for _, p := range r.pools {
			kept := p.idle[:0]
			for _, c := range p.idle {
				if c.isExited() || time.Since(c.lastUsed) > r.cfg.IdleTimeout {
					r.removeLocked(c)
					continue
				}
				kept = append(kept, c)
			}
			p.idle = kept
		}
		r.mu.Unlock()
	}
}

// Shutdown stops taking invocations, fails those in flight with ErrClosed,
// and starts removing every container. It returns at once; Close waits.
func (r *Runner) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	close(r.stop)
	for _, p := range r.pools {
		r.removeIdleLocked(p)
		for c := range p.busy {
			r.removeLocked(c)
		}
	}
	r.broadcastLocked()
}

// Close shuts the runner down and waits, as long as ctx allows, for the
// invocations in flight to return and every container to be removed.
func (r *Runner) Close(ctx context.Context) error {
	r.Shutdown()
	waited := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
		r.doneOnce.Do(func() { close(r.done) })
		return nil
	case <-ctx.Done():
		return fmt.Errorf("runner: containers still being removed: %w", ctx.Err())
	}
}

// RemoveLeftovers removes every container carrying this instance's label:
// those a run that did not shut down cleanly left behind.
func (r *Runner) RemoveLeftovers(ctx context.Context) error {
	found, err := r.cfg.Docker.ListContainers(ctx, LabelInstance, r.cfg.InstanceID)
	if err != nil {
		return fmt.Errorf("runner: list leftover containers: %w", err)
	}
	for _, id := range found {
		if rErr := r.cfg.Docker.RemoveContainer(ctx, id); rErr != nil {
			return fmt.Errorf("runner: remove leftover container %s: %w", id, rErr)
		}
	}
	return nil
}
