package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/ids"
)

// removeTimeout bounds one container's removal.
const removeTimeout = 30 * time.Second

// logMaxSize bounds what Docker's log driver keeps of a container's output:
// the service reads it from the attach stream, so Docker's copy is only for
// docker logs.
const logMaxSize = "10m"

// errDeletedMeanwhile fails a cold start whose function was deleted while
// its container was being created.
var errDeletedMeanwhile = fmt.Errorf("%w while its container was being created", ErrRetired)

// startContainer creates, attaches to and starts the registered container
// c, served by the Runtime API under its token. A container whose removal
// began while Docker created it, as a DeleteFunction does, is removed at
// once.
func (r *Runner) startContainer(ctx context.Context, c *container) error {
	spec := c.spec
	creds, err := r.credentials(ctx, c)
	if err != nil {
		return err
	}
	r.cfg.Runtime.Register(c.token, c)
	id, err := r.cfg.Docker.CreateContainer(ctx, r.containerSpec(c, creds))
	r.mu.Lock()
	if err != nil {
		r.removeLocked(c)
		r.finishLocked(c)
		r.mu.Unlock()
		close(c.logsDone)
		return fmt.Errorf("runner: create a container for %s: %w", spec.Function, err)
	}
	c.id = id
	if c.removing {
		r.queueLocked(c)
		r.mu.Unlock()
		close(c.logsDone)
		return errDeletedMeanwhile
	}
	r.mu.Unlock()
	// From here the container exists, so every failure removes it. The
	// attach and the wait outlive ctx: they end with the container.
	if err = r.attach(ctx, c); err != nil {
		return err
	}

	c.started = time.Now()
	if err = r.cfg.Docker.StartContainer(ctx, id); err != nil {
		if r.removeStarting(c) {
			return errDeletedMeanwhile
		}
		return fmt.Errorf("runner: start container %s: %w", id, err)
	}
	// Waiting for a container that is not running returns at once, so the
	// wait starts once the container has.
	r.wg.Add(1)
	go r.watch(context.WithoutCancel(ctx), c)
	return nil
}

// attach attaches to c's created container and copies its output into
// c's logs until the container ends. When the attach fails, c's removal
// begins.
func (r *Runner) attach(ctx context.Context, c *container) error {
	stream, err := r.cfg.Docker.Attach(context.WithoutCancel(ctx), c.id)
	if err != nil {
		deleted := r.removeStarting(c)
		close(c.logsDone)
		if deleted {
			return errDeletedMeanwhile
		}
		return fmt.Errorf("runner: attach to container %s: %w", c.id, err)
	}
	go func() {
		defer close(c.logsDone)
		defer func() { _ = stream.Close() }()
		if dErr := docker.Demux(stream, &c.logs); dErr != nil {
			r.cfg.Logger.Debug("container output ended").Str("container", c.id).
				Err("error", dErr).Send()
		}
	}()
	return nil
}

// containerSpec is what c is created as, with creds as its credentials.
func (r *Runner) containerSpec(c *container, creds *Credentials) *docker.ContainerSpec {
	spec := c.spec
	return &docker.ContainerSpec{
		Name:        "tule-fn-" + spec.Function + "-" + ids.Hex(4),
		Image:       spec.Image,
		Entrypoint:  spec.EntryPoint,
		Cmd:         spec.Command,
		WorkingDir:  spec.WorkingDir,
		Env:         r.environment(spec, c.token, creds),
		ExtraHosts:  r.cfg.ExtraHosts,
		MemoryBytes: int64(spec.MemorySize) << 20,
		PidsLimit:   r.cfg.PidsLimit,
		LogMaxSize:  logMaxSize,
		Labels: map[string]string{
			LabelInstance: r.cfg.InstanceID,
			LabelFunction: spec.Function,
		},
	}
}

// credentials returns the credentials c starts with, from Credentials when
// it is set, or nil. When they cannot be had, c is given up as a container
// that could not be created is.
func (r *Runner) credentials(ctx context.Context, c *container) (*Credentials, error) {
	if r.cfg.Credentials == nil {
		return nil, nil
	}
	creds, err := r.cfg.Credentials(ctx, c.spec)
	if err != nil {
		r.mu.Lock()
		r.removeLocked(c)
		r.finishLocked(c)
		r.mu.Unlock()
		close(c.logsDone)
		return nil, fmt.Errorf("runner: credentials for %s: %w", c.spec.Function, err)
	}
	c.expires = creds.Expiration
	return creds, nil
}

// watch waits for the container to exit, and records its exit status.
func (r *Runner) watch(ctx context.Context, c *container) {
	defer r.wg.Done()
	code, err := r.cfg.Docker.WaitContainer(ctx, c.id)
	c.mu.Lock()
	c.exitCode, c.exitErr = code, err
	c.mu.Unlock()
	close(c.exited)
}

// environment is the container's environment: the function's variables,
// then the ones Lambda defines, which a function cannot set, with creds as
// its credentials when they are given.
func (r *Runner) environment(spec *Spec, token string, creds *Credentials) []string {
	env := make([]string, 0, len(spec.Env)+12)
	keys := make([]string, 0, len(spec.Env))
	for k := range spec.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+spec.Env[k])
	}
	switch {
	case creds != nil:
		// The variables Lambda sets from the function's role.
		env = append(env,
			"AWS_ACCESS_KEY_ID="+creds.AccessKeyID,
			"AWS_ACCESS_KEY="+creds.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
			"AWS_SESSION_TOKEN="+creds.SessionToken,
		)
	case r.cfg.AccessKeyID != "":
		// The variables Lambda sets from the function's role, but for
		// AWS_SESSION_TOKEN: a static key has none.
		env = append(env,
			"AWS_ACCESS_KEY_ID="+r.cfg.AccessKeyID,
			"AWS_ACCESS_KEY="+r.cfg.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY="+r.cfg.SecretAccessKey,
		)
	}
	// The stream name gets an ID of its own: the token, which a process in
	// the container could read from the name, is the container's key to the
	// Runtime API.
	stream := time.Now().UTC().Format("2006/01/02") + "/[$LATEST]" + ids.Hex(16)
	return append(env,
		"AWS_LAMBDA_RUNTIME_API="+r.cfg.RuntimeAddr+"/"+token,
		"AWS_LAMBDA_FUNCTION_NAME="+spec.Function,
		"AWS_LAMBDA_FUNCTION_MEMORY_SIZE="+strconv.Itoa(spec.MemorySize),
		"AWS_LAMBDA_FUNCTION_VERSION=$LATEST",
		"AWS_LAMBDA_INITIALIZATION_TYPE=on-demand",
		"AWS_LAMBDA_LOG_GROUP_NAME=/aws/lambda/"+spec.Function,
		"AWS_LAMBDA_LOG_STREAM_NAME="+stream,
		"AWS_REGION="+r.cfg.Region,
		"AWS_DEFAULT_REGION="+r.cfg.Region,
		"LAMBDA_TASK_ROOT=/var/task",
		"LAMBDA_RUNTIME_DIR=/var/runtime",
	)
}

// remove removes c in the background.
func (r *Runner) remove(c *container) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(c)
}

// removeStarting begins the removal of c, which failed to start, and
// reports whether its removal had already begun: a delete that raced the
// start, which Docker then refuses to start a container marked for removal
// for.
func (r *Runner) removeStarting(c *container) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	deleted := c.removing
	r.removeLocked(c)
	return deleted
}

// removeLocked begins c's removal, once; r.mu is held. A container Docker
// has not created yet is removed once it has been.
func (r *Runner) removeLocked(c *container) {
	if c.removing {
		return
	}
	c.removing = true
	r.cfg.Runtime.Unregister(c.token)
	if c.id != "" {
		r.queueLocked(c)
	}
}

// queueLocked hands c to the remover; r.mu is held.
func (r *Runner) queueLocked(c *container) {
	if c.queued {
		return
	}
	c.queued = true
	r.wg.Add(1)
	r.removals = append(r.removals, c)
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// finishLocked frees c's slots once it is gone; r.mu is held.
func (r *Runner) finishLocked(c *container) {
	if c.finished {
		return
	}
	c.finished = true
	p := c.pool
	delete(p.busy, c)
	p.idle = slices.DeleteFunc(p.idle, func(i *container) bool { return i == c })
	p.live--
	r.live--
	r.broadcastLocked()
}

// remover removes the queued containers, each in its own goroutine, until
// Close has waited for every removal.
func (r *Runner) remover(ctx context.Context) {
	for {
		select {
		case <-r.wake:
		case <-r.done:
			return
		}
		r.mu.Lock()
		queued := r.removals
		r.removals = nil
		r.mu.Unlock()
		for _, c := range queued {
			go r.removeContainer(ctx, c)
		}
	}
}

func (r *Runner) removeContainer(ctx context.Context, c *container) {
	defer r.wg.Done()
	rctx, cancel := context.WithTimeout(ctx, removeTimeout)
	defer cancel()
	if err := r.cfg.Docker.RemoveContainer(rctx, c.id); err != nil {
		r.cfg.Logger.Error("failed to remove a function container").
			Str("container", c.id).Err("error", err).Send()
	}
	r.mu.Lock()
	r.finishLocked(c)
	r.mu.Unlock()
}

// errorDoc is the error document an invocation answers with: the shape the
// Runtime API's error requests and Invoke's error payloads take.
type errorDoc struct {
	ErrorMessage string          `json:"errorMessage"`
	ErrorType    string          `json:"errorType,omitempty"`
	StackTrace   json.RawMessage `json:"stackTrace,omitempty"`
}

// completed is the result of an invocation the runtime completed.
func (r *Runner) completed(req *Request, start time.Time, o outcome) *Result {
	if !o.failed {
		return &Result{
			RequestID: req.RequestID,
			Start:     start,
			Duration:  time.Since(start),
			Status:    StatusSucceeded,
			Payload:   o.body,
		}
	}
	return r.errorResult(req, start, o)
}

// errorResult is the result of a function error. The runtime's error
// document is answered as it sent it, when it is a JSON object; anything
// else is wrapped in one, typed by the Lambda-Runtime-Function-Error-Type
// header.
func (r *Runner) errorResult(req *Request, start time.Time, o outcome) *Result {
	var doc errorDoc
	payload := o.body
	if json.Unmarshal(o.body, &doc) != nil || !isObject(o.body) {
		doc = errorDoc{ErrorMessage: strings.TrimSpace(string(o.body)), ErrorType: o.errorType}
		if doc.ErrorType == "" {
			doc.ErrorType = "Function.Unknown"
		}
		payload, _ = json.Marshal(doc)
	}
	if doc.ErrorType == "" {
		doc.ErrorType = o.errorType
	}
	return &Result{
		RequestID:     req.RequestID,
		Start:         start,
		Duration:      time.Since(start),
		Status:        StatusFailed,
		FunctionError: "Unhandled",
		ErrorType:     doc.ErrorType,
		ErrorMessage:  doc.ErrorMessage,
		Payload:       payload,
	}
}

func isObject(b []byte) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(b, &m) == nil
}

// exitResult is the result of an invocation whose container exited before
// completing it: Runtime.ExitError, with the exit status.
func (r *Runner) exitResult(c *container, req *Request, start time.Time) *Result {
	code, err := c.exitStatus()
	reason := "exit status " + strconv.Itoa(code)
	if err != nil {
		reason = err.Error()
	}
	doc := errorDoc{
		ErrorType: "Runtime.ExitError",
		ErrorMessage: "RequestId: " + req.RequestID +
			" Error: Runtime exited with error: " + reason,
	}
	return r.docResult(req, start, StatusFailed, doc)
}

// timedOut is the result of an invocation that ran out of time: its
// container is removed, and the error is Sandbox.Timedout.
func (r *Runner) timedOut(
	c *container,
	req *Request,
	start time.Time,
	limit time.Duration,
) *Result {
	r.remove(c)
	doc := errorDoc{
		ErrorType: "Sandbox.Timedout",
		ErrorMessage: fmt.Sprintf("RequestId: %s Error: Task timed out after %.2f seconds",
			req.RequestID, limit.Seconds()),
	}
	res := r.docResult(req, start, StatusTimedOut, doc)
	res.Duration = limit
	return res
}

func (r *Runner) docResult(req *Request, start time.Time, status string, doc errorDoc) *Result {
	payload, _ := json.Marshal(doc)
	return &Result{
		RequestID:     req.RequestID,
		Start:         start,
		Duration:      time.Since(start),
		Status:        status,
		FunctionError: "Unhandled",
		ErrorType:     doc.ErrorType,
		ErrorMessage:  doc.ErrorMessage,
		Payload:       payload,
	}
}
