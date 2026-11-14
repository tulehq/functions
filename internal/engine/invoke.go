package engine

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"time"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/lambdaapi"
	"tule.dev/functions/internal/runner"
)

// asyncAttempts is how many times an asynchronous invocation runs when it
// keeps failing: once, and Lambda's default two retries.
const asyncAttempts = 3

// Invocable returns the function when it can be invoked: Active, or
// updating with a usable image. Otherwise it fails with
// ResourceConflictException, as Lambda does for a function that is not
// Active.
func (e *Engine) Invocable(ctx context.Context, name string) (*contracts.Function, error) {
	fn, err := e.function(ctx, name)
	if err != nil {
		return nil, err
	}
	if fn.State != contracts.StateActive || fn.Image.ID == "" {
		return nil, lambdaapi.ErrConflict("The operation cannot be performed at this time. " +
			"The function is currently in the following state: " + fn.State)
	}
	return fn, nil
}

// specOf is what fn's containers run.
func specOf(fn *contracts.Function) *runner.Spec {
	return &runner.Spec{
		Env:        fn.Environment,
		Function:   fn.Name,
		ARN:        fn.ARN,
		Role:       fn.Role,
		Revision:   fn.RevisionID,
		Image:      fn.Image.ID,
		WorkingDir: fn.ImageConfig.WorkingDirectory,
		EntryPoint: fn.ImageConfig.EntryPoint,
		Command:    fn.ImageConfig.Command,
		Timeout:    time.Duration(fn.Timeout) * time.Second,
		MemorySize: fn.MemorySize,
	}
}

// Invoke runs a synchronous invocation of fn and records it under source.
// At the function's cap it fails with TooManyRequestsException.
func (e *Engine) Invoke(
	ctx context.Context,
	fn *contracts.Function,
	source, requestID, clientContext string,
	payload []byte,
) (*runner.Result, error) {
	res, err := e.runner.Invoke(ctx, specOf(fn), &runner.Request{
		RequestID: requestID, ClientContext: clientContext, Payload: payload,
	})
	if errors.Is(err, runner.ErrThrottled) {
		return nil, lambdaapi.NewError(http.StatusTooManyRequests, lambdaapi.CodeTooManyRequests,
			"Rate Exceeded.")
	}
	if errors.Is(err, runner.ErrRetired) {
		return nil, e.errNotFound(fn.Name)
	}
	if err != nil {
		return nil, err
	}
	e.record(ctx, fn.Name, source, payload, res, 1)
	return res, nil
}

// InvokeAsync queues an asynchronous invocation of fn, recorded under
// source, and returns its request ID. It runs in the background, waiting
// for a container when the function is at its cap, and when it fails it
// runs again after AsyncRetryDelay, then after twice that.
func (e *Engine) InvokeAsync(fn *contracts.Function, source string, payload []byte) string {
	requestID := ids.UUID()
	name := fn.Name
	e.goBackground(func(ctx context.Context) {
		e.runAsync(ctx, name, source, requestID, payload)
	})
	return requestID
}

// The bounds of an asynchronous invocation's retries of errors that are
// not the function's own, a function not ready or a container that would
// not start: Lambda's backoff from 1 second to 5 minutes, for up to the
// default maximum event age, 6 hours.
const (
	systemRetryFirst = time.Second
	systemRetryMax   = 5 * time.Minute
	maxEventAge      = 6 * time.Hour
)

// runAsync runs an asynchronous invocation until it succeeds or its
// retries run out. A function error or timeout is retried twice, after
// AsyncRetryDelay and twice that, each attempt recorded; any other failure
// is retried with backoff until the function is gone or the event is too
// old, and then recorded as failed. Only a shutdown drops it unrecorded.
func (e *Engine) runAsync(ctx context.Context, name, source, requestID string, payload []byte) {
	queued := time.Now()
	backoff := systemRetryFirst
	for attempt := 1; ; {
		res, err := e.attemptAsync(ctx, name, requestID, payload)
		if errors.Is(err, runner.ErrClosed) || ctx.Err() != nil {
			return
		}
		if err != nil {
			if !e.retrySystemError(ctx, name, source, requestID, payload, err, attempt-1,
				time.Since(queued)+backoff, backoff) {
				return
			}
			backoff = min(2*backoff, systemRetryMax)
			continue
		}
		e.record(ctx, name, source, payload, res, attempt)
		if res.Status == runner.StatusSucceeded || attempt == asyncAttempts {
			return
		}
		if !sleepCtx(ctx, e.settings.AsyncRetryDelay*time.Duration(attempt)) {
			return
		}
		attempt++
	}
}

// retrySystemError waits backoff before an asynchronous invocation that
// could not run is tried again, and reports whether it is: one whose
// function is gone, or that would pass the maximum event age by then, is
// recorded as failed instead.
func (e *Engine) retrySystemError(
	ctx context.Context,
	name, source, requestID string,
	payload []byte,
	err error,
	attempts int,
	ageThen, backoff time.Duration,
) bool {
	if gone(err) || ageThen > maxEventAge {
		e.recordFailure(ctx, name, source, requestID, payload, err, attempts)
		return false
	}
	e.logger.Warn("an asynchronous invocation will be retried").Str("function", name).
		Str("requestId", requestID).Err("error", err).Send()
	return sleepCtx(ctx, backoff)
}

func (e *Engine) attemptAsync(
	ctx context.Context,
	name, requestID string,
	payload []byte,
) (*runner.Result, error) {
	fn, err := e.Invocable(ctx, name)
	if err != nil {
		return nil, err
	}
	return e.runner.Invoke(ctx, specOf(fn), &runner.Request{
		RequestID: requestID, Payload: payload, Wait: true,
	})
}

// gone reports whether err says the function no longer exists.
func gone(err error) bool {
	var apiErr *lambdaapi.Error
	return errors.Is(err, runner.ErrRetired) ||
		(errors.As(err, &apiErr) && apiErr.Code == lambdaapi.CodeResourceNotFound)
}

// recordFailure records an asynchronous invocation that could not be run,
// as failed under source, with the error that stopped it.
func (e *Engine) recordFailure(
	ctx context.Context,
	function, source, requestID string,
	payload []byte,
	cause error,
	attempts int,
) {
	errType, msg := lambdaapi.CodeService, cause.Error()
	var apiErr *lambdaapi.Error
	if errors.As(cause, &apiErr) {
		errType, msg = apiErr.Code, apiErr.Message
	} else if errors.Is(cause, runner.ErrRetired) {
		errType, msg = lambdaapi.CodeResourceNotFound, "Function not found: "+
			e.settings.FunctionARN(function)
	}
	doc, _ := json.Marshal(map[string]string{"errorType": errType, "errorMessage": msg})
	e.put(ctx, &contracts.Invocation{
		Time: time.Now().UTC(), RequestID: requestID, Function: function,
		Source: source, Status: contracts.StatusFailed,
		ErrorType: errType, ErrorMessage: msg, Payload: payload, Result: doc,
		Attempts: attempts,
	})
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// record adds the invocation to the history. A failure to record is logged:
// the invocation itself ran.
func (e *Engine) record(
	ctx context.Context,
	function, source string,
	payload []byte,
	res *runner.Result,
	attempt int,
) {
	inv := &contracts.Invocation{
		Time:         res.Start.UTC(),
		RequestID:    res.RequestID,
		Function:     function,
		Source:       source,
		Status:       res.Status,
		ErrorType:    res.ErrorType,
		ErrorMessage: res.ErrorMessage,
		Log:          res.Log,
		Payload:      payload,
		Result:       res.Payload,
		Duration:     math.Round(float64(res.Duration)/float64(time.Millisecond)*100) / 100,
		Attempts:     attempt,
	}
	e.put(ctx, inv)
}

// put adds inv to the history, within its bounds. A failure to record is
// logged: the invocation itself ran.
func (e *Engine) put(ctx context.Context, inv *contracts.Invocation) {
	if err := e.store.PutInvocation(context.WithoutCancel(ctx), inv, contracts.HistoryBounds{
		Rows: e.settings.HistoryLimit, Bytes: e.settings.HistoryMaxBytes,
	}); err != nil {
		e.logger.Error("failed to record an invocation").Str("requestId", inv.RequestID).
			Err("error", err).Send()
	}
}
