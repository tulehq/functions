//go:build e2e

package e2e

import (
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// These tests use the service's own settings: TULE_Functions_AsyncRetryDelay
// to make Lambda's async retries quick, and TULE_Functions_MaxContainers to
// reach the concurrency cap.

func TestAsyncRetries(t *testing.T) {
	// "if you invoke a function asynchronously and it returns an error,
	// Lambda executes the function up to two more times" (Invoke): three
	// attempts in all, and no more. The delay is 1s, then 2s.
	srv := startServer(t, map[string]string{"TULE_Functions_AsyncRetryDelay": "1s"})
	c := clientFor(srv)
	createFunction(t, c, "flaky", "errors", nil)
	out := invokeWith(t, c, &lambda.InvokeInput{
		FunctionName:   aws.String("flaky"),
		InvocationType: types.InvocationTypeEvent,
		Payload:        []byte(`{"message":"again"}`),
	})
	requireEqual(t, out.StatusCode, int32(202), "Event status")

	h := historyFor(srv)
	eventually(t, 30*time.Second, "three attempts", func() bool {
		return attemptsOf(t, h, "flaky") >= 3
	})
	time.Sleep(5 * time.Second)
	requireEqual(t, attemptsOf(t, h, "flaky"), 3, "attempts after the retries")
	for _, it := range h.all(t, url.Values{"function": {"flaky"}}) {
		requireEqual(t, it.Source, "async", "source of an attempt")
		requireEqual(t, it.Status, "failed", "status of an attempt")
	}
}

// attemptsOf counts the attempts recorded for function. Assumption: the
// history records each attempt as an item, or one item whose attempts
// field counts them; this takes whichever is larger.
func attemptsOf(t *testing.T, h *history, function string) int {
	t.Helper()
	items := h.all(t, url.Values{"function": {function}})
	n := len(items)
	for _, it := range items {
		n = max(n, it.Attempts)
	}
	return n
}

func TestMaxContainersThrottles(t *testing.T) {
	// TooManyRequestsException (429) when "running the function would cause
	// you to exceed a concurrency limit" (Invoke). With one container
	// allowed, a second synchronous invocation while the first runs is
	// refused, and the first still succeeds.
	srv := startServer(t, map[string]string{"TULE_Functions_MaxContainers": "1"})
	c := clientFor(srv)
	createFunction(t, c, "single", "sleep", func(in *lambda.CreateFunctionInput) {
		in.Timeout = aws.Int32(30)
	})
	invokeOK(t, c, "single", map[string]int{"ms": 1}, nil)

	first := make(chan error, 1)
	go func() {
		out, err := c.Invoke(t.Context(), &lambda.InvokeInput{
			FunctionName: aws.String("single"),
			Payload:      []byte(`{"ms":4000}`),
		})
		if err == nil && out.FunctionError != nil {
			err = &invokeError{payload: string(out.Payload)}
		}
		first <- err
	}()
	time.Sleep(time.Second)

	err := errOf(c.Invoke(t.Context(), &lambda.InvokeInput{
		FunctionName: aws.String("single"),
		Payload:      []byte(`{"ms":1}`),
	}))
	requireModeled[*types.TooManyRequestsException](t, err)
	requireNoErr(t, <-first, "the invocation that held the container")
}
