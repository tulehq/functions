package runner

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/testfn"
)

// onlyContainer returns the function's one container.
func onlyContainer(t *testing.T, r *Runner, function string) string {
	t.Helper()
	got := r.Containers(function)
	if len(got) != 1 {
		t.Fatalf("%s has containers %v, want one", function, got)
	}
	return got[0]
}

func TestAContainerIsLimitedAndPausedBetweenInvocations(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 1)
	spec := specFor(image, 5*time.Second)
	spec.MemorySize = 256

	decodeEcho(t, invoke(t, r, spec, `{}`))
	info, err := r.cfg.Docker.InspectContainer(t.Context(), onlyContainer(t, r, "fn"))
	if err != nil {
		t.Fatal(err)
	}
	l := info.Limits
	driver, opts := l.LogDriver()
	if l.Memory != 256<<20 || l.MemorySwap != 256<<20 || l.PidsLimit != 1024 ||
		driver != "local" || opts["max-size"] != logMaxSize {
		t.Fatalf("limits = %+v", l)
	}
	if !info.Paused {
		t.Fatal("the idle container is not paused")
	}
}

// count invokes the counting function and returns its count.
func count(t *testing.T, r *Runner, spec *Spec) int64 {
	t.Helper()
	res := invoke(t, r, spec, `{"action":"count"}`)
	n, err := strconv.ParseInt(string(res.Payload), 10, 64)
	if err != nil {
		t.Fatalf("count = %s: %v", res.Payload, err)
	}
	return n
}

// TestWhatAFunctionLeavesRunningIsFrozen checks a goroutine the function
// started does not run between invocations: it counts milliseconds, and
// barely counts across a second of idleness.
func TestWhatAFunctionLeavesRunningIsFrozen(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 1)
	spec := specFor(image, 5*time.Second)

	before := count(t, r, spec)
	time.Sleep(time.Second)
	after := count(t, r, spec)
	// The goroutine runs during the invocations and the output drain after
	// each, some tens of milliseconds; unfrozen it would count about 1000.
	if after-before > 400 {
		t.Fatalf("the goroutine counted %d ms while the container was idle", after-before)
	}
}

func TestOutputAfterTheResponseStaysWithItsInvocation(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 1)
	spec := specFor(image, 5*time.Second)

	spam := invoke(t, r, spec, `{"action":"spam"}`)
	if spam.Status != StatusSucceeded {
		t.Fatalf("spam = %+v", spam)
	}
	time.Sleep(500 * time.Millisecond)
	next := invoke(t, r, spec, `{"action":"reply","reply":1,"print":"the next one"}`)
	requireLog(t, next.Log, []string{"the next one"}, nil)
	// The spamming goroutine thaws with the container, so some of its
	// output lands here, but no more than the capture keeps.
	if len(next.Log) > MaxLogCapture+4096 {
		t.Fatalf("the next invocation's log is %d bytes", len(next.Log))
	}
}

func TestAnInvocationsLogIsCapped(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 1)
	spec := specFor(image, 10*time.Second)

	res := invoke(t, r, spec, `{"action":"flood","bytes":3000000}`)
	if res.Status != StatusSucceeded {
		t.Fatalf("flood = %+v", res)
	}
	if len(res.Log) > MaxLogCapture+4096 || !strings.Contains(res.Log, "bytes of output dropped]") {
		t.Fatalf("log of %d bytes, starting %.200q", len(res.Log), res.Log)
	}
}

// sleepers starts n invocations that each sleep for ms, and returns a wait
// for them.
func sleepers(t *testing.T, r *Runner, spec *Spec, n, ms int) func() {
	t.Helper()
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := r.Invoke(t.Context(), spec, &Request{
				RequestID: ids.UUID(), Wait: true,
				Payload: []byte(`{"sleepMs":` + strconv.Itoa(ms) + `}`),
			})
			if err != nil {
				t.Errorf("sleeper: %v", err)
			}
		})
	}
	return wg.Wait
}

// waitBusy waits for the function to have n live containers.
func waitBusy(t *testing.T, r *Runner, function string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if live, _ := r.Live(function); live == n && len(r.Containers(function)) == n {
			return
		}
		if time.Now().After(deadline) {
			live, _ := r.Live(function)
			t.Fatalf("%s has %d live containers, want %d", function, live, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRetiredContainersCountAgainstTheCap(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 2)
	spec := specFor(image, 10*time.Second)

	wait := sleepers(t, r, spec, 2, 2000)
	waitBusy(t, r, "fn", 2)
	for i := range 3 {
		r.Retire("fn")
		next := *spec
		next.Revision = "r" + strconv.Itoa(i+2)
		_, err := r.Invoke(t.Context(), &next, &Request{
			RequestID: ids.UUID(),
			Payload:   []byte(`{}`),
		})
		if !errors.Is(err, ErrThrottled) {
			t.Fatalf("invocation %d after a retire = %v, want ErrThrottled", i, err)
		}
	}
	if live, total := r.Live("fn"); live != 2 || total != 2 {
		t.Fatalf("live = %d, total = %d, want 2 and 2", live, total)
	}
	wait()
}

func TestTheRunnersCapEvictsAnotherFunctionsIdleContainer(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 2)
	r.cfg.MaxTotalContainers = 1
	a := specFor(image, 5*time.Second)
	b := specFor(image, 5*time.Second)
	b.Function = "other"

	decodeEcho(t, invoke(t, r, a, `{}`))
	decodeEcho(t, invoke(t, r, b, `{}`))
	if got := r.Containers("fn"); len(got) != 0 {
		t.Fatalf("fn kept %v past the runner's cap of 1", got)
	}
	if _, total := r.Live("other"); total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
}

func TestADeleteKillsAColdStartingInvocation(t *testing.T) {
	image := testfn.Image(t)
	for _, delay := range []time.Duration{0, 20 * time.Millisecond, 50 * time.Millisecond} {
		r := newRunner(t, 1)
		spec := specFor(image, 10*time.Second)
		done := make(chan error, 1)
		start := time.Now()
		go func() {
			_, err := r.Invoke(t.Context(), spec, &Request{
				RequestID: ids.UUID(), Wait: true, Payload: []byte(`{"sleepMs":4000}`),
			})
			done <- err
		}()
		time.Sleep(delay)
		r.Delete("fn", spec.Revision)
		select {
		case err := <-done:
			// Killed while starting it fails with ErrRetired, while
			// running with the container's exit.
			if err != nil && !errors.Is(err, ErrRetired) {
				t.Fatalf("the deleted invocation = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("after a delete %v in, the invocation ran on", delay)
		}
		waitBusy(t, r, "fn", 0)
		if took := time.Since(start); took > 3*time.Second {
			t.Fatalf("the deleted invocation took %v", took)
		}
		_, err := r.Invoke(
			t.Context(),
			spec,
			&Request{RequestID: ids.UUID(), Payload: []byte(`{}`)},
		)
		if !errors.Is(err, ErrRetired) {
			t.Fatalf("invoking the deleted revision = %v, want ErrRetired", err)
		}
	}
}

func TestTheLogStreamNameDoesNotCarryTheToken(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 1)
	got := decodeEcho(t, invoke(t, r, specFor(image, 5*time.Second),
		`{"env":["AWS_LAMBDA_RUNTIME_API","AWS_LAMBDA_LOG_STREAM_NAME"]}`))
	api := got.Env["AWS_LAMBDA_RUNTIME_API"]
	_, token, _ := strings.Cut(api, "/")
	if len(token) != 32 || strings.Contains(got.Env["AWS_LAMBDA_LOG_STREAM_NAME"], token) {
		t.Fatalf("runtime API %q, log stream %q", api, got.Env["AWS_LAMBDA_LOG_STREAM_NAME"])
	}
	info, err := r.cfg.Docker.InspectContainer(t.Context(), onlyContainer(t, r, "fn"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(info.Name, token[:8]) {
		t.Fatalf("container name %q carries the token", info.Name)
	}
}

func TestTheRemoverExitsOnClose(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 1)
	decodeEcho(t, invoke(t, r, specFor(image, 5*time.Second), `{}`))
	if err := r.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.done:
	default:
		t.Fatal("Close returned with the remover still waiting")
	}
	if _, err := r.Invoke(t.Context(), specFor(image, time.Second),
		&Request{RequestID: ids.UUID()}); !errors.Is(err, ErrClosed) {
		t.Fatalf("invoke after Close = %v, want ErrClosed", err)
	}
}
