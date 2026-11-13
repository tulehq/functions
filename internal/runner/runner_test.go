package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/runtimeapi"
	"tule.dev/functions/internal/testfn"
)

// newRunner starts a Runtime API listener and a Runner on the local Docker
// daemon, both stopped when the test ends, and fails the test if any
// container of its instance is left behind.
func newRunner(t *testing.T, maxContainers int) *Runner {
	t.Helper()
	return newRunnerWith(t, maxContainers, "AKIDTEST", "secret-test")
}

// newRunnerWith is newRunner with the credentials the containers get, none
// when accessKeyID is empty.
func newRunnerWith(
	t *testing.T,
	maxContainers int,
	accessKeyID, secret string,
	opts ...func(*Config),
) *Runner {
	t.Helper()
	dc, err := docker.New("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if err = dc.Ping(t.Context()); err != nil {
		t.Skipf("docker is not reachable: %v", err)
	}
	// The containers reach the listener through the Docker host's gateway,
	// which is not the loopback interface on Linux.
	ln, err := net.Listen("tcp", ":0") //nolint:gosec // see above
	if err != nil {
		t.Fatal(err)
	}
	rt := runtimeapi.NewServer()
	srv := &http.Server{Handler: rt, ReadHeaderTimeout: time.Minute}
	go func() { _ = srv.Serve(ln) }()

	instance := ids.Hex(8)
	cfg := Config{
		Logger:             &gas.NopLogger{},
		Docker:             dc,
		Runtime:            rt,
		RuntimeAddr:        "host.docker.internal:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		ExtraHosts:         []string{"host.docker.internal:host-gateway"},
		InstanceID:         instance,
		Region:             "us-east-1",
		MaxContainers:      maxContainers,
		MaxTotalContainers: 50,
		PidsLimit:          1024,
		IdleTimeout:        time.Minute,
		AccessKeyID:        accessKeyID,
		SecretAccessKey:    secret,
	}
	for _, o := range opts {
		o(&cfg)
	}
	r := New(context.Background(), cfg)
	t.Cleanup(func() {
		ctx := context.Background()
		if cErr := r.Close(ctx); cErr != nil {
			t.Errorf("close runner: %v", cErr)
		}
		_ = srv.Close()
		left, lErr := dc.ListContainers(ctx, LabelInstance, instance)
		if lErr != nil {
			t.Errorf("list containers: %v", lErr)
		}
		if len(left) > 0 {
			t.Errorf("containers left behind: %v", left)
			for _, id := range left {
				_ = dc.RemoveContainer(ctx, id)
			}
		}
	})
	return r
}

func specFor(image string, timeout time.Duration) *Spec {
	return &Spec{
		Function:   "fn",
		ARN:        "arn:aws:lambda:us-east-1:000000000000:function:fn",
		Revision:   "r1",
		Image:      image,
		Env:        map[string]string{"GREETING": "hello"},
		Timeout:    timeout,
		MemorySize: 128,
	}
}

func invoke(t *testing.T, r *Runner, spec *Spec, payload string) *Result {
	t.Helper()
	res, err := r.Invoke(t.Context(), spec, &Request{
		RequestID: ids.UUID(), Payload: []byte(payload), Wait: true,
	})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	return res
}

// echoed is what the test function answers by default.
type echoed struct {
	Env       map[string]string `json:"env"`
	RequestID string            `json:"requestId"`
	ARN       string            `json:"functionArn"`
	Hostname  string            `json:"hostname"`
}

func decodeEcho(t *testing.T, res *Result) echoed {
	t.Helper()
	if res.Status != StatusSucceeded {
		t.Fatalf("invocation = %s %s", res.Status, res.Payload)
	}
	var got echoed
	if err := json.Unmarshal(res.Payload, &got); err != nil {
		t.Fatalf("decode %s: %v", res.Payload, err)
	}
	return got
}

// requireLog fails unless log holds every one of want and none of absent.
func requireLog(t *testing.T, log string, want, absent []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(log, w) {
			t.Fatalf("log lacks %q:\n%s", w, log)
		}
	}
	for _, a := range absent {
		if strings.Contains(log, a) {
			t.Fatalf("log holds %q:\n%s", a, log)
		}
	}
}

func TestARunnerRunsAWarmContainer(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 2)
	spec := specFor(image, 5*time.Second)

	first := invoke(t, r, spec,
		`{"print":"first line","env":["GREETING","AWS_LAMBDA_FUNCTION_NAME","AWS_REGION"]}`)
	got := decodeEcho(t, first)
	want := echoed{
		Env: map[string]string{
			"GREETING": "hello", "AWS_LAMBDA_FUNCTION_NAME": "fn", "AWS_REGION": "us-east-1",
		},
		RequestID: first.RequestID, ARN: spec.ARN, Hostname: got.Hostname,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the function saw %+v, want %+v", got, want)
	}
	requireLog(t, first.Log, []string{
		"initializing\n", "START RequestId: " + first.RequestID,
		"first line\n", "END RequestId: ", "REPORT RequestId: ", "Init Duration: ",
	}, nil)

	second := invoke(t, r, spec, `{"print":"second line"}`)
	if again := decodeEcho(t, second); again.Hostname != got.Hostname {
		t.Fatalf("the second invocation ran on %s, not the warm %s", again.Hostname, got.Hostname)
	}
	requireLog(t, second.Log, []string{"second line"}, []string{"Init Duration", "first line"})
}

func TestARunnerReportsErrorsPanicsAndTimeouts(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 2)
	spec := specFor(image, time.Second)

	tests := []struct {
		payload, status, errType, message, log string
	}{
		{`{"action":"error"}`, StatusFailed, "errorString", "the handler failed", ""},
		{`{"action":"panic"}`, StatusFailed, "string", "the handler panicked", ""},
		{`{"action":"exit"}`, StatusFailed, "Runtime.ExitError", "exit status 3", ""},
		{
			`{"sleepMs":5000,"print":"sleeping"}`, StatusTimedOut, "Sandbox.Timedout",
			"Task timed out after 1.00 seconds", "Status: timeout",
		},
	}
	for _, tt := range tests {
		res := invoke(t, r, spec, tt.payload)
		if res.Status != tt.status || res.FunctionError != "Unhandled" ||
			res.ErrorType != tt.errType || !strings.Contains(res.ErrorMessage, tt.message) {
			t.Fatalf("%s = %+v %s", tt.payload, res, res.Payload)
		}
		requireLog(t, res.Log, []string{tt.log}, nil)
	}
	// After all that, the function still runs.
	decodeEcho(t, invoke(t, r, spec, `{}`))
}

func TestARunnerStartsAContainerPerConcurrentInvocation(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 2)
	spec := specFor(image, 5*time.Second)

	var wg sync.WaitGroup
	hosts := make([]string, 2)
	for i := range hosts {
		wg.Go(func() {
			res, err := r.Invoke(t.Context(), spec, &Request{
				RequestID: ids.UUID(), Payload: []byte(`{"sleepMs":700}`), Wait: true,
			})
			if err != nil || res.Status != StatusSucceeded {
				t.Errorf("invoke: %v %+v", err, res)
				return
			}
			var got struct {
				Hostname string `json:"hostname"`
			}
			_ = json.Unmarshal(res.Payload, &got)
			hosts[i] = got.Hostname
		})
	}
	time.Sleep(300 * time.Millisecond)
	// Both containers are busy; a third invocation that does not wait is
	// throttled.
	_, err := r.Invoke(t.Context(), spec, &Request{RequestID: ids.UUID(), Payload: []byte(`{}`)})
	if !errors.Is(err, ErrThrottled) {
		t.Errorf("third invocation = %v, want ErrThrottled", err)
	}
	wg.Wait()
	if hosts[0] == "" || hosts[0] == hosts[1] {
		t.Fatalf("the invocations ran on %q", hosts)
	}
	if n := len(r.Containers("fn")); n != 2 {
		t.Fatalf("%d containers, want 2", n)
	}
	r.Retire("fn")
	if n := len(r.Containers("fn")); n != 0 {
		t.Fatalf("%d containers after retiring, want 0", n)
	}
}

// credentialsSeen returns the credential variables the function saw.
func credentialsSeen(t *testing.T, r *Runner, image string) map[string]string {
	t.Helper()
	got := decodeEcho(t, invoke(
		t,
		r,
		specFor(image, 5*time.Second),
		`{"env":["AWS_ACCESS_KEY_ID","AWS_ACCESS_KEY","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN"]}`,
	))
	return got.Env
}

func TestTheContainersGetTheConfiguredKey(t *testing.T) {
	image := testfn.Image(t)
	got := credentialsSeen(t, newRunner(t, 1), image)
	want := map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIDTEST", "AWS_ACCESS_KEY": "AKIDTEST",
		"AWS_SECRET_ACCESS_KEY": "secret-test", "AWS_SESSION_TOKEN": "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the function saw %v, want %v", got, want)
	}
}

func TestTheContainersGetNoKeyWhenItIsOff(t *testing.T) {
	image := testfn.Image(t)
	got := credentialsSeen(t, newRunnerWith(t, 1, "", ""), image)
	for k, v := range got {
		if v != "" {
			t.Errorf("%s = %q, want unset", k, v)
		}
	}
}

// TestAContainerWithExpiringCredentialsIsNotReused gives each container a
// role session of its own: one whose session would expire before an
// invocation's timeout and margin is replaced by a container with a new
// session, and one with time to spare is reused.
func TestAContainerWithExpiringCredentialsIsNotReused(t *testing.T) {
	image := testfn.Image(t)
	var mu sync.Mutex
	sessions := 0
	lifetimes := []time.Duration{30 * time.Second, time.Hour}
	r := newRunnerWith(t, 1, "", "", func(c *Config) {
		c.Credentials = func(_ context.Context, spec *Spec) (*Credentials, error) {
			mu.Lock()
			defer mu.Unlock()
			n := sessions
			sessions++
			if spec.Role != "arn:aws:iam::000000000000:role/r" {
				t.Errorf("credentials for role %q", spec.Role)
			}
			return &Credentials{
				Expiration:      time.Now().Add(lifetimes[min(n, len(lifetimes)-1)]),
				AccessKeyID:     "ASIA" + strconv.Itoa(n),
				SecretAccessKey: "secret-" + strconv.Itoa(n),
				SessionToken:    "token-" + strconv.Itoa(n),
			}, nil
		}
	})
	spec := specFor(image, 5*time.Second)
	spec.Role = "arn:aws:iam::000000000000:role/r"
	seen := func() map[string]string {
		return decodeEcho(t, invoke(t, r, spec,
			`{"env":["AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN"]}`)).Env
	}
	for i, want := range []string{"0", "1", "1"} {
		got := seen()
		if got["AWS_ACCESS_KEY_ID"] != "ASIA"+want || got["AWS_SESSION_TOKEN"] != "token-"+want ||
			got["AWS_SECRET_ACCESS_KEY"] != "secret-"+want {
			t.Fatalf("invocation %d saw %v, want session %s", i, got, want)
		}
	}
}

// TestACredentialsFailureFailsTheInvocation checks that a container whose
// credentials cannot be had is not started, and frees its slot.
func TestACredentialsFailureFailsTheInvocation(t *testing.T) {
	image := testfn.Image(t)
	r := newRunnerWith(t, 1, "", "", func(c *Config) {
		c.Credentials = func(context.Context, *Spec) (*Credentials, error) {
			return nil, errors.New("no role")
		}
	})
	spec := specFor(image, 5*time.Second)
	for range 2 {
		if _, err := r.Invoke(t.Context(), spec, &Request{
			RequestID: ids.UUID(),
			Payload:   []byte(`{}`),
		}); err == nil || !strings.Contains(err.Error(), "no role") {
			t.Fatalf("got %v", err)
		}
	}
	if live, _ := r.Live(spec.Function); live != 0 {
		t.Fatalf("%d containers live", live)
	}
}
