package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"
	_ "modernc.org/sqlite"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/lambdaapi"
	"tule.dev/functions/internal/runner"
	"tule.dev/functions/internal/services/functions/sqlimpl"
	"tule.dev/functions/internal/testfn"
)

// newStore opens a store on a fresh database, as the app wires it.
func newStore(t *testing.T) *sqlimpl.Service {
	t.Helper()
	ctx := context.Background()
	logger := &gas.NopLogger{}
	cfg := database.DefaultConfig()
	cfg.Database.Dialect = database.DialectSQLite
	cfg.Database.DSN = gas.Secret("file:" + filepath.Join(t.TempDir(), "functions.db"))
	cfg.Database.MaxOpenConns = 1
	cfg.Database.MaxIdleConns = 1
	db, err := database.New(database.WithConfig(cfg))(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Init(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(ctx) })
	mm, err := migrate.New()(db, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err = mm.Init(ctx); err != nil {
		t.Fatal(err)
	}
	s := sqlimpl.NewService(db, mm)
	if err = s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err = mm.RunPendingContext(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func settings() *contracts.Settings {
	return &contracts.Settings{
		DockerHost:          "unix:///var/run/docker.sock",
		RuntimeAPIHost:      "host.docker.internal",
		QueuesEndpoint:      "http://127.0.0.1:1",
		AccountID:           "000000000000",
		Region:              "us-east-1",
		FunctionCredentials: contracts.CredentialsRoot,
		MaxContainers:       2,
		MaxTotalContainers:  10,
		PidsLimit:           1024,
		HistoryLimit:        100,
		HistoryMaxBytes:     1 << 30,
		IdleTimeout:         time.Minute,
		AsyncRetryDelay:     100 * time.Millisecond,
	}
}

// newEngine starts an engine on a fresh store and the local Docker, and
// closes it when the test ends.
func newEngine(t *testing.T, s *contracts.Settings) (*Engine, *sqlimpl.Service) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	store := newStore(t)
	e := New(s, "AKIDROOT", "root-secret")(store, &gas.NopLogger{}, gas.NewEventBus())
	ctx := t.Context()
	if err := e.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := e.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Close(context.Background()); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return e, store
}

// createFunction creates a function of image and waits for it to be
// Active.
func createFunction(t *testing.T, e *Engine, image string) {
	t.Helper()
	const name = "fn"
	fn := &contracts.Function{
		Name: name, Image: contracts.Image{URI: image}, Timeout: 5, MemorySize: 128,
		Environment: map[string]string{}, Tags: map[string]string{},
	}
	if err := e.CreateFunction(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := e.store.GetFunction(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		if got.State == contracts.StateActive {
			return
		}
		if got.State == contracts.StateFailed || time.Now().After(deadline) {
			t.Fatalf("function is %s: %s", got.State, got.StateReason)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func invoke(t *testing.T, e *Engine, name, payload string) *runner.Result {
	t.Helper()
	fn, err := e.Invocable(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Invoke(t.Context(), fn, ids.UUID(), "", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestTheRuntimeAPIListensWhereTheContainersReachTheHost(t *testing.T) {
	e, _ := newEngine(t, settings())
	dc, err := docker.New(settings().DockerHost)
	if err != nil {
		t.Fatal(err)
	}
	want, err := dc.HostAddress(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(e.listener.Addr().String())
	if host != want {
		t.Fatalf("the Runtime API listens on %s, want %s", host, want)
	}
	// And the containers reach it there.
	createFunction(t, e, testfn.Image(t))
	if res := invoke(t, e, "fn", `{}`); res.Status != runner.StatusSucceeded {
		t.Fatalf("invoke = %+v", res)
	}
}

// credentials returns the credential variables a function sees.
func credentialsSeen(t *testing.T, s *contracts.Settings) map[string]string {
	t.Helper()
	e, _ := newEngine(t, s)
	createFunction(t, e, testfn.Image(t))
	res := invoke(t, e, "fn", `{"env":["AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"]}`)
	var got struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(res.Payload, &got); err != nil {
		t.Fatalf("decode %s: %v", res.Payload, err)
	}
	return got.Env
}

func TestTheFunctionCredentialsFollowTheSetting(t *testing.T) {
	custom := settings()
	custom.FunctionCredentials = contracts.CredentialsCustom
	custom.FunctionAccessKeyID, custom.FunctionSecretAccessKey = "AKIDFN", "fn-secret"
	none := settings()
	none.FunctionCredentials = contracts.CredentialsNone
	for _, tt := range []struct {
		s          *contracts.Settings
		id, secret string
	}{
		{settings(), "AKIDROOT", "root-secret"},
		{custom, "AKIDFN", "fn-secret"},
		{none, "", ""},
	} {
		got := credentialsSeen(t, tt.s)
		if got["AWS_ACCESS_KEY_ID"] != tt.id || got["AWS_SECRET_ACCESS_KEY"] != tt.secret {
			t.Errorf("%s: the function saw %v", tt.s.FunctionCredentials, got)
		}
	}
}

// TestAnAsyncInvocationThatCannotRunIsRecorded removes the function's
// image, so its container cannot be created, and deletes the function
// while the invocation retries: the history gets its failure.
func TestAnAsyncInvocationThatCannotRunIsRecorded(t *testing.T) {
	e, store := newEngine(t, settings())
	image := testfn.Image(t)
	createFunction(t, e, image)
	// image is the tag testfn made.
	rmi := exec.Command("docker", "rmi", "-f", image) //nolint:gosec // see above
	if out, err := rmi.CombinedOutput(); err != nil {
		t.Fatalf("docker rmi: %v\n%s", err, out)
	}
	fn, err := e.Invocable(t.Context(), "fn")
	if err != nil {
		t.Fatal(err)
	}
	requestID := e.InvokeAsync(fn, []byte(`{}`))
	time.Sleep(1500 * time.Millisecond) // a couple of retries
	if _, err = store.GetInvocation(t.Context(), requestID); !errors.Is(err,
		contracts.ErrInvocationNotFound) {
		t.Fatalf("recorded while still retrying: %v", err)
	}
	if err = e.DeleteFunction(t.Context(), "fn"); err != nil {
		t.Fatal(err)
	}
	inv := waitRecord(t, store, requestID)
	if inv.Status != contracts.StatusFailed || inv.Source != contracts.SourceAsync ||
		inv.ErrorType != lambdaapi.CodeResourceNotFound {
		t.Fatalf("recorded %+v", inv)
	}
}

// waitRecord waits for the history to record the request.
func waitRecord(t *testing.T, store contracts.Store, requestID string) *contracts.Invocation {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		inv, err := store.GetInvocation(t.Context(), requestID)
		if err == nil {
			return inv
		}
		if time.Now().After(deadline) {
			t.Fatalf("no record of %s: %v", requestID, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestAFunctionErrorIsRetriedAndEachAttemptRecorded(t *testing.T) {
	e, store := newEngine(t, settings())
	createFunction(t, e, testfn.Image(t))
	fn, err := e.Invocable(t.Context(), "fn")
	if err != nil {
		t.Fatal(err)
	}
	requestID := e.InvokeAsync(fn, []byte(`{"action":"error"}`))
	deadline := time.Now().Add(15 * time.Second)
	for {
		inv, gErr := store.GetInvocation(t.Context(), requestID)
		if gErr == nil && inv.Attempts == asyncAttempts {
			if inv.Status != contracts.StatusFailed || inv.ErrorType != "errorString" {
				t.Fatalf("last attempt = %+v", inv)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after 15s: %+v %v", inv, gErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestAMappingDeletedWhileItStartsLeavesNoPoller races a mapping's start
// with its delete and its disabling update, many times.
func TestAMappingDeletedWhileItStartsLeavesNoPoller(t *testing.T) {
	e, _ := newEngine(t, settings())
	ctx := t.Context()
	for i := range 50 {
		m := &contracts.Mapping{
			UUID: ids.UUID(), EventSourceARN: "arn:aws:sqs:us-east-1:000000000000:q",
			FunctionName: "fn", BatchSize: 10, Enabled: true,
		}
		if err := e.CreateMapping(ctx, m); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Go(func() {
			if i%2 == 0 {
				_, _ = e.DeleteMapping(ctx, m.UUID)
				return
			}
			_, _ = e.UpdateMapping(ctx, m.UUID, func(m *contracts.Mapping) error {
				m.Enabled = false
				return nil
			})
		})
		wg.Wait()
		time.Sleep(20 * time.Millisecond)
		got, err := e.store.GetMapping(ctx, m.UUID)
		running := e.Polling(m.UUID)
		switch {
		case errors.Is(err, contracts.ErrMappingNotFound) || (err == nil &&
			got.State != contracts.MappingEnabled):
			if running {
				t.Fatalf("round %d: a poller runs for a mapping that is %v", i, got)
			}
		case err != nil:
			t.Fatal(err)
		}
	}
}
