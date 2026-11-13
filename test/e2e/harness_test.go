//go:build e2e

package e2e

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go"
	smithytraits "github.com/aws/smithy-go/traits"
	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/functions/internal/app"
)

// server is the app under test, served by the app's own *http.Server over a
// real TCP listener: the listener is created here because gas.App.Serve
// exposes neither the listener nor its port, and everything else is the
// server gas built from the bound configuration, reached over the network
// and shut down through gas.App.Stop.
type server struct {
	app      *gas.App
	listener net.Listener
	client   *http.Client
	served   chan error
	URL      string
	Addr     string
	stopped  bool
}

// clientTimeout bounds a test's own requests, so a hung server fails the test
// instead of the suite's timeout. It is longer than any function the tests
// run.
const clientTimeout = 60 * time.Second

// region is the region every client signs for, the service's default
// (TULE_Functions_Region).
const region = "us-east-1"

// defaultAccountID is the account in ARNs when TULE_Functions_AccountID is
// unset.
const defaultAccountID = "000000000000"

// role is the execution role every function is created with: CreateFunction
// requires one (the SDK model), and the design records it.
const role = "arn:aws:iam::000000000000:role/lambda-role"

// newClient starts the app on a fresh store and returns a Lambda client
// pointed at it.
func newClient(t *testing.T) (*lambda.Client, *server) {
	t.Helper()
	srv := startServer(t, nil)
	return clientFor(srv), srv
}

// startServer starts the app on a fresh store, with env setting extra TULE_
// variables. It accepts the test/test credentials clientFor signs with unless
// env changes them.
func startServer(t *testing.T, env map[string]string) *server {
	t.Helper()

	setEnv(t, env)

	cfg, err := app.LoadConfigFrom(config.NewEnvProvider(
		config.WithEnvSeparator("_"),
		config.WithEnvPrefix("TULE_"),
	))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	a, err := app.New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	// Start binds the configuration and initializes the services, so the
	// server built after it carries the configured timeouts.
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	srv := serve(t, a)
	t.Cleanup(func() { srv.Stop(t) })
	return srv
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()

	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "functions.db"))
	t.Setenv("TULE_Auth_AccessKeyID", "test")
	t.Setenv("TULE_Auth_SecretAccessKey", "test")
	t.Setenv("TULE_Functions_RuntimeAPIPort", "0")
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// serve puts the app's own server on a loopback listener on a free port.
func serve(t *testing.T, a *gas.App) *server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &server{
		app:      a,
		listener: listener,
		client:   &http.Client{Timeout: clientTimeout},
		served:   make(chan error, 1),
		Addr:     listener.Addr().String(),
		URL:      "http://" + listener.Addr().String(),
	}

	go func() {
		srv.served <- a.Server().Serve(listener)
	}()

	return srv
}

// Client returns an HTTP client for the server.
func (s *server) Client() *http.Client {
	return s.client
}

// Stop shuts the app down the way a signal does, through gas.App.Stop, and
// fails the test if the shutdown or the server itself reported an error. It
// is idempotent, so a test can stop the server early and let the cleanup run
// anyway.
func (s *server) Stop(t *testing.T) {
	t.Helper()

	if s.stopped {
		return
	}
	s.stopped = true

	s.client.CloseIdleConnections()

	if err := s.app.Stop(context.Background()); err != nil {
		t.Errorf("stop app: %v", err)
	}

	select {
	case err := <-s.served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(clientTimeout):
		t.Error("serve did not return after shutdown")
	}
}

// functionARN is the ARN of the function name with the default account and
// region: arn:aws:lambda:<region>:<account>:function:<name>.
func functionARN(name string) string {
	return "arn:aws:lambda:" + region + ":" + defaultAccountID + ":function:" + name
}

// clientFor returns a Lambda client for srv, with the test/test credentials
// unless opts change them. It does not retry, so a refused request fails at
// once and a test sees each request it makes exactly once.
func clientFor(srv *server, opts ...func(*lambda.Options)) *lambda.Client {
	return lambda.New(lambda.Options{
		Region:           region,
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	}, opts...)
}

// lambdaClientWith returns a Lambda client for srv signing with creds.
func lambdaClientWith(srv *server, creds aws.Credentials) *lambda.Client {
	return clientFor(srv, func(o *lambda.Options) {
		o.Credentials = credentials.StaticCredentialsProvider{Value: creds}
	})
}

// errOf returns the error of an SDK call and drops its output, for tests that
// call an operation only for the error it reports.
func errOf[T any](_ T, err error) error {
	return err
}

func requireNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func requireEqual[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func requireSameSet(t *testing.T, got, want []string, what string) {
	t.Helper()
	g, w := slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
	if !slices.Equal(g, w) {
		t.Fatalf("%s: got %q, want %q", what, got, want)
	}
}

func requireSlice(t *testing.T, got, want []string, what string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s: got %q, want %q", what, got, want)
	}
}

func requireContains(t *testing.T, s, sub, what string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("%s: %q does not contain %q", what, s, sub)
	}
}

// requireAs fails unless err matches the modeled SDK error type T.
func requireAs[T error](t *testing.T, err error) {
	t.Helper()
	var want T
	if !errors.As(err, &want) {
		t.Fatalf("want error of type %T, got %v", want, err)
	}
}

// requireModeled fails unless err is the modeled error T with the HTTP
// status the SDK's schema gives it (the httpError trait, schemas/; the
// Lambda API reference lists the same status for each error).
func requireModeled[T error](t *testing.T, err error) {
	t.Helper()
	requireAs[T](t, err)
	requireStatus(t, err, modeledStatus[T](t))
}

// modeledStatus is the httpError status of the SDK's schema for T.
func modeledStatus[T error](t *testing.T) int {
	t.Helper()
	name := reflect.TypeFor[T]().Elem().Name()
	entry, ok := lambda.TypeRegistry.Entries["com.amazonaws.lambda#"+name]
	if !ok {
		t.Fatalf("no SDK schema for error %s", name)
	}
	h, ok := smithy.SchemaTrait[*smithytraits.HTTPError](entry.Schema)
	if !ok {
		t.Fatalf("the SDK schema for %s has no httpError trait", name)
	}
	return h.Code
}

// requireAPIError fails unless err is an API error the service answered.
func requireAPIError(t *testing.T, err error) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want an API error, got %v", err)
	}
}

// requireStatus fails unless err came with the given HTTP status.
func requireStatus(t *testing.T, err error, status int) {
	t.Helper()
	var re *awshttp.ResponseError
	if !errors.As(err, &re) {
		t.Fatalf("want an HTTP response error with status %d, got %v", status, err)
	}
	requireEqual(t, re.HTTPStatusCode(), status, "HTTP status")
}

// eventually polls cond every 200ms until it holds or d passes, and fails
// the test with what if it never holds.
func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, d)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// within fails unless f returns within d.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	start := time.Now()
	f()
	took := time.Since(start)
	if took > d {
		t.Fatalf("%s took %v, want at most %v", what, took, d)
	}
}

// requireUnsignedOK fails unless an unsigned GET of path answers 200.
func requireUnsignedOK(t *testing.T, srv *server, path string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, http.NoBody)
	requireNoErr(t, err, "build "+path)
	res, err := srv.Client().Do(req)
	requireNoErr(t, err, "probe "+path)
	_ = res.Body.Close()
	requireEqual(t, res.StatusCode, http.StatusOK, "unsigned "+path)
}

func TestProbes(t *testing.T) {
	// The siblings' probes: unsigned, 200 once the app is up.
	srv := startServer(t, nil)
	requireUnsignedOK(t, srv, "/_health")
	requireUnsignedOK(t, srv, "/_ready")
}
