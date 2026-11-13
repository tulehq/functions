package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/gasmod/gas"

	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/runner"
	"tule.dev/functions/internal/testfn"
)

// startApp starts the app on a fresh store in a temporary directory, on the
// local Docker daemon, and returns a Lambda client for its handler and the
// server. The full server, over TCP, is what test/e2e drives; this only
// checks the wiring, the protocol and the store meet as the SDK expects.
func startApp(t *testing.T) (*lambda.Client, *httptest.Server) {
	t.Helper()
	dc, err := docker.New("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if err = dc.Ping(t.Context()); err != nil {
		t.Skipf("docker is not reachable: %v", err)
	}
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "nested", "functions.db"))
	t.Setenv("TULE_Functions_RuntimeAPIPort", "0")
	t.Setenv("TULE_Functions_QueuesEndpoint", "http://127.0.0.1:1")

	cfg, err := loadEnvConfig(t, "test", "test")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() {
		srv.Close()
		if sErr := a.Shutdown(context.Background()); sErr != nil {
			t.Errorf("shutdown: %v", sErr)
		}
	})
	return lambda.New(lambda.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	}), srv
}

const missingARN = "arn:aws:lambda:us-east-1:000000000000:function:missing"

// errOf returns the error of an SDK call and drops its output.
func errOf[T any](_ T, err error) error {
	return err
}

// TestAMissingFunctionIsNotFoundEverywhere calls every function operation
// with a function that does not exist, by name and by ARN.
func TestAMissingFunctionIsNotFoundEverywhere(t *testing.T) {
	c, _ := startApp(t)
	ctx := t.Context()
	name := aws.String("missing")
	calls := map[string]func() error{
		"GetFunction": func() error {
			return errOf(c.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: name}))
		},
		"GetFunction by ARN": func() error {
			return errOf(c.GetFunction(ctx,
				&lambda.GetFunctionInput{FunctionName: aws.String(missingARN)}))
		},
		"GetFunctionConfiguration": func() error {
			return errOf(c.GetFunctionConfiguration(ctx,
				&lambda.GetFunctionConfigurationInput{FunctionName: name}))
		},
		"UpdateFunctionCode": func() error {
			return errOf(c.UpdateFunctionCode(ctx, &lambda.UpdateFunctionCodeInput{
				FunctionName: name, ImageUri: aws.String("example:latest"),
			}))
		},
		"UpdateFunctionConfiguration": func() error {
			return errOf(c.UpdateFunctionConfiguration(
				ctx,
				&lambda.UpdateFunctionConfigurationInput{
					FunctionName: name,
					Timeout:      aws.Int32(5),
				},
			))
		},
		"DeleteFunction": func() error {
			return errOf(c.DeleteFunction(ctx, &lambda.DeleteFunctionInput{FunctionName: name}))
		},
		"Invoke": func() error {
			return errOf(c.Invoke(ctx, &lambda.InvokeInput{FunctionName: name}))
		},
		"Invoke Event": func() error {
			return errOf(c.Invoke(ctx, &lambda.InvokeInput{
				FunctionName: name, InvocationType: types.InvocationTypeEvent,
			}))
		},
	}
	for op, call := range calls {
		t.Run(op, func(t *testing.T) { requireNotFound(t, call()) })
	}
}

// TestAMissingFunctionIsNotFoundByTagsAndMappings calls the tagging and
// mapping operations with a function that does not exist.
func TestAMissingFunctionIsNotFoundByTagsAndMappings(t *testing.T) {
	c, _ := startApp(t)
	ctx := t.Context()
	arn := aws.String(missingARN)
	calls := map[string]func() error{
		"TagResource": func() error {
			return errOf(c.TagResource(ctx, &lambda.TagResourceInput{
				Resource: arn, Tags: map[string]string{"k": "v"},
			}))
		},
		"UntagResource": func() error {
			return errOf(c.UntagResource(ctx, &lambda.UntagResourceInput{
				Resource: arn, TagKeys: []string{"k"},
			}))
		},
		"ListTags": func() error {
			return errOf(c.ListTags(ctx, &lambda.ListTagsInput{Resource: arn}))
		},
		"CreateEventSourceMapping": func() error {
			return errOf(c.CreateEventSourceMapping(ctx, &lambda.CreateEventSourceMappingInput{
				FunctionName:   aws.String("missing"),
				EventSourceArn: aws.String("arn:aws:sqs:us-east-1:000000000000:q"),
			}))
		},
	}
	for op, call := range calls {
		t.Run(op, func(t *testing.T) { requireNotFound(t, call()) })
	}
}

func requireNotFound(t *testing.T, err error) {
	t.Helper()
	var nf *types.ResourceNotFoundException
	if !errors.As(err, &nf) {
		t.Fatalf("error = %v, want ResourceNotFoundException", err)
	}
	var re *smithyhttp.ResponseError
	if !errors.As(err, &re) || re.HTTPStatusCode() != http.StatusNotFound {
		t.Fatalf("error = %v, want status 404", err)
	}
	if !strings.Contains(aws.ToString(nf.Message), "missing") {
		t.Fatalf("message = %q, want the function named", aws.ToString(nf.Message))
	}
}

func TestAMissingMappingIsNotFound(t *testing.T) {
	c, _ := startApp(t)
	uuid := aws.String("a1b2c3d4-5678-90ab-cdef-111111111111")
	_, err := c.GetEventSourceMapping(t.Context(), &lambda.GetEventSourceMappingInput{UUID: uuid})
	var nf *types.ResourceNotFoundException
	if !errors.As(err, &nf) {
		t.Fatalf("get = %v, want ResourceNotFoundException", err)
	}
	_, err = c.DeleteEventSourceMapping(t.Context(),
		&lambda.DeleteEventSourceMappingInput{UUID: uuid})
	if !errors.As(err, &nf) {
		t.Fatalf("delete = %v, want ResourceNotFoundException", err)
	}
}

func TestAZipFunctionIsRefused(t *testing.T) {
	c, _ := startApp(t)
	_, err := c.CreateFunction(t.Context(), &lambda.CreateFunctionInput{
		FunctionName: aws.String("zipped"),
		Role:         aws.String("arn:aws:iam::000000000000:role/r"),
		Code:         &types.FunctionCode{ZipFile: []byte("PK")},
		Runtime:      types.RuntimeProvidedal2023,
		Handler:      aws.String("bootstrap"),
	})
	var bad *types.InvalidParameterValueException
	if !errors.As(err, &bad) {
		t.Fatalf("create = %v, want InvalidParameterValueException", err)
	}
}

func TestAMissingImageFailsTheFunction(t *testing.T) {
	c, _ := startApp(t)
	ctx := t.Context()
	out, err := c.CreateFunction(ctx, &lambda.CreateFunctionInput{
		FunctionName: aws.String("absent"),
		Role:         aws.String("arn:aws:iam::000000000000:role/r"),
		PackageType:  types.PackageTypeImage,
		Code:         &types.FunctionCode{ImageUri: aws.String("tule-functions-test:absent")},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.State != types.StatePending {
		t.Fatalf("state after create = %s, want Pending", out.State)
	}
	err = lambda.NewFunctionActiveWaiter(c, func(o *lambda.FunctionActiveWaiterOptions) {
		o.MinDelay, o.MaxDelay = 50*time.Millisecond, 100*time.Millisecond
	}).Wait(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: aws.String("absent")},
		10*time.Second)
	if err == nil {
		t.Fatal("the waiter saw the function Active")
	}
	got, err := c.GetFunctionConfiguration(ctx,
		&lambda.GetFunctionConfigurationInput{FunctionName: aws.String("absent")})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != types.StateFailed || got.StateReasonCode != types.StateReasonCodeInvalidImage {
		t.Fatalf("state = %s %s %q", got.State, got.StateReasonCode, aws.ToString(got.StateReason))
	}
	_, err = c.Invoke(ctx, &lambda.InvokeInput{FunctionName: aws.String("absent")})
	var conflict *types.ResourceConflictException
	if !errors.As(err, &conflict) {
		t.Fatalf("invoke = %v, want ResourceConflictException", err)
	}
}

func signedRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if err = v4.NewSigner().SignHTTP(t.Context(),
		aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, req, emptySHA256,
		"lambda", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestTheRetrievalAPIIsSignedAndTheProbesAreNot(t *testing.T) {
	_, srv := startApp(t)
	for _, tt := range []struct {
		req    *http.Request
		code   string
		status int
	}{
		{signedRequest(t, srv.URL+"/_functions/invocations"), "", 200},
		{
			httptest.NewRequest(http.MethodGet, srv.URL+"/_functions/invocations", nil),
			"MissingAuthenticationTokenException", 403,
		},
		{
			signedRequest(t, srv.URL+"/_functions/invocations/nope"),
			"ResourceNotFoundException", 404,
		},
		{
			signedRequest(t, srv.URL+"/_functions/invocations?status=odd"),
			"InvalidParameterValueException", 400,
		},
		{signedRequest(t, srv.URL+"/nowhere"), "UnknownOperationException", 404},
		{httptest.NewRequest(http.MethodGet, srv.URL+"/_ready", nil), "", 200},
	} {
		tt.req.RequestURI = ""
		resp, err := srv.Client().Do(tt.req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tt.status || resp.Header.Get("X-Amzn-Errortype") != tt.code {
			t.Errorf("%s %s = %d %q, want %d %q", tt.req.Method, tt.req.URL.Path,
				resp.StatusCode, resp.Header.Get("X-Amzn-Errortype"), tt.status, tt.code)
		}
	}
}

func TestAnImageURIOutsideDockersGrammarIsRefused(t *testing.T) {
	c, _ := startApp(t)
	for _, uri := range []string{"x/../../containers/abc", "Upper:1", "a b"} {
		_, err := c.CreateFunction(t.Context(), &lambda.CreateFunctionInput{
			FunctionName: aws.String("bad"),
			Role:         aws.String("arn:aws:iam::000000000000:role/r"),
			PackageType:  types.PackageTypeImage,
			Code:         &types.FunctionCode{ImageUri: aws.String(uri)},
		})
		var bad *types.InvalidParameterValueException
		if !errors.As(err, &bad) {
			t.Errorf("create with %q = %v, want InvalidParameterValueException", uri, err)
		}
	}
}

// TestStoppingWithAnInvocationInFlightIsClean stops the app the way a
// SIGTERM does while a synchronous invocation runs: the invocation is
// aborted at once rather than waited out, the stop succeeds, and no
// container is left.
//
// The client is the test's own, and its idle connections are closed before
// the stop, as test/e2e's harness does. A connection the transport dialed
// and then did not use, which it does when an idle connection comes back
// while it dials, never sends a request, and net/http's Shutdown waits for
// such a connection until it is 5 seconds old.
func TestStoppingWithAnInvocationInFlightIsClean(t *testing.T) {
	image := testfn.Image(t)
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "functions.db"))
	t.Setenv("TULE_Functions_RuntimeAPIPort", "0")
	cfg, err := loadEnvConfig(t, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	a := newStarted(t, cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = a.Server().Serve(ln) }()
	httpClient := &http.Client{Timeout: time.Minute}
	c := lambda.New(lambda.Options{
		Region: "us-east-1", BaseEndpoint: aws.String("http://" + ln.Addr().String()),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:       httpClient,
		RetryMaxAttempts: 1,
	})
	name := "stop-" + ids.Hex(4)
	createActive(t, c, name, image)

	invoked := make(chan error, 1)
	go func() {
		_, iErr := c.Invoke(context.Background(), &lambda.InvokeInput{
			FunctionName: aws.String(name), Payload: []byte(`{"sleepMs":4000}`),
		})
		invoked <- iErr
	}()
	waitRunning(t, name)
	httpClient.CloseIdleConnections()
	start := time.Now()
	stopped := make(chan error, 1)
	go func() { stopped <- a.Stop(context.Background()) }()
	select {
	case iErr := <-invoked:
		if iErr == nil {
			t.Fatal("the invocation succeeded across the stop")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the stop did not abort the invocation within 3s")
	}
	if err = <-stopped; err != nil {
		t.Fatalf("stop = %v, want a clean stop", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the stop took %v", took)
	}
	requireNoContainers(t, name)
}

// waitRunning waits for the function to have a running container, so the
// stop meets an invocation in flight rather than one still on its way.
func waitRunning(t *testing.T, function string) {
	t.Helper()
	dc, err := docker.New("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		found, lErr := dc.ListContainers(t.Context(), runner.LabelFunction, function)
		if lErr != nil {
			t.Fatal(lErr)
		}
		if len(found) > 0 {
			// The container runs; give the event the time to reach it.
			time.Sleep(200 * time.Millisecond)
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the invocation's container never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// requireNoContainers fails unless the function has no container left.
func requireNoContainers(t *testing.T, function string) {
	t.Helper()
	dc, err := docker.New("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	left, err := dc.ListContainers(context.Background(), runner.LabelFunction, function)
	if err != nil || len(left) != 0 {
		t.Fatalf("containers left: %v, %v", left, err)
	}
}

// newStarted builds and starts the app, which the test stops.
func newStarted(t *testing.T, cfg *Config) *gas.App {
	t.Helper()
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return a
}

// createActive creates a function of image and waits for it to be Active.
func createActive(t *testing.T, c *lambda.Client, name, image string) {
	t.Helper()
	_, err := c.CreateFunction(t.Context(), &lambda.CreateFunctionInput{
		FunctionName: aws.String(name),
		Role:         aws.String("arn:aws:iam::000000000000:role/r"),
		PackageType:  types.PackageTypeImage,
		Timeout:      aws.Int32(10),
		Code:         &types.FunctionCode{ImageUri: aws.String(image)},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = lambda.NewFunctionActiveWaiter(c, func(o *lambda.FunctionActiveWaiterOptions) {
		o.MinDelay, o.MaxDelay = 50*time.Millisecond, 100*time.Millisecond
	}).Wait(t.Context(), &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)},
		10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
}
