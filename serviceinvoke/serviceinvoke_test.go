package serviceinvoke_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/gasmod/gas/config"

	"tule.dev/functions/internal/app"
	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/testfn"
	"tule.dev/functions/serviceinvoke"
)

const (
	keyID          = "test"
	secret         = "test"
	region         = "us-east-1"
	secretsManager = "secretsmanager.amazonaws.com"
	secretARN      = "arn:aws:secretsmanager:us-east-1:000000000000:secret:db-AbCdEf"
)

// startFunctions runs the functions app on a fresh store, on the local
// Docker daemon, and returns its URL and a Lambda client for it.
func startFunctions(t *testing.T) (string, *lambda.Client) {
	t.Helper()
	dc, err := docker.New("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if err = dc.Ping(t.Context()); err != nil {
		t.Skipf("docker is not reachable: %v", err)
	}
	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "functions.db"))
	t.Setenv("TULE_Auth_AccessKeyID", keyID)
	t.Setenv("TULE_Auth_SecretAccessKey", secret)
	t.Setenv("TULE_Functions_RuntimeAPIPort", "0")
	cfg, err := app.LoadConfigFrom(config.NewEnvProvider(
		config.WithEnvSeparator("_"), config.WithEnvPrefix("TULE_")))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	a, err := app.New(cfg)
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
	return srv.URL, lambda.New(lambda.Options{
		Region:           region,
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider(keyID, secret, ""),
		RetryMaxAttempts: 1,
	})
}

func client(t *testing.T, url string) *serviceinvoke.Client {
	t.Helper()
	c, err := serviceinvoke.New(serviceinvoke.Config{
		Endpoint: url, Region: region, AccessKeyID: keyID, SecretAccessKey: secret,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

// createFunction creates name from image, and, when wait is set, waits for
// it to be Active.
func createFunction(t *testing.T, c *lambda.Client, name, image string, wait bool) {
	t.Helper()
	if _, err := c.CreateFunction(t.Context(), &lambda.CreateFunctionInput{
		FunctionName: aws.String(name),
		Role:         aws.String("arn:aws:iam::000000000000:role/r"),
		PackageType:  types.PackageTypeImage,
		Timeout:      aws.Int32(10),
		Code:         &types.FunctionCode{ImageUri: aws.String(image)},
	}); err != nil {
		t.Fatal(err)
	}
	if !wait {
		return
	}
	if err := lambda.NewFunctionActiveWaiter(c, func(o *lambda.FunctionActiveWaiterOptions) {
		o.MinDelay, o.MaxDelay = 50*time.Millisecond, 100*time.Millisecond
	}).Wait(t.Context(), &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)},
		10*time.Second); err != nil {
		t.Fatal(err)
	}
}

// grant allows secretsmanager.amazonaws.com to invoke name for the secret.
func grant(t *testing.T, c *lambda.Client, name string) {
	t.Helper()
	if _, err := c.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName: aws.String(name), StatementId: aws.String("secretsmanager"),
		Action: aws.String("lambda:InvokeFunction"), Principal: aws.String(secretsManager),
		SourceArn: aws.String(secretARN),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	for what, cfg := range map[string]serviceinvoke.Config{
		"no endpoint":    {Region: region, AccessKeyID: keyID, SecretAccessKey: secret},
		"a relative URL": {Endpoint: "localhost:9060", Region: region, AccessKeyID: keyID, SecretAccessKey: secret},
		"no region":      {Endpoint: "http://localhost:9060", AccessKeyID: keyID, SecretAccessKey: secret},
		"no access key":  {Endpoint: "http://localhost:9060", Region: region, SecretAccessKey: secret},
		"no secret":      {Endpoint: "http://localhost:9060", Region: region, AccessKeyID: keyID},
	} {
		if _, err := serviceinvoke.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", what)
		}
	}
}

func TestAServiceInvokesAFunctionThatAllowsIt(t *testing.T) {
	url, lc := startFunctions(t)
	createFunction(t, lc, "fn", testfn.Image(t), true)
	grant(t, lc, "fn")
	c := client(t, url)
	ctx := t.Context()

	res, err := c.Invoke(ctx, "fn", secretsManager, []byte(`{"action":"echo"}`),
		serviceinvoke.WithSourceArn(secretARN))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	requireEchoed(t, res)

	res, err = c.Invoke(ctx, "fn", secretsManager, []byte(`{"action":"error"}`),
		serviceinvoke.WithSourceArn(secretARN))
	if err != nil || res.FunctionError != "Unhandled" {
		t.Fatalf("a failing function: %+v, %v", res, err)
	}

	res, err = c.Invoke(ctx, "fn", secretsManager, nil,
		serviceinvoke.WithSourceArn(secretARN), serviceinvoke.WithEvent())
	if err != nil || res.StatusCode != http.StatusAccepted || res.Payload != nil {
		t.Fatalf("an Event invocation: %+v, %v", res, err)
	}
}

// requireEchoed fails unless res is the test function's successful reply,
// from the function fn.
func requireEchoed(t *testing.T, res *serviceinvoke.Result) {
	t.Helper()
	var reply struct {
		FunctionARN string `json:"functionArn"`
	}
	if res.StatusCode != http.StatusOK || res.ExecutedVersion != "$LATEST" ||
		res.FunctionError != "" || json.Unmarshal(res.Payload, &reply) != nil ||
		reply.FunctionARN != "arn:aws:lambda:us-east-1:000000000000:function:fn" {
		t.Fatalf("result = %+v (%s)", res, res.Payload)
	}
}

func TestTheRefusalsCanBeToldApart(t *testing.T) {
	url, lc := startFunctions(t)
	// The image does not exist, so the function is never Active.
	createFunction(t, lc, "inactive", "tule-functions-test:missing", false)
	grant(t, lc, "inactive")
	createFunction(t, lc, "nopolicy", "tule-functions-test:missing", false)
	c := client(t, url)
	ctx := t.Context()
	arn := serviceinvoke.WithSourceArn(secretARN)

	_, err := c.Invoke(ctx, "missing", secretsManager, nil, arn)
	if !errors.Is(err, serviceinvoke.ErrNotFound) {
		t.Errorf("a missing function: %v", err)
	}
	_, err = c.Invoke(ctx, "nopolicy", secretsManager, nil, arn)
	if !errors.Is(err, serviceinvoke.ErrAccessDenied) {
		t.Errorf("no function policy: %v", err)
	}
	_, err = c.Invoke(ctx, "inactive", "sns.amazonaws.com", nil, arn)
	if !errors.Is(err, serviceinvoke.ErrAccessDenied) {
		t.Errorf("another service: %v", err)
	}
	_, err = c.Invoke(ctx, "inactive", secretsManager, nil, arn)
	if !errors.Is(err, serviceinvoke.ErrConflict) {
		t.Errorf("a function that is not Active: %v", err)
	}
	var e *serviceinvoke.Error
	_, err = c.Invoke(ctx, "inactive", secretsManager, []byte(`{}`),
		serviceinvoke.WithSourceAccount("12"))
	if !errors.As(err, &e) || e.Status != http.StatusBadRequest ||
		e.Code != serviceinvoke.CodeInvalidRequest {
		t.Errorf("a malformed SourceAccount: %v", err)
	}
}

// TestOtherAnswersAreErrors checks the client against a local listener's
// answers the endpoint documents no sentinel for.
func TestOtherAnswersAreErrors(t *testing.T) {
	for what, c := range map[string]struct {
		body   string
		code   string
		status int
	}{
		"a sigv4 refusal":         {`{"Code":"UnknownAccessKey","Message":"m"}`, "UnknownAccessKey", 403},
		"a 404 of another code":   {`{"Code":"Other","Message":"m"}`, "Other", 404},
		"a body that is not JSON": {`oops`, "", 502},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != serviceinvoke.Path || r.Header.Get("Authorization") == "" {
				t.Errorf("%s: an unsigned call of %s", what, r.URL.Path)
			}
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		_, err := client(t, srv.URL).Invoke(t.Context(), "fn", secretsManager, nil)
		srv.Close()
		var e *serviceinvoke.Error
		if !errors.As(err, &e) || e.Status != c.status || e.Code != c.code {
			t.Errorf("%s: got %v", what, err)
		}
	}
}

// TestThePayloadAndTheResultAreSentAsTheyAre checks, against a local
// listener, that the payload reaches the endpoint byte for byte, its <, >
// and & and white space included, and that the result and the request ID
// come back as the endpoint sent them.
func TestThePayloadAndTheResultAreSentAsTheyAre(t *testing.T) {
	const payload = `{ "html": "<b>&amp;</b>",  "n": [1, 2] }`
	const result = `{"echo":"<script>&</script>", "x" : 1}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Payload json.RawMessage `json:"Payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
			string(req.Payload) != payload {
			t.Errorf("the endpoint got the payload %s, %v; want %s", req.Payload, err, payload)
		}
		w.Header().Set(serviceinvoke.RequestIDHeader, "req-1")
		_, _ = w.Write([]byte(`{"StatusCode":200,"ExecutedVersion":"$LATEST","Payload":` +
			result + `}`))
	}))
	defer srv.Close()
	res, err := client(t, srv.URL).Invoke(t.Context(), "fn", secretsManager, []byte(payload))
	if err != nil || string(res.Payload) != result || res.RequestID != "req-1" {
		t.Fatalf("result = %+v (%s), %v", res, res.Payload, err)
	}
	if _, err = client(t, srv.URL).Invoke(t.Context(), "fn", secretsManager,
		[]byte(`{"open":`)); err == nil {
		t.Fatal("a payload that is not JSON was sent")
	}
	setPayload := func(r *serviceinvoke.Request) { r.Payload = json.RawMessage(`{}`) }
	if _, err = client(t, srv.URL).Invoke(t.Context(), "fn", secretsManager,
		[]byte(`{}`), setPayload); err == nil {
		t.Fatal("an option's Payload was sent beside Invoke's")
	}
}

// TestAnEventPayloadIsMeasuredAsSent checks that an Event payload of
// exactly the 1 MB limit, all of it <, is accepted: escaped, it would be
// six times as long.
func TestAnEventPayloadIsMeasuredAsSent(t *testing.T) {
	url, lc := startFunctions(t)
	createFunction(t, lc, "fn", testfn.Image(t), true)
	grant(t, lc, "fn")
	payload := `"` + strings.Repeat("<", 1024*1024-2) + `"`
	res, err := client(t, url).Invoke(t.Context(), "fn", secretsManager, []byte(payload),
		serviceinvoke.WithSourceArn(secretARN), serviceinvoke.WithEvent())
	if err != nil || res.StatusCode != http.StatusAccepted || res.RequestID == "" {
		t.Fatalf("an Event payload of 1 MB of <: %+v, %v", res, err)
	}
	res, err = client(t, url).Invoke(t.Context(), "fn", secretsManager, nil,
		serviceinvoke.WithSourceArn(secretARN))
	if err != nil || res.RequestID == "" {
		t.Fatalf("a RequestResponse invocation's request ID: %+v, %v", res, err)
	}
}
