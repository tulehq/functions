//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// envResult is what the env test function answers.
type envResult struct {
	Env                map[string]string `json:"env"`
	ClientCustom       map[string]string `json:"clientCustom"`
	RequestID          string            `json:"requestId"`
	InvokedFunctionArn string            `json:"invokedFunctionArn"`
	DeadlineMs         int64             `json:"deadlineMs"`
}

// sleepResult is what the sleep test function answers.
type sleepResult struct {
	Host  string `json:"host"`
	Slept int    `json:"slept"`
}

func TestInvokeEcho(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "echo", "echo", nil)

	payload := `{"greeting":"hello","n":[1,2,3],"nested":{"ok":true}}`
	out := invokeOK(t, c, "echo", []byte(payload), nil)
	requireEqual(t, string(out.Payload), payload, "echoed payload")
	// "ExecutedVersion": "$LATEST" (Invoke a function synchronously).
	requireEqual(t, aws.ToString(out.ExecutedVersion), "$LATEST", "ExecutedVersion")
	if out.LogResult != nil {
		t.Fatalf("LogResult without LogType Tail: %q", *out.LogResult)
	}
}

func TestInvokeEnvironment(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "envy", "env", func(in *lambda.CreateFunctionInput) {
		in.MemorySize = aws.Int32(256)
		in.Timeout = aws.Int32(9)
		in.Environment = &types.Environment{Variables: map[string]string{"GREETING": "hello"}}
	})

	var r envResult
	start := time.Now()
	invokeOK(t, c, "envy", map[string]any{}, &r)

	requireEqual(t, r.Env["GREETING"], "hello", "the function's own variable")
	// Defined runtime environment variables (Working with Lambda
	// environment variables).
	for k, want := range map[string]string{
		"AWS_LAMBDA_FUNCTION_NAME":        "envy",
		"AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "256",
		"AWS_LAMBDA_FUNCTION_VERSION":     "$LATEST",
		"AWS_REGION":                      region,
		"AWS_DEFAULT_REGION":              region,
		"AWS_LAMBDA_INITIALIZATION_TYPE":  "on-demand",
	} {
		requireEqual(t, r.Env[k], want, k)
	}
	for _, k := range []string{
		"AWS_LAMBDA_RUNTIME_API", "AWS_LAMBDA_LOG_GROUP_NAME", "AWS_LAMBDA_LOG_STREAM_NAME",
	} {
		if r.Env[k] == "" {
			t.Fatalf("%s is not set in the function", k)
		}
	}

	// The Runtime API's next-invocation headers, as aws-lambda-go hands
	// them to the handler: the request ID, the invoked function's ARN, and
	// the deadline, the timeout after the invocation began.
	if r.RequestID == "" {
		t.Fatal("the function saw no request ID")
	}
	requireEqual(
		t,
		r.InvokedFunctionArn,
		functionARN("envy"),
		"Lambda-Runtime-Invoked-Function-Arn",
	)
	deadline := time.UnixMilli(r.DeadlineMs)
	if lo, hi := start.Add(8*time.Second), time.Now().Add(9*time.Second); deadline.Before(lo) ||
		deadline.After(hi) {
		t.Fatalf("deadline %v, want about 9s after the invocation began (%v)", deadline, start)
	}
}

func TestInvokeRequestIDHeader(t *testing.T) {
	// Assumption: the Invoke response's x-amzn-RequestId is the request ID
	// the function saw, as AWS answers; no page states it.
	c, _ := newClient(t)
	createFunction(t, c, "rid", "env", nil)
	var r envResult
	out := invokeOK(t, c, "rid", map[string]any{}, &r)
	id, _ := middleware.GetRequestIDMetadata(out.ResultMetadata)
	requireEqual(t, id, r.RequestID, "x-amzn-RequestId")
}

func TestInvokeClientContext(t *testing.T) {
	// ClientContext, "base64-encoded data about the invoking client to pass
	// to the function in the context object" (Invoke), passed through.
	c, _ := newClient(t)
	createFunction(t, c, "ctx", "env", nil)
	cc := base64.StdEncoding.EncodeToString([]byte(`{"custom":{"user":"u-1"}}`))
	out := invokeWith(t, c, &lambda.InvokeInput{
		FunctionName:  aws.String("ctx"),
		ClientContext: aws.String(cc),
		Payload:       []byte(`{}`),
	})
	var r envResult
	unmarshal(t, out.Payload, &r)
	requireEqual(t, r.ClientCustom["user"], "u-1", "client context custom field")
}

func TestInvokeHandledError(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "fails", "errors", nil)
	e := requireFunctionError(t, invoke(t, c, "fails", map[string]string{"message": "nope"}))
	requireEqual(t, e.ErrorMessage, "handled failure: nope", "errorMessage")
	// aws-lambda-go reports the error's type name: errors.New is an
	// *errors.errorString.
	requireEqual(t, e.ErrorType, "errorString", "errorType")
}

func TestInvokePanic(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "panics", "panic", nil)
	e := requireFunctionError(t, invoke(t, c, "panics", map[string]string{"message": "boom"}))
	requireEqual(t, e.ErrorMessage, "boom", "errorMessage")
	// aws-lambda-go reports a panic with the panic value's type and the
	// stack (lambdaPanicResponse), then exits.
	requireEqual(t, e.ErrorType, "string", "errorType")
	if len(e.StackTrace) == 0 {
		t.Fatal("a panic's error has no stackTrace")
	}

	// Assumption: the next invocation gets a working environment, though
	// the runtime exited after the panic; no page states it for images.
	out := invokeOK(t, c, "panics", map[string]bool{"ok": true}, nil)
	requireEqual(t, string(out.Payload), `"survived"`, "invocation after a panic")
}

func TestInvokeTimeout(t *testing.T) {
	// The design: the container is stopped and the invocation fails as
	// Lambda reports a timeout: "Task timed out after 1.00 seconds"
	// (Troubleshoot invocation issues).
	c, _ := newClient(t)
	createFunction(t, c, "slow", "sleep", func(in *lambda.CreateFunctionInput) {
		in.Timeout = aws.Int32(1)
	})

	var out *lambda.InvokeOutput
	within(t, 5*time.Second, "an invocation past its 1s timeout", func() {
		out = invoke(t, c, "slow", map[string]int{"ms": 20000})
	})
	e := requireFunctionError(t, out)
	requireContains(t, e.ErrorMessage, "Task timed out after 1.00 seconds", "errorMessage")

	// The next invocation runs in a fresh container and succeeds.
	var r sleepResult
	invokeOK(t, c, "slow", map[string]int{"ms": 10}, &r)
	requireEqual(t, r.Slept, 10, "invocation after the timeout")
}

func TestInvokeInvalidJSON(t *testing.T) {
	// InvalidRequestContentException: "The request body could not be parsed
	// as JSON" (Invoke, 400).
	c, _ := newClient(t)
	createFunction(t, c, "strict", "echo", nil)
	err := errOf(c.Invoke(t.Context(), &lambda.InvokeInput{
		FunctionName: aws.String("strict"),
		Payload:      []byte("value"),
	}))
	requireModeled[*types.InvalidRequestContentException](t, err)
}

// reportLine is Lambda's REPORT line (Invoke a function synchronously).
var reportLine = regexp.MustCompile(
	`REPORT RequestId: (\S+)\s+Duration: [0-9.]+ ms\s+Billed Duration: \d+ ms\s+` +
		`Memory Size: (\d+) MB`)

func TestInvokeTailLog(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "loud", "env", nil)
	out := invokeWith(t, c, &lambda.InvokeInput{
		FunctionName: aws.String("loud"),
		LogType:      types.LogTypeTail,
		Payload:      []byte(`{}`),
	})
	var r envResult
	unmarshal(t, out.Payload, &r)
	log := decodeLog(t, out)

	requireContains(t, log, "START RequestId: "+r.RequestID+" Version: $LATEST", "START line")
	requireContains(t, log, "env: reported", "the function's own output")
	requireContains(t, log, "END RequestId: "+r.RequestID, "END line")
	m := reportLine.FindStringSubmatch(log)
	if m == nil {
		t.Fatalf("no REPORT line in the log:\n%s", log)
	}
	requireEqual(t, m[1], r.RequestID, "REPORT RequestId")
	requireEqual(t, m[2], "128", "REPORT Memory Size")

	// In order: START, the output, END, REPORT.
	iStart, iOut := strings.Index(log, "START RequestId"), strings.Index(log, "env: reported")
	iEnd, iReport := strings.Index(log, "END RequestId"), strings.Index(log, "REPORT RequestId")
	if iStart >= iOut || iOut >= iEnd || iEnd >= iReport {
		t.Fatalf("log lines out of order:\n%s", log)
	}
}

func TestInvokeTailLogIsTheLast4KB(t *testing.T) {
	// LogResult: "The last 4 KB of the execution log, which is base64-encoded"
	// (Invoke). The echo function prints a 10 KB payload, so the tail ends
	// with the REPORT line and holds at most 4 KB.
	c, _ := newClient(t)
	createFunction(t, c, "big", "echo", nil)
	big := strings.Repeat("x", 10*1024)
	out := invokeWith(t, c, &lambda.InvokeInput{
		FunctionName: aws.String("big"),
		LogType:      types.LogTypeTail,
		Payload:      marshal(t, map[string]string{"big": big}),
	})
	log := decodeLog(t, out)
	if len(log) > 4096 {
		t.Fatalf("the tail is %d bytes, want at most 4096", len(log))
	}
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if !reportLine.MatchString(lines[len(lines)-1]) {
		t.Fatalf("the tail does not end with the REPORT line:\n%s", log[max(0, len(log)-300):])
	}
}

func TestInvokeTimeoutLog(t *testing.T) {
	// "Task timed out" appears in a timed-out invocation's log
	// (How do I troubleshoot Lambda function invocation timeout errors?).
	c, _ := newClient(t)
	createFunction(t, c, "slowlog", "sleep", func(in *lambda.CreateFunctionInput) {
		in.Timeout = aws.Int32(1)
	})
	out := invokeWith(t, c, &lambda.InvokeInput{
		FunctionName: aws.String("slowlog"),
		LogType:      types.LogTypeTail,
		Payload:      []byte(`{"ms":20000}`),
	})
	log := decodeLog(t, out)
	requireContains(t, log, "sleep: sleeping", "the function's output before the timeout")
	requireContains(t, log, "Task timed out", "the timeout in the log")
}

func decodeLog(t *testing.T, out *lambda.InvokeOutput) string {
	t.Helper()
	if out.LogResult == nil {
		t.Fatal("no LogResult with LogType Tail")
	}
	b, err := base64.StdEncoding.DecodeString(*out.LogResult)
	requireNoErr(t, err, "decode LogResult")
	return string(b)
}

func TestInvokeEvent(t *testing.T) {
	// InvocationType Event: "this status code is 202" (Invoke), with no
	// function payload; the invocation runs and the history shows it.
	c, srv := newClient(t)
	createFunction(t, c, "later", "echo", nil)
	out := invokeWith(t, c, &lambda.InvokeInput{
		FunctionName:   aws.String("later"),
		InvocationType: types.InvocationTypeEvent,
		Payload:        []byte(`{"async":true}`),
	})
	requireEqual(t, out.StatusCode, int32(202), "Event status")
	requireEqual(t, len(out.Payload), 0, "Event payload length")

	h := historyFor(srv)
	var items []invocation
	eventually(t, 20*time.Second, "the async invocation in the history", func() bool {
		items = h.all(t, url.Values{"function": {"later"}, "status": {"succeeded"}})
		return len(items) == 1
	})
	requireEqual(t, items[0].Source, "async", "source")
	d := h.get(t, items[0].RequestID)
	requireJSONEqual(t, d.payloadJSON(t), `{"async":true}`, "recorded payload")
}

func TestInvokeDryRun(t *testing.T) {
	// InvocationType DryRun: "Validate parameter values and verify that the
	// user or role has permission"; "the status code is 204" (Invoke). It
	// runs nothing, so the history stays empty.
	c, srv := newClient(t)
	createFunction(t, c, "dry", "echo", nil)
	out := invokeWith(t, c, &lambda.InvokeInput{
		FunctionName:   aws.String("dry"),
		InvocationType: types.InvocationTypeDryRun,
		Payload:        []byte(`{}`),
	})
	requireEqual(t, out.StatusCode, int32(204), "DryRun status")
	requireEqual(t, len(historyFor(srv).all(t, nil)), 0, "invocations after a DryRun")

	err := errOf(c.Invoke(t.Context(), &lambda.InvokeInput{
		FunctionName:   aws.String("nobody"),
		InvocationType: types.InvocationTypeDryRun,
	}))
	requireModeled[*types.ResourceNotFoundException](t, err)
}

func TestInvokeConcurrently(t *testing.T) {
	// The design: more concurrent invocations start more containers. Four
	// 2s invocations at once finish well before the 8s they would take
	// one at a time, on at least two containers.
	c, _ := newClient(t)
	createFunction(t, c, "busy", "sleep", func(in *lambda.CreateFunctionInput) {
		in.Timeout = aws.Int32(30)
	})
	const n = 4
	results := make(chan sleepResult, n)
	errs := make(chan error, n)
	within(t, 7*time.Second, strconv.Itoa(n)+" concurrent 2s invocations", func() {
		for range n {
			go func() {
				out, err := c.Invoke(t.Context(), &lambda.InvokeInput{
					FunctionName: aws.String("busy"),
					Payload:      []byte(`{"ms":2000}`),
				})
				if err == nil && out.FunctionError != nil {
					err = &invokeError{payload: string(out.Payload)}
				}
				var r sleepResult
				if err == nil {
					err = json.Unmarshal(out.Payload, &r)
				}
				errs <- err
				results <- r
			}()
		}
		for range n {
			requireNoErr(t, <-errs, "concurrent invocation")
		}
	})
	hosts := map[string]bool{}
	for range n {
		hosts[(<-results).Host] = true
	}
	if len(hosts) < 2 {
		t.Fatalf("%d concurrent invocations ran on %d container(s), want at least 2", n, len(hosts))
	}
}

type invokeError struct{ payload string }

func (e *invokeError) Error() string { return "function error: " + e.payload }

func TestWarmContainerIsReused(t *testing.T) {
	// The design: containers are reused while warm.
	c, _ := newClient(t)
	createFunction(t, c, "warm", "sleep", nil)
	var a, b sleepResult
	invokeOK(t, c, "warm", map[string]int{"ms": 1}, &a)
	invokeOK(t, c, "warm", map[string]int{"ms": 1}, &b)
	requireEqual(t, b.Host, a.Host, "container of the second invocation")
}
