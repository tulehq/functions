//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// corpus is four invocations made in order, so the newest is d: a and d of
// echo (a synchronous, d asynchronous), b a handled error of errs, c a
// timeout of slow. between falls after b and before c, to the second.
type corpus struct {
	a, b, c, d string // request IDs
	between    string
	payload    string
}

func seed(t *testing.T, c *lambda.Client, h *history) corpus {
	t.Helper()

	createFunction(t, c, "echo", "echo", nil)
	createFunction(t, c, "errs", "errors", nil)
	createFunction(t, c, "slow", "sleep", func(in *lambda.CreateFunctionInput) {
		in.Timeout = aws.Int32(1)
	})

	k := corpus{payload: `{"seed":"a"}`}
	invokeOK(t, c, "echo", []byte(k.payload), nil)
	k.a = awaitOnly(t, h, url.Values{"function": {"echo"}}).RequestID
	time.Sleep(20 * time.Millisecond)
	invoke(t, c, "errs", map[string]string{"message": "b"})
	k.b = awaitOnly(t, h, url.Values{"function": {"errs"}}).RequestID

	// The bounds are RFC 3339 to the second, so between is 1.5s clear of
	// both sides.
	time.Sleep(1500 * time.Millisecond)
	k.between = time.Now().UTC().Format(time.RFC3339)
	time.Sleep(1500 * time.Millisecond)

	invoke(t, c, "slow", map[string]int{"ms": 20000})
	k.c = awaitOnly(t, h, url.Values{"function": {"slow"}}).RequestID
	time.Sleep(20 * time.Millisecond)
	invokeWith(t, c, &lambda.InvokeInput{
		FunctionName:   aws.String("echo"),
		InvocationType: types.InvocationTypeEvent,
		Payload:        []byte(`{"seed":"d"}`),
	})
	eventually(t, 20*time.Second, "the async invocation in the history", func() bool {
		return len(h.all(t, url.Values{"source": {"async"}})) == 1
	})
	k.d = awaitOnly(t, h, url.Values{"source": {"async"}}).RequestID
	return k
}

// only returns the single invocation matching q, failing otherwise.
func only(t *testing.T, h *history, q url.Values) invocation {
	t.Helper()
	items := h.all(t, q)
	if len(items) != 1 {
		t.Fatalf("%s: %d invocations, want 1: %+v", q.Encode(), len(items), items)
	}
	return items[0]
}

func requestIDs(items []invocation) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.RequestID)
	}
	return out
}

func TestRetrievalFilters(t *testing.T) {
	c, srv := newClient(t)
	h := historyFor(srv)
	k := seed(t, c, h)

	for _, tt := range []struct {
		query url.Values
		name  string
		want  []string
	}{
		{name: "none", want: []string{k.d, k.c, k.b, k.a}},
		{name: "function", query: url.Values{"function": {"echo"}}, want: []string{k.d, k.a}},
		{name: "succeeded", query: url.Values{"status": {"succeeded"}}, want: []string{k.d, k.a}},
		{name: "failed", query: url.Values{"status": {"failed"}}, want: []string{k.b}},
		{name: "timedOut", query: url.Values{"status": {"timedOut"}}, want: []string{k.c}},
		{name: "invoke", query: url.Values{"source": {"invoke"}}, want: []string{k.c, k.b, k.a}},
		{name: "async", query: url.Values{"source": {"async"}}, want: []string{k.d}},
		{name: "eventSourceMapping", query: url.Values{"source": {"eventSourceMapping"}}},
		{name: "since", query: url.Values{"since": {k.between}}, want: []string{k.d, k.c}},
		{name: "until", query: url.Values{"until": {k.between}}, want: []string{k.b, k.a}},
		{name: "function and source", query: url.Values{
			"function": {"echo"}, "source": {"invoke"},
		}, want: []string{k.a}},
		{name: "matching nothing together", query: url.Values{
			"function": {"errs"}, "status": {"succeeded"},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := requestIDs(h.all(t, tt.query))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRetrievalPagination(t *testing.T) {
	c, srv := newClient(t)
	h := historyFor(srv)
	k := seed(t, c, h)

	q := url.Values{"limit": {"1"}}
	var got []string
	for range 10 {
		p := h.list(t, q)
		if len(p.Items) > 1 {
			t.Fatalf("limit 1 answered %d items", len(p.Items))
		}
		got = append(got, requestIDs(p.Items)...)
		if p.NextCursor == "" {
			break
		}
		q.Set("cursor", p.NextCursor)
	}
	requireSlice(t, got, []string{k.d, k.c, k.b, k.a}, "pages of one, newest first")

	p := h.list(t, url.Values{"limit": {"3"}})
	requireEqual(t, len(p.Items), 3, "items with limit 3")
	if p.NextCursor == "" {
		t.Fatal("no nextCursor with a fourth invocation left")
	}
	rest := h.list(t, url.Values{"limit": {"3"}, "cursor": {p.NextCursor}})
	requireSlice(t, requestIDs(rest.Items), []string{k.a}, "the page after the cursor")
	requireEqual(t, rest.NextCursor, "", "nextCursor of the last page")
}

func TestRetrievalFields(t *testing.T) {
	c, srv := newClient(t)
	h := historyFor(srv)
	k := seed(t, c, h)

	a := h.get(t, k.a)
	requireEqual(t, a.Function, "echo", "function")
	requireEqual(t, a.Source, "invoke", "source")
	requireEqual(t, a.Status, "succeeded", "status")
	requireJSONEqual(t, a.payloadJSON(t), k.payload, "payload")
	requireJSONEqual(t, a.resultJSON(t), k.payload, "result")
	requireContains(t, a.Log, "START RequestId: "+k.a, "log START")
	requireContains(t, a.Log, "echo: ", "log output")
	requireContains(t, a.Log, "END RequestId: "+k.a, "log END")
	requireContains(t, a.Log, "REPORT RequestId: "+k.a, "log REPORT")

	b := h.get(t, k.b)
	requireEqual(t, b.Status, "failed", "status of the handled error")
	requireEqual(t, b.ErrorType, "errorString", "errorType")
	requireEqual(t, b.ErrorMessage, "handled failure: b", "errorMessage")

	cc := h.get(t, k.c)
	requireEqual(t, cc.Status, "timedOut", "status of the timeout")
	requireContains(t, cc.ErrorMessage, "Task timed out", "errorMessage of the timeout")
	if cc.Duration < 900 {
		t.Fatalf("a 1s timeout lasted %vms", cc.Duration)
	}
}

func TestRetrievalErrors(t *testing.T) {
	// Assumption: an unknown request ID is 404 and a bad query 400, with the
	// API's JSON error; the design does not name the codes.
	c, srv := newClient(t)
	h := historyFor(srv)
	createFunction(t, c, "echo", "echo", nil)
	invokeOK(t, c, "echo", map[string]string{}, nil)

	requireAPIErrorBody(t, h.do(t, http.MethodGet, "/_functions/invocations/no-such-id", nil),
		http.StatusNotFound, "an unknown request ID")
	for _, q := range []url.Values{
		{"status": {"sleeping"}},
		{"source": {"mail"}},
		{"since": {"yesterday"}},
		{"until": {"tomorrow"}},
		{"limit": {"0"}},
		{"limit": {"ten"}},
		{"cursor": {"not-a-cursor"}},
	} {
		requireAPIErrorBody(t, h.do(t, http.MethodGet, "/_functions/invocations", q),
			http.StatusBadRequest, "query "+q.Encode())
	}
}

func TestRetrievalReset(t *testing.T) {
	c, srv := newClient(t)
	h := historyFor(srv)
	createFunction(t, c, "echo", "echo", nil)
	invokeOK(t, c, "echo", map[string]string{}, nil)
	id := only(t, h, nil).RequestID

	h.reset(t)
	requireEqual(t, len(h.all(t, nil)), 0, "invocations after the reset")
	requireAPIErrorBody(t, h.do(t, http.MethodGet, "/_functions/invocations/"+id, nil),
		http.StatusNotFound, "a reset invocation")

	// The history keeps recording after a reset.
	invokeOK(t, c, "echo", map[string]string{}, nil)
	only(t, h, nil)
}

func TestRetrievalRefusesBadSignatures(t *testing.T) {
	// Assumption: refused with 403, as tule.dev/sigv4 refuses a request it
	// cannot authenticate, and with the API's JSON error.
	c, srv := newClient(t)
	createFunction(t, c, "echo", "echo", nil)
	invokeOK(t, c, "echo", map[string]string{}, nil)
	h := historyFor(srv)
	id := only(t, h, nil).RequestID

	wrongSecret := historyWith(srv, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "wrong"})
	unknownKey := historyWith(srv, aws.Credentials{AccessKeyID: "other", SecretAccessKey: "test"})
	otherService := historyFor(srv)
	otherService.service = "s3"

	for name, do := range map[string]func(method, path string) response{
		"unsigned":      func(m, p string) response { return h.doUnsigned(t, m, p) },
		"wrong secret":  func(m, p string) response { return wrongSecret.do(t, m, p, nil) },
		"unknown key":   func(m, p string) response { return unknownKey.do(t, m, p, nil) },
		"signed for s3": func(m, p string) response { return otherService.do(t, m, p, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			requireAPIErrorBody(t, do(http.MethodGet, "/_functions/invocations"),
				http.StatusForbidden, "list")
			requireAPIErrorBody(t, do(http.MethodGet, "/_functions/invocations/"+id),
				http.StatusForbidden, "get")
			requireAPIErrorBody(t, do(http.MethodDelete, "/_functions/invocations"),
				http.StatusForbidden, "reset")
		})
	}
	// None of the refused resets deleted anything.
	h.get(t, id)
}

func TestLambdaRefusesBadSignatures(t *testing.T) {
	// Assumption: refused with 403, the status AWS answers a key or
	// signature it does not accept with; the code is not asserted.
	srv := startServer(t, nil)
	for name, creds := range map[string]aws.Credentials{
		"wrong secret": {AccessKeyID: "test", SecretAccessKey: "wrong"},
		"unknown key":  {AccessKeyID: "other", SecretAccessKey: "test"},
	} {
		t.Run(name, func(t *testing.T) {
			err := errOf(lambdaClientWith(srv, creds).CreateFunction(t.Context(),
				createInput("refused", "echo")))
			requireAPIError(t, err)
			requireStatus(t, err, http.StatusForbidden)
		})
	}
	out, err := clientFor(srv).ListFunctions(t.Context(), &lambda.ListFunctionsInput{})
	requireNoErr(t, err, "list functions")
	requireEqual(t, len(out.Functions), 0, "functions after the refused creates")
}

// awaitOnly waits up to 5s for exactly one invocation to match q and
// returns it.
func awaitOnly(t *testing.T, h *history, q url.Values) invocation {
	t.Helper()
	eventually(t, 5*time.Second, "one invocation matching "+q.Encode(), func() bool {
		return len(h.all(t, q)) == 1
	})
	return only(t, h, q)
}
