package runtimeapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeSession hands out one event and records what the runtime answered.
type fakeSession struct {
	event    *Event
	response string
	errType  string
	errBody  string
	initType string
	running  string
}

func (f *fakeSession) Next(ctx context.Context) (*Event, error) {
	if f.event == nil {
		<-ctx.Done()
		return nil, fmt.Errorf("next: %w", ctx.Err())
	}
	ev := f.event
	f.event = nil
	f.running = ev.RequestID
	return ev, nil
}

func (f *fakeSession) Respond(id string, body []byte) error {
	if id != f.running {
		return ErrUnknownRequest
	}
	f.response = string(body)
	return nil
}

func (f *fakeSession) Fail(id, errType string, body []byte) error {
	if id != f.running {
		return ErrUnknownRequest
	}
	f.errType, f.errBody = errType, string(body)
	return nil
}

func (f *fakeSession) InitFail(errType string, _ []byte) { f.initType = errType }

// answer is what the API answered.
type answer struct {
	header http.Header
	body   string
	status int
}

func call(t *testing.T, srv *httptest.Server, method, path, body string) answer {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path,
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerErrorType, "Function.Custom")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer{header: resp.Header, body: string(b), status: resp.StatusCode}
}

func TestARuntimeGetsItsEventAndResponds(t *testing.T) {
	s := NewServer()
	sess := &fakeSession{event: &Event{
		RequestID: "req-1", Deadline: time.UnixMilli(1700000000123),
		FunctionARN: "arn:aws:lambda:us-east-1:000000000000:function:f", TraceID: "Root=1-x",
		ClientContext: `{"custom":{"k":"v"}}`, Payload: []byte(`{"a":1}`),
	}}
	s.Register("tok", sess)
	srv := httptest.NewServer(s)
	defer srv.Close()

	got := call(t, srv, http.MethodGet, "/tok/2018-06-01/runtime/invocation/next", "")
	want := map[string]string{
		"Lambda-Runtime-Aws-Request-Id":       "req-1",
		"Lambda-Runtime-Deadline-Ms":          "1700000000123",
		"Lambda-Runtime-Invoked-Function-Arn": "arn:aws:lambda:us-east-1:000000000000:function:f",
		"Lambda-Runtime-Trace-Id":             "Root=1-x",
		"Lambda-Runtime-Client-Context":       `{"custom":{"k":"v"}}`,
	}
	for k, v := range want {
		if got.header.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.header.Get(k), v)
		}
	}
	if got.status != 200 || got.body != `{"a":1}` {
		t.Fatalf("next = %d %s", got.status, got.body)
	}
	if r := call(t, srv, http.MethodPost, "/tok/2018-06-01/runtime/invocation/other/response",
		"x"); r.status != http.StatusBadRequest {
		t.Fatalf("response for another request = %d, want 400", r.status)
	}
	if r := call(t, srv, http.MethodPost, "/tok/2018-06-01/runtime/invocation/req-1/response",
		`"done"`); r.status != http.StatusAccepted || sess.response != `"done"` {
		t.Fatalf("response = %d, recorded %q", r.status, sess.response)
	}
}

func TestARuntimeReportsErrors(t *testing.T) {
	s := NewServer()
	sess := &fakeSession{event: &Event{RequestID: "req-2"}}
	s.Register("tok", sess)
	srv := httptest.NewServer(s)
	defer srv.Close()

	call(t, srv, http.MethodGet, "/tok/2018-06-01/runtime/invocation/next", "")
	r := call(t, srv, http.MethodPost, "/tok/2018-06-01/runtime/invocation/req-2/error",
		`{"errorMessage":"m","errorType":"T"}`)
	if r.status != http.StatusAccepted || sess.errType != "Function.Custom" ||
		sess.errBody != `{"errorMessage":"m","errorType":"T"}` {
		t.Fatalf("error = %d, recorded %q %q", r.status, sess.errType, sess.errBody)
	}
	r = call(t, srv, http.MethodPost, "/tok/2018-06-01/runtime/init/error", `{}`)
	if r.status != http.StatusAccepted || sess.initType != "Function.Custom" {
		t.Fatalf("init error = %d, recorded %q", r.status, sess.initType)
	}
}

func TestATokenReachesOnlyItsOwnSession(t *testing.T) {
	s := NewServer()
	s.Register("mine", &fakeSession{event: &Event{RequestID: "secret"}})
	srv := httptest.NewServer(s)
	defer srv.Close()

	for _, path := range []string{
		"/theirs/2018-06-01/runtime/invocation/next",
		"/2018-06-01/runtime/invocation/next",
	} {
		if r := call(t, srv, http.MethodGet, path, ""); r.status != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", path, r.status)
		}
	}
	s.Unregister("mine")
	if r := call(t, srv, http.MethodGet, "/mine/2018-06-01/runtime/invocation/next",
		""); r.status != http.StatusForbidden {
		t.Errorf("after Unregister = %d, want 403", r.status)
	}
}

func TestATooLargeResponseFailsTheInvocation(t *testing.T) {
	s := NewServer()
	sess := &fakeSession{event: &Event{RequestID: "big"}}
	s.Register("tok", sess)
	srv := httptest.NewServer(s)
	defer srv.Close()

	call(t, srv, http.MethodGet, "/tok/2018-06-01/runtime/invocation/next", "")
	r := call(t, srv, http.MethodPost, "/tok/2018-06-01/runtime/invocation/big/response",
		strings.Repeat("x", MaxResponseSize+1))
	if r.status != http.StatusRequestEntityTooLarge ||
		sess.errType != "Function.ResponseSizeTooLarge" {
		t.Fatalf("too large = %d, recorded %q", r.status, sess.errType)
	}
}

func TestTheServerBoundsHeadersAndIdleConnections(t *testing.T) {
	srv := NewHTTPServer(NewServer(), 10*time.Minute)
	if srv.ReadHeaderTimeout != readHeaderTimeout || srv.IdleTimeout != 11*time.Minute {
		t.Fatalf("server timeouts = header %v, idle %v", srv.ReadHeaderTimeout, srv.IdleTimeout)
	}
	// invocation/next waits in its handler, so the whole request may not be
	// bounded, nor the write of its answer.
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Fatalf("read %v, write %v, want neither", srv.ReadTimeout, srv.WriteTimeout)
	}
}

func TestTheResponseLimitIsLambdas(t *testing.T) {
	if MaxResponseSize != 6291556 {
		t.Fatalf("MaxResponseSize = %d", MaxResponseSize)
	}
}
