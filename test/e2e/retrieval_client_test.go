//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// history is a client of the retrieval API under /_functions/, which is not
// an AWS API: each request is signed SigV4 for service lambda.
type history struct {
	srv     *server
	creds   aws.Credentials
	service string
}

func historyFor(srv *server) *history {
	return historyWith(srv, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
}

func historyWith(srv *server, creds aws.Credentials) *history {
	return &history{srv: srv, creds: creds, service: "lambda"}
}

// response is what the retrieval API answered.
type response struct {
	Header http.Header
	Body   []byte
	Status int
}

// invocation is a listed invocation. duration is in milliseconds.
type invocation struct {
	RequestID    string  `json:"requestId"`
	Function     string  `json:"function"`
	Time         string  `json:"time"`
	Source       string  `json:"source"`
	Status       string  `json:"status"`
	ErrorType    string  `json:"errorType"`
	ErrorMessage string  `json:"errorMessage"`
	Duration     float64 `json:"duration"`
	Attempts     int     `json:"attempts"`
}

// invocationDetail is one invocation with its payload, result and log.
type invocationDetail struct {
	Payload json.RawMessage `json:"payload"`
	Result  json.RawMessage `json:"result"`
	Log     string          `json:"log"`
	invocation
}

type invocationPage struct {
	NextCursor string       `json:"nextCursor"`
	Items      []invocation `json:"items"`
}

// do sends a signed request and returns the response.
func (h *history) do(t *testing.T, method, path string, q url.Values) response {
	t.Helper()
	req := h.request(t, method, path, q)
	sum := sha256.Sum256(nil)
	err := v4.NewSigner().SignHTTP(context.Background(), h.creds, req,
		hex.EncodeToString(sum[:]), h.service, region, time.Now())
	requireNoErr(t, err, "sign "+method+" "+path)
	return h.send(t, req)
}

func (h *history) doUnsigned(t *testing.T, method, path string) response {
	t.Helper()
	return h.send(t, h.request(t, method, path, nil))
}

func (h *history) request(t *testing.T, method, path string, q url.Values) *http.Request {
	t.Helper()
	u := h.srv.URL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, http.NoBody)
	requireNoErr(t, err, "build "+method+" "+path)
	return req
}

func (h *history) send(t *testing.T, req *http.Request) response {
	t.Helper()
	res, err := h.srv.Client().Do(req)
	requireNoErr(t, err, req.Method+" "+req.URL.Path)
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	requireNoErr(t, err, "read "+req.Method+" "+req.URL.Path)
	return response{Status: res.StatusCode, Header: res.Header, Body: body}
}

// list lists one page of invocations matching q.
func (h *history) list(t *testing.T, q url.Values) invocationPage {
	t.Helper()
	res := h.do(t, http.MethodGet, "/_functions/invocations", q)
	requireOK(t, res, "list invocations "+q.Encode())
	var shape map[string]json.RawMessage
	decode(t, res, &shape)
	if v := bytes.TrimSpace(shape["items"]); len(v) == 0 || v[0] != '[' {
		t.Fatalf("items is %s, want an array: %s", shape["items"], res.Body)
	}
	var p invocationPage
	decode(t, res, &p)
	for _, it := range p.Items {
		requireInvocationShape(t, it)
	}
	return p
}

// all lists every invocation matching q, following the cursor.
func (h *history) all(t *testing.T, q url.Values) []invocation {
	t.Helper()
	params := url.Values{}
	for k, v := range q {
		params[k] = v
	}
	var out []invocation
	for range 1000 {
		p := h.list(t, params)
		out = append(out, p.Items...)
		if p.NextCursor == "" {
			return out
		}
		params.Set("cursor", p.NextCursor)
	}
	t.Fatal("the cursor did not end after 1000 pages")
	return nil
}

// get returns one invocation with its payload, result and log.
func (h *history) get(t *testing.T, requestID string) invocationDetail {
	t.Helper()
	res := h.do(t, http.MethodGet, "/_functions/invocations/"+url.PathEscape(requestID), nil)
	requireOK(t, res, "get invocation "+requestID)
	var d invocationDetail
	decode(t, res, &d)
	requireInvocationShape(t, d.invocation)
	requireEqual(t, d.RequestID, requestID, "requestId of the fetched invocation")
	return d
}

func (h *history) reset(t *testing.T) {
	t.Helper()
	res := h.do(t, http.MethodDelete, "/_functions/invocations", nil)
	if res.Status != http.StatusOK && res.Status != http.StatusNoContent {
		t.Fatalf("reset: status %d, want 200 or 204: %s", res.Status, res.Body)
	}
}

// requireInvocationShape checks what every listed invocation holds.
func requireInvocationShape(t *testing.T, it invocation) {
	t.Helper()
	if it.RequestID == "" || it.Function == "" {
		t.Fatalf("invocation without a requestId or a function: %+v", it)
	}
	it.at(t)
	switch it.Status {
	case "succeeded", "failed", "timedOut":
	default:
		t.Fatalf("invocation %s has status %q", it.RequestID, it.Status)
	}
	switch it.Source {
	case "invoke", "async", "eventSourceMapping":
	default:
		t.Fatalf("invocation %s has source %q", it.RequestID, it.Source)
	}
	if it.Duration < 0 {
		t.Fatalf("invocation %s has duration %v", it.RequestID, it.Duration)
	}
}

// at parses the invocation's time. Assumption: RFC 3339, as the siblings'
// retrieval APIs answer times.
func (it invocation) at(t *testing.T) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, it.Time)
	if err != nil {
		t.Fatalf("invocation %s: time %q is not RFC 3339: %v", it.RequestID, it.Time, err)
	}
	return v
}

// payloadJSON is the recorded payload as JSON. Assumption: the API holds
// it either as the JSON value itself or as a string of it; the design does
// not say which.
func (d invocationDetail) payloadJSON(t *testing.T) []byte {
	t.Helper()
	return asJSON(t, d.Payload, "payload")
}

// resultJSON is the recorded result as JSON, like payloadJSON.
func (d invocationDetail) resultJSON(t *testing.T) []byte {
	t.Helper()
	return asJSON(t, d.Result, "result")
}

func asJSON(t *testing.T, raw json.RawMessage, what string) []byte {
	t.Helper()
	v := bytes.TrimSpace(raw)
	if len(v) == 0 || string(v) == "null" {
		t.Fatalf("no %s recorded", what)
	}
	if v[0] != '"' {
		return v
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		t.Fatalf("decode %s %s: %v", what, v, err)
	}
	return []byte(s)
}

// requireJSONEqual fails unless got and want are the same JSON value.
func requireJSONEqual(t *testing.T, got []byte, want, what string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("%s: %s is not JSON: %v", what, got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("%s: want %s is not JSON: %v", what, want, err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("%s: got %s, want %s", what, got, want)
	}
}

func decode(t *testing.T, res response, v any) {
	t.Helper()
	if err := json.Unmarshal(res.Body, v); err != nil {
		t.Fatalf("decode %s: %v", res.Body, err)
	}
}

func requireOK(t *testing.T, res response, what string) {
	t.Helper()
	if res.Status != http.StatusOK {
		t.Fatalf("%s: status %d, want 200: %s", what, res.Status, res.Body)
	}
}

// requireAPIErrorBody fails unless res has the given status, an
// X-Amzn-ErrorType header and a JSON body {code, message} with the same
// code. The code itself is not pinned: the design names none.
func requireAPIErrorBody(t *testing.T, res response, status int, what string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("%s: status %d, want %d: %s", what, res.Status, status, res.Body)
	}
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(res.Body, &e); err != nil {
		t.Fatalf("%s: error body is not JSON: %v: %s", what, err, res.Body)
	}
	if e.Code == "" || e.Message == "" {
		t.Fatalf("%s: error body lacks a code or a message: %s", what, res.Body)
	}
	header, _, _ := strings.Cut(res.Header.Get("X-Amzn-ErrorType"), ":")
	if header == "" {
		t.Fatalf("%s: no X-Amzn-ErrorType header", what)
	}
	requireEqual(t, header, e.Code, what+": X-Amzn-ErrorType against the body's code")
}
