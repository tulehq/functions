// Package runtimeapi serves the Lambda Runtime API, version 2018-06-01, to
// the function containers: invocation/next, invocation/{id}/response,
// invocation/{id}/error and init/error, with the headers and bodies the
// Lambda developer guide gives them.
//
// The API is not signed, since containers do not sign. Each container is
// given its own path prefix, a random token, in AWS_LAMBDA_RUNTIME_API, and
// a request is served by the session registered for its token only: a
// container cannot reach another's prefix without its token, and a request
// whose token is not registered is refused.
package runtimeapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the Runtime API version in every path.
const Version = "2018-06-01"

// MaxResponseSize is the largest response a function may return, as the
// Runtime API's error for a larger one gives it: 6291556 bytes.
const MaxResponseSize = 6291556

// The server's timeouts. A runtime's invocation/next waits, in the handler,
// for as long as there is no event, so the server has no read or write
// timeout of its own: headers must arrive within readHeaderTimeout, and a
// response or error body within bodyTimeout, set on those requests only.
const (
	readHeaderTimeout = 10 * time.Second
	bodyTimeout       = time.Minute
)

// NewHTTPServer returns the HTTP server for s. A runtime keeps its
// connections while its container is paused between invocations, so they
// may sit idle for as long as a container may, idleTimeout, and a minute
// more.
func NewHTTPServer(s *Server, idleTimeout time.Duration) *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout + time.Minute,
	}
}

// bodyDeadline bounds the read of a request's body.
func bodyDeadline(w http.ResponseWriter) {
	// The writer is net/http's own, which supports read deadlines.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyTimeout))
}

// maxErrorSize bounds an error or init error body.
const maxErrorSize = 1 << 20

// The headers of the Runtime API.
const (
	headerRequestID     = "Lambda-Runtime-Aws-Request-Id"
	headerDeadline      = "Lambda-Runtime-Deadline-Ms"
	headerFunctionARN   = "Lambda-Runtime-Invoked-Function-Arn"
	headerTraceID       = "Lambda-Runtime-Trace-Id"
	headerClientContext = "Lambda-Runtime-Client-Context"
	headerErrorType     = "Lambda-Runtime-Function-Error-Type"
	// headerErrorBody is the trailer aws-lambda-go sends, base64, when it
	// failed while streaming a response.
	headerErrorBody = "Lambda-Runtime-Function-Error-Body"
)

// Event is one invocation handed to a runtime.
type Event struct {
	Deadline      time.Time
	RequestID     string
	FunctionARN   string
	TraceID       string
	ClientContext string
	Payload       []byte
}

// ErrUnknownRequest is returned by a session for a response or error that
// names a request it is not running.
var ErrUnknownRequest = errors.New("runtimeapi: unknown request ID")

// Session is one container's side of the API.
type Session interface {
	// Next waits for the next event, or returns ctx's error.
	Next(ctx context.Context) (*Event, error)
	// Respond completes the request with the function's result.
	Respond(requestID string, body []byte) error
	// Fail completes the request with a function error. errorType is the
	// Lambda-Runtime-Function-Error-Type header, "" when absent; body is
	// the error document as the runtime sent it.
	Fail(requestID, errorType string, body []byte) error
	// InitFail reports that the runtime could not initialize.
	InitFail(errorType string, body []byte)
}

// Server routes Runtime API requests to the registered sessions.
type Server struct {
	sessions map[string]Session
	mu       sync.Mutex
}

// NewServer returns a server with no sessions.
func NewServer() *Server {
	return &Server{sessions: map[string]Session{}}
}

// Register serves s under token until Unregister.
func (s *Server) Register(token string, sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = sess
}

// Unregister stops serving token.
func (s *Server) Unregister(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *Server) session(token string) Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[token]
}

// statusError is the body the API answers an error with.
type statusError struct {
	ErrorMessage string `json:"errorMessage"`
	ErrorType    string `json:"errorType"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, errType, msg string) {
	writeJSON(w, status, statusError{ErrorMessage: msg, ErrorType: errType})
}

func accepted(w http.ResponseWriter) {
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "OK"})
}

// ServeHTTP serves /{token}/2018-06-01/runtime/....
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	sess := s.session(token)
	if sess == nil {
		writeError(w, http.StatusForbidden, "Runtime.Forbidden",
			"This path is not a runtime's.")
		return
	}
	rest, ok := strings.CutPrefix(rest, Version+"/runtime/")
	if !ok {
		notFound(w)
		return
	}
	switch {
	case rest == "invocation/next" && r.Method == http.MethodGet:
		s.next(w, r, sess)
	case rest == "init/error" && r.Method == http.MethodPost:
		s.initFail(w, r, sess)
	case strings.HasPrefix(rest, "invocation/") && r.Method == http.MethodPost:
		s.complete(w, r, sess, strings.TrimPrefix(rest, "invocation/"))
	default:
		notFound(w)
	}
}

func (s *Server) initFail(w http.ResponseWriter, r *http.Request, sess Session) {
	bodyDeadline(w)
	body, _ := readLimited(r.Body, maxErrorSize)
	sess.InitFail(r.Header.Get(headerErrorType), body)
	accepted(w)
}

// complete serves invocation/{id}/response and invocation/{id}/error.
func (s *Server) complete(w http.ResponseWriter, r *http.Request, sess Session, rest string) {
	id, action, _ := strings.Cut(rest, "/")
	switch action {
	case "response":
		s.respond(w, r, sess, id)
	case "error":
		s.fail(w, r, sess, id)
	default:
		notFound(w)
	}
}

func notFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "Runtime.NotFound", "No such Runtime API path.")
}

func (s *Server) next(w http.ResponseWriter, r *http.Request, sess Session) {
	ev, err := sess.Next(r.Context())
	if err != nil {
		// The container is going away, or the runtime hung up.
		writeError(w, http.StatusInternalServerError, "Runtime.Unavailable", err.Error())
		return
	}
	h := w.Header()
	h.Set(headerRequestID, ev.RequestID)
	h.Set(headerDeadline, strconv.FormatInt(ev.Deadline.UnixMilli(), 10))
	h.Set(headerFunctionARN, ev.FunctionARN)
	h.Set(headerTraceID, ev.TraceID)
	if ev.ClientContext != "" {
		h.Set(headerClientContext, ev.ClientContext)
	}
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ev.Payload)
}

// readLimited reads up to limit bytes of body, and reports whether there
// was more.
func readLimited(body io.Reader, limit int64) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return b, false
	}
	if int64(len(b)) > limit {
		return b[:limit], true
	}
	return b, false
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request, sess Session, id string) {
	bodyDeadline(w)
	body, tooLarge := readLimited(r.Body, MaxResponseSize)
	if tooLarge {
		msg := "Response payload size exceeded maximum allowed payload size (" +
			strconv.Itoa(MaxResponseSize) + " bytes)."
		doc, _ := json.Marshal(statusError{
			ErrorMessage: msg, ErrorType: "Function.ResponseSizeTooLarge",
		})
		if err := sess.Fail(id, "Function.ResponseSizeTooLarge", doc); err != nil {
			invalidRequest(w)
			return
		}
		writeError(w, http.StatusRequestEntityTooLarge, "RequestEntityTooLarge", msg)
		return
	}
	// aws-lambda-go reports a failure while it streamed the response in
	// trailers, which net/http fills in once the body is read.
	if errType := r.Trailer.Get(headerErrorType); errType != "" {
		doc, _ := base64.StdEncoding.DecodeString(r.Trailer.Get(headerErrorBody))
		if err := sess.Fail(id, errType, doc); err != nil {
			invalidRequest(w)
			return
		}
		accepted(w)
		return
	}
	if err := sess.Respond(id, body); err != nil {
		invalidRequest(w)
		return
	}
	accepted(w)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, sess Session, id string) {
	bodyDeadline(w)
	body, _ := readLimited(r.Body, maxErrorSize)
	if err := sess.Fail(id, r.Header.Get(headerErrorType), body); err != nil {
		invalidRequest(w)
		return
	}
	accepted(w)
}

func invalidRequest(w http.ResponseWriter) {
	writeError(w, http.StatusBadRequest, "InvalidRequestID", "Invalid request ID")
}
