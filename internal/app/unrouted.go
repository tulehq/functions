package app

import (
	"net/http"
	"slices"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/lambdaapi"
)

// installUnrouted makes the router answer the requests no route serves: a
// path no route matches with UnknownOperationException, 404, and a
// method the path is not routed for with an empty 405, as chi sends it. Gas
// answers both with an RFC 9457 problem document, whose "code" the SDKs read
// as the error code.
//
// It installs a middleware, so it is called after the others, to sit closest
// to the routes.
func installUnrouted(r *gas.Router) {
	r.NotFound(nil, func(w http.ResponseWriter, req *http.Request) {
		writeError(w, req, lambdaapi.ErrUnknownOperation())
	})
	r.UseMiddlewareFunc(nil, emptyMethodNotAllowed)
}

// chiMethods are the methods chi routes. chi answers any other method with a
// 405 that has no Allow header, as no route can serve it.
var chiMethods = []string{
	http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
	http.MethodOptions, http.MethodPatch, http.MethodPost, http.MethodPut,
	http.MethodTrace,
}

// emptyMethodNotAllowed strips the problem document from the router's 405,
// leaving its status and Allow header, as chi sends them. No handler or
// middleware of this service answers 405, so the status alone marks the
// router's answer.
func emptyMethodNotAllowed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&methodNotAllowedWriter{
			ResponseWriter: w,
			knownMethod:    slices.Contains(chiMethods, r.Method),
		}, r)
	})
}

// methodNotAllowedWriter drops the body and the problem headers of a 405.
type methodNotAllowedWriter struct {
	http.ResponseWriter
	knownMethod bool
	discard     bool
}

func (w *methodNotAllowedWriter) WriteHeader(code int) {
	if code == http.StatusMethodNotAllowed {
		w.discard = true
		h := w.Header()
		h.Del("Content-Type")
		h.Del("Cache-Control")
		if !w.knownMethod {
			h.Del("Allow")
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *methodNotAllowedWriter) Write(b []byte) (int, error) {
	if w.discard {
		return len(b), nil
	}
	//nolint:wrapcheck // the writer's error is the caller's, as from any ResponseWriter
	return w.ResponseWriter.Write(b)
}

// Flush flushes the writer underneath when it can, as gas's own writer does,
// so a handler behind this middleware keeps its http.Flusher. A dropped 405
// body has nothing to flush.
func (w *methodNotAllowedWriter) Flush() {
	if w.discard {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController and gas reach the writer underneath.
func (w *methodNotAllowedWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
