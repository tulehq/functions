// Package history serves the retrieval API under /_functions: the
// invocations the service ran, listed, filtered, read back whole and reset.
// It is not an AWS API; its errors are X-Amzn-ErrorType and a body of code
// and message.
package history

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/httpx"
	"tule.dev/functions/internal/lambdaapi"
)

const moduleName = "tule/modules/history"

// Prefix is where the retrieval API lives.
const Prefix = "/_functions/"

// The page sizes of GET /_functions/invocations.
const (
	defaultLimit = 20
	maxLimit     = 100
)

// Module registers the retrieval routes and serves them.
type Module struct {
	router *gas.Router
	store  contracts.Store
}

// NewModule returns a Module serving from store.
func NewModule(router *gas.Router, store contracts.Store) *Module {
	return &Module{router: router, store: store}
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// Init registers the module's routes.
func (m *Module) Init(context.Context) error {
	routes := []struct {
		h      func(gas.Context) error
		method string
		path   string
	}{
		{m.list, http.MethodGet, "/_functions/invocations"},
		{m.reset, http.MethodDelete, "/_functions/invocations"},
		{m.get, http.MethodGet, "/_functions/invocations/{requestId}"},
	}
	for _, r := range routes {
		h := r.h
		m.router.Handle(m, r.method, r.path, func(ctx gas.Context) error {
			if err := h(ctx); err != nil {
				WriteError(ctx.ResponseWriter(), ctx.Request(), err)
			}
			return nil
		})
	}
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

// errorBody is the retrieval API's error document.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteError renders err as the retrieval API's error: the Lambda error it
// maps to, as X-Amzn-ErrorType and a body of code and message.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr := lambdaapi.ToError(r.Context(), err)
	body, _ := json.Marshal(errorBody{Code: apiErr.Code, Message: apiErr.Message})
	w.Header().Set("Content-Type", lambdaapi.ContentType)
	w.Header().Set(lambdaapi.ErrorTypeHeader, apiErr.Code)
	lambdaapi.SetRequestID(w, r)
	w.WriteHeader(apiErr.Status)
	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(r.Context()).Warn("failed to write error response").Err("error", wErr).Send()
	}
}

// Summary is a listed invocation.
type Summary struct {
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

// Detail is an invocation read back whole: its summary, the payload it was
// invoked with, the result or error document it answered, and its log. The
// payload and result are text, as the function sent them.
type Detail struct {
	Payload string `json:"payload"`
	Result  string `json:"result"`
	Log     string `json:"log"`
	Summary
}

// Page is one page of a listing; NextCursor is absent on the last.
type Page struct {
	NextCursor string    `json:"nextCursor,omitempty"`
	Items      []Summary `json:"items"`
}

// timeFormat is how times are written: RFC 3339 in UTC, to the millisecond.
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

func summaryOf(inv *contracts.Invocation) Summary {
	return Summary{
		RequestID:    inv.RequestID,
		Function:     inv.Function,
		Time:         inv.Time.UTC().Format(timeFormat),
		Source:       inv.Source,
		Status:       inv.Status,
		ErrorType:    inv.ErrorType,
		ErrorMessage: inv.ErrorMessage,
		Duration:     inv.Duration,
		Attempts:     inv.Attempts,
	}
}

func badRequest(msg string) error {
	return lambdaapi.ErrInvalidParameter(msg)
}

func (m *Module) list(ctx gas.Context) error {
	q := ctx.Request().URL.Query()
	f, page, err := filterOf(q)
	if err != nil {
		return err
	}
	out, err := m.store.ListInvocations(ctx, f, page)
	if errors.Is(err, contracts.ErrInvalidToken) {
		return badRequest("The cursor is not valid.")
	}
	if err != nil {
		return err
	}
	resp := Page{Items: make([]Summary, 0, len(out.Items)), NextCursor: out.NextToken}
	for i := range out.Items {
		resp.Items = append(resp.Items, summaryOf(&out.Items[i]))
	}
	return lambdaapi.Write(ctx, http.StatusOK, resp)
}

// The values the status and source filters take.
var (
	statuses = []string{contracts.StatusSucceeded, contracts.StatusFailed, contracts.StatusTimedOut}
	sources  = []string{contracts.SourceInvoke, contracts.SourceAsync, contracts.SourceMapping}
)

func oneOf(name, v string, allowed []string) error {
	if v == "" {
		return nil
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return badRequest(fmt.Sprintf("%s must be one of %s.", name, strings.Join(allowed, ", ")))
}

// filterOf reads a listing's filters and page from the query.
func filterOf(q url.Values) (contracts.InvocationFilter, contracts.PageInput, error) {
	f := contracts.InvocationFilter{
		Function: q.Get("function"),
		Status:   q.Get("status"),
		Source:   q.Get("source"),
	}
	page := contracts.PageInput{Token: q.Get("cursor"), Size: defaultLimit}
	if err := oneOf("status", f.Status, statuses); err != nil {
		return f, page, err
	}
	if err := oneOf("source", f.Source, sources); err != nil {
		return f, page, err
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLimit {
			return f, page, badRequest(fmt.Sprintf("limit must be a number from 1 to %d.",
				maxLimit))
		}
		page.Size = n
	}
	var err error
	if f.Since, err = timeParam(q.Get("since"), "since"); err != nil {
		return f, page, err
	}
	f.Until, err = timeParam(q.Get("until"), "until")
	return f, page, err
}

func timeParam(v, name string) (*time.Time, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, badRequest(fmt.Sprintf("%s must be an RFC 3339 time.", name))
	}
	return &t, nil
}

func (m *Module) get(ctx gas.Context) error {
	id, err := lambdaapi.PathParam(ctx, "requestId")
	if err != nil {
		return err
	}
	inv, err := m.store.GetInvocation(ctx, id)
	if errors.Is(err, contracts.ErrInvocationNotFound) {
		return lambdaapi.ErrNotFound("No invocation has the request ID " + id + ".")
	}
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusOK, Detail{
		Summary: summaryOf(inv),
		Payload: string(inv.Payload),
		Result:  string(inv.Result),
		Log:     inv.Log,
	})
}

func (m *Module) reset(ctx gas.Context) error {
	if err := m.store.DeleteInvocations(ctx); err != nil {
		return err
	}
	return lambdaapi.NoContent(ctx)
}
