package lambda

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/httpx"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/lambdaapi"
	"tule.dev/functions/internal/runner"
)

// The payload limits of the Invoke API reference: 6 MB for a synchronous
// invocation, 1 MB for an asynchronous one.
const (
	MaxSyncPayload  = 6 * 1024 * 1024
	MaxAsyncPayload = 1024 * 1024
)

// maxClientContext is how much base64 ClientContext may carry.
const maxClientContext = 3583

// tailSize is how much of the log LogType Tail returns: the last 4 KB.
const tailSize = 4096

// The invocation types.
const (
	invokeSync   = "RequestResponse"
	invokeAsync  = "Event"
	invokeDryRun = "DryRun"
)

func (m *Module) invoke(ctx gas.Context) error {
	name, err := m.pathQualifiedFunction(ctx)
	if err != nil {
		return err
	}
	r := ctx.Request()
	invType, tail, err := invokeHeaders(r.Header)
	if err != nil {
		return err
	}
	payload, err := readPayload(r, invType)
	if err != nil {
		return err
	}
	clientContext, err := decodeClientContext(r.Header.Get("X-Amz-Client-Context"))
	if err != nil {
		return err
	}
	fn, err := m.authorizedInvocable(ctx, name)
	if err != nil {
		return err
	}
	w := ctx.ResponseWriter()
	w.Header().Set("X-Amz-Executed-Version", "$LATEST")
	switch invType {
	case invokeDryRun:
		return lambdaapi.NoContent(ctx)
	case invokeAsync:
		w.Header().
			Set(lambdaapi.RequestIDHeader, m.engine.InvokeAsync(fn, contracts.SourceAsync, payload))
		w.WriteHeader(http.StatusAccepted)
		return nil
	}
	requestID := ids.UUID()
	res, err := m.engine.Invoke(ctx, fn, contracts.SourceInvoke, requestID, clientContext,
		payload)
	if err != nil {
		return err
	}
	writeResult(ctx, requestID, res, tail)
	return nil
}

// authorizedInvocable authorizes the invocation of the function name and
// returns it, under the name's lock, so the function invoked is the one
// evaluated. The payload is read before, so a slow body holds no lock; the
// invocation runs after, on the function returned.
func (m *Module) authorizedInvocable(ctx gas.Context, name string) (*contracts.Function, error) {
	defer m.names.read(name)()
	if err := m.authorizeQualifiedFunction(ctx, "Invoke", name); err != nil {
		return nil, err
	}
	return m.engine.Invocable(ctx, name)
}

// invokeHeaders reads the invocation type, RequestResponse by default, and
// whether the log is asked for.
func invokeHeaders(h http.Header) (string, bool, error) {
	invType := h.Get("X-Amz-Invocation-Type")
	if invType == "" {
		invType = invokeSync
	}
	if invType != invokeSync && invType != invokeAsync && invType != invokeDryRun {
		return "", false, lambdaapi.ErrValidation(fmt.Sprintf("1 validation error detected: "+
			"Value '%s' at 'invocationType' failed to satisfy constraint: Member must satisfy "+
			"enum value set: [Event, RequestResponse, DryRun]", invType))
	}
	logType := h.Get("X-Amz-Log-Type")
	if logType != "" && logType != "None" && logType != "Tail" {
		return "", false, lambdaapi.ErrValidation(fmt.Sprintf("1 validation error detected: "+
			"Value '%s' at 'logType' failed to satisfy constraint: Member must satisfy enum "+
			"value set: [None, Tail]", logType))
	}
	return invType, logType == "Tail", nil
}

// writeResult answers a synchronous invocation with the function's result
// or error document, X-Amz-Function-Error when it failed, and the last 4 KB
// of its log when tail is set.
func writeResult(ctx gas.Context, requestID string, res *runner.Result, tail bool) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set(lambdaapi.RequestIDHeader, requestID)
	h.Set("Content-Type", lambdaapi.ContentType)
	h.Set("Content-Length", strconv.Itoa(len(res.Payload)))
	if res.FunctionError != "" {
		h.Set("X-Amz-Function-Error", res.FunctionError)
	}
	if tail {
		log := res.Log
		if len(log) > tailSize {
			log = log[len(log)-tailSize:]
		}
		h.Set("X-Amz-Log-Result", base64.StdEncoding.EncodeToString([]byte(log)))
	}
	w.WriteHeader(http.StatusOK)
	if _, wErr := w.Write(res.Payload); wErr != nil {
		httpx.Logger(ctx).Warn("failed to write an invocation's result").
			Err("error", wErr).Send()
	}
}

// readPayload reads the invocation's payload, which must be JSON and
// within its invocation type's limit. An empty payload is the empty
// object.
func readPayload(r *http.Request, invType string) ([]byte, error) {
	limit := int64(MaxSyncPayload)
	if invType == invokeAsync {
		limit = MaxAsyncPayload
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, lambdaapi.NewError(http.StatusBadRequest,
			lambdaapi.CodeInvalidRequestContent, "Could not read the request body.")
	}
	if int64(len(payload)) > limit {
		return nil, lambdaapi.NewError(http.StatusRequestEntityTooLarge,
			lambdaapi.CodeRequestTooLarge, fmt.Sprintf(
				"Request must be smaller than %d bytes for the Invoke operation", limit))
	}
	if len(payload) == 0 {
		return []byte("{}"), nil
	}
	if !json.Valid(payload) {
		return nil, lambdaapi.NewError(http.StatusBadRequest, lambdaapi.CodeInvalidRequestContent,
			"Could not parse request body into json: the payload is not valid JSON.")
	}
	return payload, nil
}

// decodeClientContext decodes ClientContext, base64 JSON, into the JSON
// the runtime receives in Lambda-Runtime-Client-Context.
func decodeClientContext(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if len(v) > maxClientContext {
		return "", lambdaapi.ErrInvalidParameter(fmt.Sprintf(
			"Client context must be at most %d bytes of base64.", maxClientContext))
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || !json.Valid(b) {
		return "", lambdaapi.NewError(http.StatusBadRequest, lambdaapi.CodeInvalidRequestContent,
			"Client context must be a valid Base64-encoded JSON object.")
	}
	return string(b), nil
}
