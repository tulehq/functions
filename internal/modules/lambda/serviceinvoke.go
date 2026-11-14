package lambda

// The service-invoke endpoint, through which a Tule service invokes a
// function as an AWS service principal, as Secrets Manager invokes a
// rotation function as secretsmanager.amazonaws.com. It is not an AWS API;
// tule.dev/functions/serviceinvoke is its client and holds its wire types.
//
// The app verifies every call to it, before this module reads anything,
// against the root key alone, signed for lambda, and answers a failure with
// WriteServiceInvokeError.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gasmod/gas"
	"tule.dev/identity/servicerole"
	"tule.dev/sigv4"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/httpx"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/lambdaapi"
	"tule.dev/functions/internal/runner"
	"tule.dev/functions/internal/servicewire"
	"tule.dev/functions/serviceinvoke"
)

// refusal is a call the endpoint refuses, with the status and code of its
// answer.
type refusal struct {
	code    string
	message string
	status  int
}

func (r *refusal) Error() string { return r.code + ": " + r.message }

func invalidService(msg string) *refusal {
	return &refusal{
		status: http.StatusBadRequest, code: serviceinvoke.CodeInvalidRequest, message: msg,
	}
}

// serviceInvoke runs the invocation the request asks for, as Invoke of the
// same type runs it, when the function policy allows the service principal
// lambda:InvokeFunction on the function, qualified as Invoke evaluates it.
// Only the function policy is evaluated, as a service principal has no
// identity policies. The invocation is recorded with source service.
func (m *Module) serviceInvoke(ctx gas.Context) error {
	var req serviceinvoke.Request
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return writeServiceRefusal(ctx, invalidService(
			"The body is not a JSON service-invoke request."))
	}
	if r := checkServiceRequest(&req); r != nil {
		return writeServiceRefusal(ctx, r)
	}
	name, err := m.resolveName(req.FunctionName)
	if err != nil {
		return writeServiceFailure(ctx, err)
	}
	fn, err := m.serviceInvocable(ctx, &req, name)
	if err != nil {
		return writeServiceFailure(ctx, err)
	}
	// The payload is the bytes received, as Invoke passes them on.
	payload := []byte(req.Payload)
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	// The invocation's request ID is the response's, as Invoke answers it,
	// so the retrieval API finds the invocation under it.
	h := ctx.ResponseWriter().Header()
	if req.InvocationType == serviceinvoke.InvocationEvent {
		h.Set(lambdaapi.RequestIDHeader,
			m.engine.InvokeAsync(fn, contracts.SourceService, payload))
		return writeService(ctx, http.StatusAccepted,
			serviceinvoke.Response{StatusCode: http.StatusAccepted}, nil)
	}
	requestID := ids.UUID()
	res, err := m.engine.Invoke(ctx, fn, contracts.SourceService, requestID, "", payload)
	if err != nil {
		return writeServiceFailure(ctx, err)
	}
	h.Set(lambdaapi.RequestIDHeader, requestID)
	return writeServiceResult(ctx, res)
}

// writeServiceResult answers a RequestResponse invocation with its result
// as the Payload, the bytes the function sent, or with no Payload when it
// sent none, as Invoke answers an empty 200. A result that is not JSON
// cannot be the Payload, and is answered as InvalidFunctionResponse; the
// invocation ran, and is in the history.
func writeServiceResult(ctx gas.Context, res *runner.Result) error {
	status, v, payload := serviceResult(res)
	return writeService(ctx, status, v, payload)
}

// serviceResult is the status, the document and the Payload bytes a
// RequestResponse invocation that ended with res is answered with.
func serviceResult(res *runner.Result) (int, any, []byte) {
	if len(res.Payload) > 0 && !json.Valid(res.Payload) {
		return http.StatusBadGateway, serviceinvoke.ErrorResponse{
			Code:    serviceinvoke.CodeInvalidFunctionResponse,
			Message: "The function's result is not JSON.",
		}, nil
	}
	return http.StatusOK, serviceinvoke.Response{
		StatusCode:      http.StatusOK,
		ExecutedVersion: contracts.LatestVersion,
		FunctionError:   res.FunctionError,
	}, res.Payload
}

// checkServiceRequest checks the request's fields: the service principal,
// SourceArn and SourceAccount as identity's assume-role endpoint checks
// them, and the invocation type and payload (checkPayload).
func checkServiceRequest(req *serviceinvoke.Request) *refusal {
	if !servicerole.IsServicePrincipal(req.ServicePrincipal) {
		return invalidService("ServicePrincipal " + strconv.Quote(req.ServicePrincipal) +
			" is not a service principal such as secretsmanager.amazonaws.com.")
	}
	if req.SourceArn != "" && !servicerole.IsSourceArn(req.SourceArn) {
		return invalidService("SourceArn " + strconv.Quote(req.SourceArn) + " is not an ARN.")
	}
	// An ARN may be 2048 characters, and a condition value is evaluated up
	// to the authorizer's cap.
	if len(req.SourceArn) > authz.MaxValueLength {
		return invalidService(fmt.Sprintf("SourceArn is %d characters; it must be at most %d.",
			len(req.SourceArn), authz.MaxValueLength))
	}
	if req.SourceAccount != "" && !servicerole.IsAccountID(req.SourceAccount) {
		return invalidService("SourceAccount " + strconv.Quote(req.SourceAccount) +
			" is not a 12-digit account ID.")
	}
	return checkPayload(req)
}

// checkPayload checks the invocation type, setting RequestResponse when it
// is empty, and holds the payload to Invoke's limit for the type.
func checkPayload(req *serviceinvoke.Request) *refusal {
	limit := MaxSyncPayload
	switch req.InvocationType {
	case "":
		req.InvocationType = serviceinvoke.InvocationRequestResponse
	case serviceinvoke.InvocationRequestResponse:
	case serviceinvoke.InvocationEvent:
		limit = MaxAsyncPayload
	default:
		return invalidService("InvocationType " + strconv.Quote(req.InvocationType) +
			" is not RequestResponse or Event.")
	}
	if len(req.Payload) > limit {
		return &refusal{
			status: http.StatusRequestEntityTooLarge, code: serviceinvoke.CodeRequestTooLarge,
			message: fmt.Sprintf("The payload must be smaller than %d bytes for a %s "+
				"invocation.", limit, req.InvocationType),
		}
	}
	return nil
}

// serviceInvocable returns the function name when the function policy
// allows the service to invoke it and it can be invoked, under the name's
// lock, so the function invoked is the one evaluated, as Invoke holds it.
func (m *Module) serviceInvocable(
	ctx gas.Context,
	req *serviceinvoke.Request,
	name string,
) (*contracts.Function, error) {
	defer m.names.read(name)()
	fn, err := m.store.GetFunction(ctx, name)
	if errors.Is(err, contracts.ErrFunctionNotFound) {
		return nil, &refusal{
			status: http.StatusNotFound, code: serviceinvoke.CodeResourceNotFound,
			message: "Function not found: " + m.settings.FunctionARN(name),
		}
	}
	if err != nil {
		return nil, err
	}
	tags, err := resourceTags(fn.Tags)
	if err != nil {
		return nil, err
	}
	resource := m.settings.FunctionARN(name)
	if ref, _ := parseFunctionRef(req.FunctionName); ref.qualifier != "" {
		resource += ":" + ref.qualifier
	}
	k := keys{}
	// The resource the service acts for, as a service supplies it.
	if req.SourceArn != "" {
		k["aws:SourceArn"] = []string{req.SourceArn}
	}
	if req.SourceAccount != "" {
		k["aws:SourceAccount"] = []string{req.SourceAccount}
	}
	areq := withPolicy(request("Invoke", resource, merge(tags, k)), fn.Policy)
	err = m.authz.AuthorizeService(ctx.Request(), req.ServicePrincipal, &areq)
	var denied *authz.Denied
	var tooLarge *authz.TooLarge
	switch {
	case errors.As(err, &denied):
		return nil, &refusal{
			status: http.StatusForbidden, code: serviceinvoke.CodeAccessDenied,
			message: denied.Error(),
		}
	case errors.As(err, &tooLarge):
		return nil, invalidService("The function has more tags, or longer ones, than this " +
			"service evaluates policies for.")
	case err != nil:
		return nil, err
	}
	return m.engine.Invocable(ctx, name)
}

// serviceCodes are the endpoint's codes for the Lambda errors the
// resolution of the name and the invocation answer with.
var serviceCodes = map[string]string{
	lambdaapi.CodeResourceNotFound:      serviceinvoke.CodeResourceNotFound,
	lambdaapi.CodeResourceConflict:      serviceinvoke.CodeResourceConflict,
	lambdaapi.CodeValidation:            serviceinvoke.CodeInvalidRequest,
	lambdaapi.CodeInvalidParameterValue: serviceinvoke.CodeInvalidRequest,
	lambdaapi.CodeTooManyRequests:       serviceinvoke.CodeTooManyRequests,
}

// writeServiceFailure answers a refusal with its code, a Lambda error the
// endpoint has a code for with that code and the error's status and
// message, and any other failure as internal.
func writeServiceFailure(ctx gas.Context, err error) error {
	var r *refusal
	if errors.As(err, &r) {
		return writeServiceRefusal(ctx, r)
	}
	var apiErr *lambdaapi.Error
	if errors.As(err, &apiErr) {
		if code, ok := serviceCodes[apiErr.Code]; ok {
			return writeServiceRefusal(ctx, &refusal{
				status: apiErr.Status, code: code, message: apiErr.Message,
			})
		}
	}
	httpx.Logger(ctx).Error("service invoke failed").Err("error", err).Send()
	return writeService(ctx, http.StatusInternalServerError, serviceinvoke.ErrorResponse{
		Code: codeInternalFailure, Message: "The function could not be invoked.",
	}, nil)
}

// codeInternalFailure is the endpoint's code for a failure of the service,
// identity's internal endpoints' too.
const codeInternalFailure = "InternalFailure"

func writeServiceRefusal(ctx gas.Context, r *refusal) error {
	return writeService(ctx, r.status, serviceinvoke.ErrorResponse{
		Code: r.code, Message: r.message,
	}, nil)
}

// writeService answers v as JSON, with payload, when it is not empty, as
// its Payload member, byte for byte.
func writeService(ctx gas.Context, status int, v any, payload []byte) error {
	body, err := servicewire.Encode(v, payload)
	if err != nil {
		return fmt.Errorf("encode the response: %w", err)
	}
	writeServiceBody(ctx.ResponseWriter(), ctx.Request(), status, body)
	return nil
}

func writeServiceBody(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	lambdaapi.SetRequestID(w, r)
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		httpx.Logger(r.Context()).Warn("failed to write response").Err("error", err).Send()
	}
}

// WriteServiceInvokeError answers a call to the service-invoke endpoint
// that failed verification, as identity's internal endpoints answer one:
// 403 with the sigv4 Kind as the code and the verifier's message, and a
// failed key lookup as a 500 InternalFailure, logged. A body over the
// verifier's bound is 413 RequestTooLarge, the endpoint's own refusal of a
// payload over its limit.
func WriteServiceInvokeError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, msg := http.StatusInternalServerError, codeInternalFailure,
		"The request could not be served."
	var sigErr *sigv4.Error
	switch {
	case errors.As(err, &sigErr) && sigErr.Kind == sigv4.KindBodyTooLarge:
		status, code, msg = http.StatusRequestEntityTooLarge, serviceinvoke.CodeRequestTooLarge,
			sigErr.Message
	case errors.As(err, &sigErr) && sigErr.Kind != sigv4.KindKeyLookupFailed:
		status, code, msg = http.StatusForbidden, sigErr.Kind.String(), sigErr.Message
	default:
		httpx.Logger(r.Context()).Error("request failed").Err("error", err).Send()
	}
	body, mErr := json.Marshal(serviceinvoke.ErrorResponse{Code: code, Message: msg})
	if mErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeServiceBody(w, r, status, body)
}
