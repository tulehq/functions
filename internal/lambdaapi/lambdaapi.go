// Package lambdaapi is the Lambda wire layer: the restJson1 envelope the SDK
// speaks, the error documents, and the request and response shapes of the
// operations in scope, as the SDK model names their members.
package lambdaapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/httpx"
)

// ContentType is the media type of every JSON body.
const ContentType = "application/json"

// The headers AWS reports a request's ID and an error's type in.
const (
	RequestIDHeader = "X-Amzn-Requestid"
	ErrorTypeHeader = "X-Amzn-Errortype"
)

// Error is a Lambda error. It is sent as X-Amzn-ErrorType and a body with
// Type, User for a client error and Service for a server error, and the
// message under the member name the SDK model gives the error: "message"
// for most, "Message" for ServiceException, ResourceNotFoundException and
// ResourceInUseException.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

// NewError builds an error with the given status and code.
func NewError(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// The Lambda errors this service raises, with the statuses the SDK model
// gives them, and the common errors beside them.
const (
	CodeInvalidParameterValue = "InvalidParameterValueException"
	CodeValidation            = "ValidationException"
	CodeResourceNotFound      = "ResourceNotFoundException"
	CodeResourceConflict      = "ResourceConflictException"
	CodeResourceInUse         = "ResourceInUseException"
	CodePreconditionFailed    = "PreconditionFailedException"
	CodeInvalidRequestContent = "InvalidRequestContentException"
	CodeRequestTooLarge       = "RequestTooLargeException"
	CodeTooManyRequests       = "TooManyRequestsException"
	CodeService               = "ServiceException"
	CodeUnknownOperation      = "UnknownOperationException"
	CodeMissingAuthToken      = "MissingAuthenticationTokenException"
	CodeIncompleteSignature   = "IncompleteSignature"
	CodeInvalidSignature      = "InvalidSignatureException"
	CodeUnrecognizedClient    = "UnrecognizedClientException"
	CodeExpiredToken          = "ExpiredTokenException"
)

// capitalMessage are the errors whose model member is "Message".
var capitalMessage = map[string]bool{
	CodeService:          true,
	CodeResourceNotFound: true,
	CodeResourceInUse:    true,
}

// ErrInvalidParameter is InvalidParameterValueException, 400.
func ErrInvalidParameter(msg string) *Error {
	return NewError(http.StatusBadRequest, CodeInvalidParameterValue, msg)
}

// ErrValidation is ValidationException, 400, which Lambda answers a value
// outside the model's constraints with.
func ErrValidation(msg string) *Error {
	return NewError(http.StatusBadRequest, CodeValidation, msg)
}

// ErrNotFound is ResourceNotFoundException, 404.
func ErrNotFound(msg string) *Error {
	return NewError(http.StatusNotFound, CodeResourceNotFound, msg)
}

// ErrConflict is ResourceConflictException, 409.
func ErrConflict(msg string) *Error {
	return NewError(http.StatusConflict, CodeResourceConflict, msg)
}

// ErrService is ServiceException, 500, which every unrecognized failure
// becomes.
func ErrService() *Error {
	return NewError(http.StatusInternalServerError, CodeService,
		"The service encountered an internal error.")
}

// ErrUnknownOperation answers a path and method no operation is routed at.
func ErrUnknownOperation() *Error {
	return NewError(http.StatusNotFound, CodeUnknownOperation,
		"The requested operation is not recognized by this service.")
}

// ToError maps err to an Error, logging it when it is a server fault.
func ToError(ctx context.Context, err error) *Error {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		cp := *apiErr
		return &cp
	}
	if errors.Is(err, contracts.ErrInvalidToken) {
		return ErrInvalidParameter("The pagination marker is not valid.")
	}
	httpx.Logger(ctx).Error("request failed").Err("error", err).Send()
	return ErrService()
}

// WriteError renders err as an error response.
func WriteError(ctx gas.Context, err error) error {
	WriteHTTPError(ctx.ResponseWriter(), ctx.Request(), err)
	return nil
}

// WriteHTTPError renders err for plain http.Handler middleware.
func WriteHTTPError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr := ToError(r.Context(), err)
	kind := "User"
	if apiErr.Status >= http.StatusInternalServerError {
		kind = "Service"
	}
	msgKey := "message"
	if capitalMessage[apiErr.Code] {
		msgKey = "Message"
	}
	body, _ := json.Marshal(map[string]string{"Type": kind, msgKey: apiErr.Message})
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set(ErrorTypeHeader, apiErr.Code)
	SetRequestID(w, r)
	w.WriteHeader(apiErr.Status)
	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(r.Context()).Warn("failed to write error response").Err("error", wErr).Send()
	}
}

// SetRequestID reports the request's ID, unless a handler already set one.
func SetRequestID(w http.ResponseWriter, r *http.Request) {
	if w.Header().Get(RequestIDHeader) != "" {
		return
	}
	if id := httpx.RequestIDOf(r.Context()); id != "" {
		w.Header().Set(RequestIDHeader, id)
	}
}

// Write sends v as a JSON body with the given status.
func Write(ctx gas.Context, status int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return WriteError(ctx, err)
	}
	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", ContentType)
	SetRequestID(w, ctx.Request())
	w.WriteHeader(status)
	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(ctx).Warn("failed to write response").Err("error", wErr).Send()
	}
	return nil
}

// NoContent answers 204 with no body.
func NoContent(ctx gas.Context) error {
	SetRequestID(ctx.ResponseWriter(), ctx.Request())
	ctx.ResponseWriter().WriteHeader(http.StatusNoContent)
	return nil
}

// Decode reads a JSON request body into T. An empty body decodes to the
// zero value; unknown members are ignored, as restJson1 expects.
func Decode[T any](ctx gas.Context) (T, error) {
	var body T
	err := json.NewDecoder(ctx.Request().Body).Decode(&body)
	if err != nil && !errors.Is(err, io.EOF) {
		return body, NewError(http.StatusBadRequest, CodeInvalidRequestContent,
			"Could not parse request body into json: "+err.Error())
	}
	return body, nil
}

// PathParam returns a path label, decoded. The router matches the raw path
// when the request has one, as it has whenever a label holds an escaped
// character such as the colons of an ARN, and hands the label over still
// escaped.
func PathParam(ctx gas.Context, name string) (string, error) {
	v := ctx.Param(name)
	if ctx.Request().URL.RawPath == "" {
		return v, nil
	}
	d, err := url.PathUnescape(v)
	if err != nil {
		return "", ErrInvalidParameter(fmt.Sprintf(
			"The %s in the path is not percent-encoded properly.", name))
	}
	return d, nil
}
