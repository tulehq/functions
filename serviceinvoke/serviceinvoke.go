// Package serviceinvoke is the client of the functions service's
// service-invoke endpoint, through which a Tule service invokes a function
// as an AWS service principal, as Secrets Manager invokes a rotation
// function as secretsmanager.amazonaws.com: for a function whose function
// policy allows that service lambda:InvokeFunction.
//
// The endpoint is not an AWS API. It is a SigV4-signed POST, with the root
// key for the signing name lambda, of a JSON request to Path. It evaluates
// the function's function policy for the service principal, and no
// identity policies, since a service principal has none, and runs the
// invocation as Invoke runs one of the same type.
package serviceinvoke

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"tule.dev/functions/internal/servicewire"
)

// Path is where the functions service serves the service-invoke endpoint.
const Path = "/_internal/invoke"

// SigningName is the service a call is signed for, Lambda's.
const SigningName = "lambda"

// The invocation types, as Invoke names them.
const (
	InvocationRequestResponse = "RequestResponse"
	InvocationEvent           = "Event"
)

// Request is the body of a call. FunctionName is a function's name, a name
// with a qualifier, or an ARN, as Invoke takes it. ServicePrincipal is the
// service the function is invoked as, such as
// secretsmanager.amazonaws.com. SourceArn and SourceAccount, when set, name
// the resource the service acts for and its account, such as a secret and
// its account, and are supplied to the function policy as aws:SourceArn
// and aws:SourceAccount, as AWS services supply them against the confused
// deputy problem (the IAM User Guide, the confused deputy problem).
// InvocationType is RequestResponse, the default when empty, or Event.
// Payload is the event, any JSON value; left out, it is {}.
type Request struct {
	FunctionName     string          `json:"FunctionName"`
	ServicePrincipal string          `json:"ServicePrincipal"`
	SourceArn        string          `json:"SourceArn,omitempty"`
	SourceAccount    string          `json:"SourceAccount,omitempty"`
	InvocationType   string          `json:"InvocationType,omitempty"`
	Payload          json.RawMessage `json:"Payload,omitempty"`
}

// Response is the body of a successful call: StatusCode 200 with the
// function's result for a RequestResponse invocation, FunctionError
// Unhandled and the error document as Payload when the function failed;
// StatusCode 202 alone for an Event invocation, queued.
type Response struct {
	ExecutedVersion string          `json:"ExecutedVersion,omitempty"`
	FunctionError   string          `json:"FunctionError,omitempty"`
	Payload         json.RawMessage `json:"Payload,omitempty"`
	StatusCode      int             `json:"StatusCode"`
}

// ErrorResponse is the body of a failed call.
type ErrorResponse struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// The codes a call fails with. The endpoint's own authentication failures
// are 403 with the sigv4 Kind as the code, and a failure of the service is
// 500 InternalFailure.
const (
	// CodeResourceNotFound, 404: no function has the name.
	CodeResourceNotFound = "ResourceNotFound"
	// CodeAccessDenied, 403: the function policy does not allow the
	// service principal lambda:InvokeFunction.
	CodeAccessDenied = "AccessDenied"
	// CodeResourceConflict, 409: the function is not in a state it can be
	// invoked in, pending, updating without a usable image, or failed.
	CodeResourceConflict = "ResourceConflict"
	// CodeInvalidRequest, 400: the body is not a request, or a field is
	// malformed.
	CodeInvalidRequest = "InvalidRequest"
	// CodeRequestTooLarge, 413: the payload is over Invoke's limit for the
	// invocation type, 6 MB for RequestResponse and 1 MB for Event.
	CodeRequestTooLarge = "RequestTooLarge"
	// CodeTooManyRequests, 429: the function is at its cap of containers,
	// as Invoke answers TooManyRequestsException.
	CodeTooManyRequests = "TooManyRequests"
	// CodeInvalidFunctionResponse, 502: the function ran, and its result is
	// not JSON, so it cannot be the response's Payload.
	CodeInvalidFunctionResponse = "InvalidFunctionResponse"
)

// The errors the client returns for the refusals a caller can act on.
var (
	ErrNotFound     = errors.New("serviceinvoke: no such function")
	ErrAccessDenied = errors.New("serviceinvoke: the function policy does not allow the service")
	ErrConflict     = errors.New("serviceinvoke: the function cannot be invoked in its state")
)

// Error is any other failed call.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string {
	return fmt.Sprintf("serviceinvoke: the service-invoke endpoint answered %d %s: %s",
		e.Status, e.Code, e.Message)
}

// Result is what a successful call returns. RequestID is the invocation's
// request ID, from the response's X-Amzn-RequestId as Invoke answers it,
// under which the retrieval API keeps the invocation. For a RequestResponse
// invocation, StatusCode is 200, ExecutedVersion $LATEST, and Payload the
// function's result, or its error document when FunctionError is set, nil
// when the function returned nothing. For an Event invocation, StatusCode
// is 202 and Payload is nil.
type Result struct {
	RequestID       string
	ExecutedVersion string
	FunctionError   string
	Payload         []byte
	StatusCode      int
}

// RequestIDHeader is the response header that carries the invocation's
// request ID, Lambda's.
const RequestIDHeader = "X-Amzn-RequestId"

// Option sets an optional field of an Invoke request. The Payload is
// Invoke's argument: an Invoke whose options set it fails.
type Option func(*Request)

// WithSourceArn supplies arn, the resource the service acts for, as
// aws:SourceArn.
func WithSourceArn(arn string) Option {
	return func(r *Request) { r.SourceArn = arn }
}

// WithSourceAccount supplies account, the account of the resource the
// service acts for, as aws:SourceAccount.
func WithSourceAccount(account string) Option {
	return func(r *Request) { r.SourceAccount = account }
}

// WithEvent invokes the function asynchronously, as an Event invocation,
// rather than waiting for its result.
func WithEvent() Option {
	return func(r *Request) { r.InvocationType = InvocationEvent }
}

// Config configures a Client.
type Config struct {
	// HTTPClient makes the calls. It defaults to http.DefaultClient, which
	// sets no timeout: a RequestResponse call lasts as long as the function
	// runs, up to its timeout of at most 900 seconds.
	HTTPClient *http.Client
	// Endpoint is the functions service's base URL, such as
	// http://localhost:9060.
	Endpoint string
	// Region is the functions service's region, which the calls are signed
	// for, such as us-east-1.
	Region string
	// AccessKeyID and SecretAccessKey are the root key, which the calls are
	// signed with.
	AccessKeyID     string
	SecretAccessKey string
}

// Client calls the service-invoke endpoint. It is safe for concurrent use.
type Client struct {
	http   *http.Client
	signer *v4.Signer
	creds  aws.Credentials
	base   string
	region string
}

// New returns a Client for cfg. It fails when the endpoint is not an
// absolute http or https URL, or the region or the key is not set.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("serviceinvoke: the endpoint %q is not an http or https URL",
			cfg.Endpoint)
	}
	if cfg.Region == "" {
		return nil, errors.New("serviceinvoke: the region is required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("serviceinvoke: the root access key ID and secret are required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{
		http:   hc,
		signer: v4.NewSigner(),
		creds: aws.Credentials{
			AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey,
		},
		base:   strings.TrimSuffix(u.String(), "/"),
		region: cfg.Region,
	}, nil
}

// maxResponseSize bounds what is read of a response: the largest result a
// function may return, the Runtime API's 6291556 bytes, which the endpoint
// sends as it is, and 64 KiB for the members around it.
const maxResponseSize = 6291556 + 64<<10

// Invoke invokes the function functionName names as servicePrincipal with
// payload, a JSON value sent as it is, byte for byte, or {} when payload is
// nil, and the options set. It returns ErrNotFound, ErrAccessDenied or
// ErrConflict for those refusals, and an *Error or a transport error
// otherwise. A function that fails is no error: its Result has
// FunctionError set.
func (c *Client) Invoke(
	ctx context.Context,
	functionName, servicePrincipal string,
	payload []byte,
	opts ...Option,
) (*Result, error) {
	req := Request{
		FunctionName:     functionName,
		ServicePrincipal: servicePrincipal,
	}
	for _, o := range opts {
		o(&req)
	}
	// The payload is Invoke's argument alone, so the body has one.
	if req.Payload != nil {
		return nil, errors.New("serviceinvoke: an option set the Payload; " +
			"pass the payload to Invoke")
	}
	body, err := servicewire.Encode(req, payload)
	if err != nil {
		return nil, fmt.Errorf("serviceinvoke: encode the request: %w", err)
	}
	status, header, raw, err := c.post(ctx, body)
	if err != nil {
		return nil, fmt.Errorf("serviceinvoke: %w", err)
	}
	if status != http.StatusOK && status != http.StatusAccepted {
		return nil, decodeError(status, raw)
	}
	var out Response
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("serviceinvoke: decode the response: %w", err)
	}
	return &Result{
		RequestID:       header.Get(RequestIDHeader),
		StatusCode:      out.StatusCode,
		ExecutedVersion: out.ExecutedVersion,
		FunctionError:   out.FunctionError,
		Payload:         out.Payload,
	}, nil
}

// post posts body to Path, signed, and returns the response's status,
// header and body. A body over maxResponseSize is an error that says so,
// rather than one cut short.
func (c *Client) post(ctx context.Context, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+Path,
		bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	sum := sha256.Sum256(body)
	if err = c.signer.SignHTTP(ctx, c.creds, req, hex.EncodeToString(sum[:]),
		SigningName, c.region, time.Now()); err != nil {
		return 0, nil, nil, fmt.Errorf("sign the request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("call %s: %w", Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read the response: %w", err)
	}
	if len(raw) > maxResponseSize {
		return 0, nil, nil, fmt.Errorf("the response exceeds %d bytes", maxResponseSize)
	}
	return resp.StatusCode, resp.Header, raw, nil
}

func decodeError(status int, raw []byte) error {
	var e ErrorResponse
	if err := json.Unmarshal(raw, &e); err != nil {
		return &Error{Status: status, Message: string(raw)}
	}
	switch {
	case status == http.StatusNotFound && e.Code == CodeResourceNotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, e.Message)
	case status == http.StatusForbidden && e.Code == CodeAccessDenied:
		return fmt.Errorf("%w: %s", ErrAccessDenied, e.Message)
	case status == http.StatusConflict && e.Code == CodeResourceConflict:
		return fmt.Errorf("%w: %s", ErrConflict, e.Message)
	}
	return &Error{Status: status, Code: e.Code, Message: e.Message}
}
