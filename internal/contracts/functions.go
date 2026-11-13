// Package contracts defines what the functions service keeps and runs: the
// functions, their event source mappings and the invocation history, the
// store that holds them, and the engine that runs them.
package contracts

import (
	"context"
	"errors"
	"time"
)

// The function states and update statuses Lambda reports, as the SDK model
// names them.
const (
	StatePending = "Pending"
	StateActive  = "Active"
	StateFailed  = "Failed"

	UpdateInProgress = "InProgress"
	UpdateSuccessful = "Successful"
	UpdateFailed     = "Failed"
)

// LatestVersion is the only version a function has.
const LatestVersion = "$LATEST"

// ImageConfig overrides the image's entry point, command and working
// directory. Set is whether the function was given one, which decides
// whether its configuration reports one.
type ImageConfig struct {
	WorkingDirectory string   `json:"workingDirectory"`
	EntryPoint       []string `json:"entryPoint"`
	Command          []string `json:"command"`
	Set              bool     `json:"set"`
}

// Image is a checked container image: the reference it was given as, the
// image ID Docker resolved it to, which the containers are created from, and
// the digest the function reports as its code's SHA-256.
type Image struct {
	URI         string `json:"uri"`
	ID          string `json:"id"`
	ResolvedURI string `json:"resolvedUri"`
	CodeSha256  string `json:"codeSha256"`
}

// Function is a function's whole record.
//
// Image is the image the function runs; PendingImage, while an
// UpdateFunctionCode is in progress, the one being checked, which replaces
// Image only when it is usable. A function created with an image that cannot
// be used is Failed and has an Image with no ID.
//
// Policy is the function's resource-based policy document, as GetPolicy
// returns it, empty when it has none, and PolicyRevisionID its revision, a
// UUID that changes with every change to the policy.
type Function struct {
	LastModified               time.Time         `json:"lastModified"`
	Environment                map[string]string `json:"environment"`
	Tags                       map[string]string `json:"tags"`
	PendingImage               *Image            `json:"pendingImage,omitempty"`
	Image                      Image             `json:"image"`
	ARN                        string            `json:"arn"`
	LastUpdateStatusReason     string            `json:"lastUpdateStatusReason"`
	Description                string            `json:"description"`
	State                      string            `json:"state"`
	StateReason                string            `json:"stateReason"`
	StateReasonCode            string            `json:"stateReasonCode"`
	LastUpdateStatus           string            `json:"lastUpdateStatus"`
	Role                       string            `json:"role"`
	LastUpdateStatusReasonCode string            `json:"lastUpdateStatusReasonCode"`
	RevisionID                 string            `json:"revisionId"`
	Policy                     string            `json:"policy,omitempty"`
	PolicyRevisionID           string            `json:"policyRevisionId,omitempty"`
	Name                       string            `json:"name"`
	Architectures              []string          `json:"architectures"`
	ImageConfig                ImageConfig       `json:"imageConfig"`
	Timeout                    int               `json:"timeout"`
	MemorySize                 int               `json:"memorySize"`
}

// The event source mapping states Lambda reports.
const (
	MappingCreating = "Creating"
	MappingEnabled  = "Enabled"
	MappingDisabled = "Disabled"
	MappingUpdating = "Updating"
	MappingDeleting = "Deleting"
)

// ReportBatchItemFailures is the one function response type an SQS mapping
// takes.
const ReportBatchItemFailures = "ReportBatchItemFailures"

// Mapping is an event source mapping from an SQS queue to a function.
// MaximumConcurrency is 0 when the mapping has no ScalingConfig.
type Mapping struct {
	LastModified          time.Time         `json:"lastModified"`
	Tags                  map[string]string `json:"tags"`
	UUID                  string            `json:"uuid"`
	ARN                   string            `json:"arn"`
	EventSourceARN        string            `json:"eventSourceArn"`
	FunctionName          string            `json:"functionName"`
	FunctionARN           string            `json:"functionArn"`
	State                 string            `json:"state"`
	StateTransitionReason string            `json:"stateTransitionReason"`
	LastProcessingResult  string            `json:"lastProcessingResult"`
	FunctionResponseTypes []string          `json:"functionResponseTypes"`
	BatchSize             int               `json:"batchSize"`
	BatchingWindow        int               `json:"batchingWindow"`
	MaximumConcurrency    int               `json:"maximumConcurrency"`
	Enabled               bool              `json:"enabled"`
}

// The sources and statuses of an invocation, as the retrieval API names
// them.
const (
	SourceInvoke  = "invoke"
	SourceAsync   = "async"
	SourceMapping = "eventSourceMapping"

	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusTimedOut  = "timedOut"
)

// Invocation is one invocation as the history keeps it: its last attempt,
// for an asynchronous one that was retried.
type Invocation struct {
	Time         time.Time `json:"time"`
	RequestID    string    `json:"requestId"`
	Function     string    `json:"function"`
	Source       string    `json:"source"`
	Status       string    `json:"status"`
	ErrorType    string    `json:"errorType"`
	ErrorMessage string    `json:"errorMessage"`
	Log          string    `json:"log"`
	Payload      []byte    `json:"payload"`
	Result       []byte    `json:"result"`
	Duration     float64   `json:"duration"`
	Attempts     int       `json:"attempts"`
}

// InvocationFilter narrows a listing of the history. Empty fields match
// everything; Since and Until bound the time, inclusive.
type InvocationFilter struct {
	Since    *time.Time
	Until    *time.Time
	Function string
	Status   string
	Source   string
}

// HistoryBounds bound the history: its number of invocations, and the
// bytes of their payloads, results and logs together.
type HistoryBounds struct {
	Rows  int
	Bytes int
}

// MaxHistoryField is how much of an invocation's payload, result or log the
// history keeps: 1 MiB each. What is cut is replaced by TruncatedMarker.
const MaxHistoryField = 1 << 20

// TruncatedMarker ends a history field that was cut short.
const TruncatedMarker = "...[truncated by tule]"

// MappingFilter narrows a listing of the mappings.
type MappingFilter struct {
	FunctionName   string
	EventSourceARN string
}

// PageInput asks for one page of a listing: up to Size items after Token,
// or from the start when Token is empty.
type PageInput struct {
	Token string
	Size  int
}

// Page is one page of a listing; NextToken is empty on the last.
type Page[T any] struct {
	NextToken string
	Items     []T
}

// The store's sentinel errors.
var (
	ErrFunctionNotFound   = errors.New("function not found")
	ErrFunctionExists     = errors.New("function already exists")
	ErrMappingNotFound    = errors.New("event source mapping not found")
	ErrInvocationNotFound = errors.New("invocation not found")
	ErrInvalidToken       = errors.New("invalid pagination token")
)

// Store keeps the functions, the mappings and the invocation history.
type Store interface {
	// InstanceID returns the store's own random ID, made when the store was
	// created. The containers are labeled with it, so a restart on the same
	// store finds the ones a previous run left behind.
	InstanceID(ctx context.Context) (string, error)

	PutFunction(ctx context.Context, fn *Function) error
	GetFunction(ctx context.Context, name string) (*Function, error)
	// UpdateFunction reads the function, lets update change it, and writes
	// it back, in one transaction; an error from update leaves it as it was.
	UpdateFunction(
		ctx context.Context,
		name string,
		update func(*Function) error,
	) (*Function, error)
	DeleteFunction(ctx context.Context, name string) error
	ListFunctions(ctx context.Context, page PageInput) (*Page[Function], error)
	AllFunctions(ctx context.Context) ([]Function, error)

	PutMapping(ctx context.Context, m *Mapping) error
	GetMapping(ctx context.Context, uuid string) (*Mapping, error)
	UpdateMapping(ctx context.Context, uuid string, update func(*Mapping) error) (*Mapping, error)
	DeleteMapping(ctx context.Context, uuid string) error
	ListMappings(ctx context.Context, f MappingFilter, page PageInput) (*Page[Mapping], error)
	AllMappings(ctx context.Context) ([]Mapping, error)

	// PutInvocation records inv, replacing an earlier record of the same
	// request, its payload, result and log each truncated to
	// MaxHistoryField, and drops the oldest records beyond bounds.
	PutInvocation(ctx context.Context, inv *Invocation, bounds HistoryBounds) error
	GetInvocation(ctx context.Context, requestID string) (*Invocation, error)
	ListInvocations(
		ctx context.Context,
		f InvocationFilter,
		page PageInput,
	) (*Page[Invocation], error)
	DeleteInvocations(ctx context.Context) error
}
