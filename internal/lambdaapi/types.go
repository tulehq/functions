package lambdaapi

import (
	"strconv"
	"time"
)

// The request and response shapes of the operations in scope, as the SDK
// model names their members. Members this service does not act on (VPC,
// layers, tracing, file systems, KMS, SnapStart, logging and the like) are
// left out of the requests: they are decoded and ignored, as any unknown
// member is.

// FunctionCode is CreateFunction's Code.
type FunctionCode struct {
	ImageURI *string `json:"ImageUri"`
	S3Bucket *string `json:"S3Bucket"`
	S3Key    *string `json:"S3Key"`
	ZipFile  []byte  `json:"ZipFile"`
}

// ImageConfig overrides an image's entry point, command and working
// directory.
type ImageConfig struct {
	WorkingDirectory *string  `json:"WorkingDirectory,omitempty"`
	EntryPoint       []string `json:"EntryPoint,omitempty"`
	Command          []string `json:"Command,omitempty"`
}

// Environment is a function's environment variables.
type Environment struct {
	Variables map[string]string `json:"Variables"`
}

// CreateFunctionRequest is the body of CreateFunction.
type CreateFunctionRequest struct {
	Code          *FunctionCode `json:"Code"`
	Environment   *Environment  `json:"Environment"`
	ImageConfig   *ImageConfig  `json:"ImageConfig"`
	Tags          RequestTags   `json:"Tags"`
	FunctionName  *string       `json:"FunctionName"`
	Role          *string       `json:"Role"`
	Description   *string       `json:"Description"`
	PackageType   *string       `json:"PackageType"`
	Runtime       *string       `json:"Runtime"`
	Handler       *string       `json:"Handler"`
	Timeout       *int          `json:"Timeout"`
	MemorySize    *int          `json:"MemorySize"`
	Architectures []string      `json:"Architectures"`
	Publish       bool          `json:"Publish"`
}

// UpdateFunctionCodeRequest is the body of UpdateFunctionCode.
type UpdateFunctionCodeRequest struct {
	ImageURI      *string  `json:"ImageUri"`
	ZipFile       []byte   `json:"ZipFile"`
	S3Bucket      *string  `json:"S3Bucket"`
	RevisionID    *string  `json:"RevisionId"`
	Architectures []string `json:"Architectures"`
	Publish       bool     `json:"Publish"`
	DryRun        bool     `json:"DryRun"`
}

// UpdateFunctionConfigurationRequest is the body of
// UpdateFunctionConfiguration.
type UpdateFunctionConfigurationRequest struct {
	Environment *Environment `json:"Environment"`
	ImageConfig *ImageConfig `json:"ImageConfig"`
	Role        *string      `json:"Role"`
	Description *string      `json:"Description"`
	RevisionID  *string      `json:"RevisionId"`
	Runtime     *string      `json:"Runtime"`
	Handler     *string      `json:"Handler"`
	Timeout     *int         `json:"Timeout"`
	MemorySize  *int         `json:"MemorySize"`
}

// EnvironmentResponse is a function's environment as reported.
type EnvironmentResponse struct {
	Variables map[string]string `json:"Variables"`
}

// ImageConfigResponse is a function's image configuration as reported.
type ImageConfigResponse struct {
	ImageConfig ImageConfig `json:"ImageConfig"`
}

// FunctionConfiguration is a function's configuration, as every function
// operation reports it.
type FunctionConfiguration struct {
	Environment                *EnvironmentResponse `json:"Environment,omitempty"`
	ImageConfigResponse        *ImageConfigResponse `json:"ImageConfigResponse,omitempty"`
	FunctionName               string               `json:"FunctionName"`
	FunctionArn                string               `json:"FunctionArn"`
	Role                       string               `json:"Role"`
	Description                string               `json:"Description"`
	LastModified               string               `json:"LastModified"`
	CodeSha256                 string               `json:"CodeSha256"`
	Version                    string               `json:"Version"`
	RevisionID                 string               `json:"RevisionId"`
	State                      string               `json:"State"`
	StateReason                string               `json:"StateReason,omitempty"`
	StateReasonCode            string               `json:"StateReasonCode,omitempty"`
	LastUpdateStatus           string               `json:"LastUpdateStatus,omitempty"`
	LastUpdateStatusReason     string               `json:"LastUpdateStatusReason,omitempty"`
	LastUpdateStatusReasonCode string               `json:"LastUpdateStatusReasonCode,omitempty"`
	PackageType                string               `json:"PackageType"`
	Architectures              []string             `json:"Architectures"`
	CodeSize                   int64                `json:"CodeSize"`
	Timeout                    int                  `json:"Timeout"`
	MemorySize                 int                  `json:"MemorySize"`
}

// FunctionCodeLocation is GetFunction's Code.
type FunctionCodeLocation struct {
	RepositoryType   string `json:"RepositoryType"`
	ImageURI         string `json:"ImageUri"`
	ResolvedImageURI string `json:"ResolvedImageUri,omitempty"`
}

// GetFunctionResponse is the body GetFunction answers with.
type GetFunctionResponse struct {
	Tags          map[string]string     `json:"Tags,omitempty"`
	Code          FunctionCodeLocation  `json:"Code"`
	Configuration FunctionConfiguration `json:"Configuration"`
}

// ListFunctionsResponse is the body ListFunctions answers with.
type ListFunctionsResponse struct {
	NextMarker string                  `json:"NextMarker,omitempty"`
	Functions  []FunctionConfiguration `json:"Functions"`
}

// TagResourceRequest is the body of TagResource.
type TagResourceRequest struct {
	Tags RequestTags `json:"Tags"`
}

// ListTagsResponse is the body ListTags answers with.
type ListTagsResponse struct {
	Tags map[string]string `json:"Tags"`
}

// ScalingConfig is a mapping's scaling configuration.
type ScalingConfig struct {
	MaximumConcurrency *int `json:"MaximumConcurrency,omitempty"`
}

// CreateEventSourceMappingRequest is the body of CreateEventSourceMapping.
type CreateEventSourceMappingRequest struct {
	ScalingConfig                  *ScalingConfig `json:"ScalingConfig"`
	Tags                           RequestTags    `json:"Tags"`
	EventSourceArn                 *string        `json:"EventSourceArn"`
	FunctionName                   *string        `json:"FunctionName"`
	Enabled                        *bool          `json:"Enabled"`
	BatchSize                      *int           `json:"BatchSize"`
	MaximumBatchingWindowInSeconds *int           `json:"MaximumBatchingWindowInSeconds"`
	StartingPosition               *string        `json:"StartingPosition"`
	FunctionResponseTypes          []string       `json:"FunctionResponseTypes"`
}

// UpdateEventSourceMappingRequest is the body of UpdateEventSourceMapping.
type UpdateEventSourceMappingRequest struct {
	ScalingConfig                  *ScalingConfig `json:"ScalingConfig"`
	FunctionName                   *string        `json:"FunctionName"`
	Enabled                        *bool          `json:"Enabled"`
	BatchSize                      *int           `json:"BatchSize"`
	MaximumBatchingWindowInSeconds *int           `json:"MaximumBatchingWindowInSeconds"`
	FunctionResponseTypes          []string       `json:"FunctionResponseTypes"`
}

// EventSourceMappingConfiguration is a mapping, as every mapping operation
// reports it.
type EventSourceMappingConfiguration struct {
	LastModified                   EpochSeconds   `json:"LastModified"`
	ScalingConfig                  *ScalingConfig `json:"ScalingConfig,omitempty"`
	UUID                           string         `json:"UUID"`
	EventSourceArn                 string         `json:"EventSourceArn"`
	FunctionArn                    string         `json:"FunctionArn"`
	LastProcessingResult           string         `json:"LastProcessingResult,omitempty"`
	State                          string         `json:"State"`
	StateTransitionReason          string         `json:"StateTransitionReason"`
	EventSourceMappingArn          string         `json:"EventSourceMappingArn"`
	FunctionResponseTypes          []string       `json:"FunctionResponseTypes"`
	BatchSize                      int            `json:"BatchSize"`
	MaximumBatchingWindowInSeconds int            `json:"MaximumBatchingWindowInSeconds"`
}

// ListEventSourceMappingsResponse is the body ListEventSourceMappings
// answers with.
type ListEventSourceMappingsResponse struct {
	NextMarker          string                            `json:"NextMarker,omitempty"`
	EventSourceMappings []EventSourceMappingConfiguration `json:"EventSourceMappings"`
}

// EpochSeconds is a timestamp as restJson1 sends one by default: seconds
// since the Unix epoch, with a fraction for the milliseconds.
type EpochSeconds time.Time

// MarshalJSON writes the timestamp as fractional epoch seconds.
func (t EpochSeconds) MarshalJSON() ([]byte, error) {
	ms := time.Time(t).UnixMilli()
	return []byte(strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64)), nil
}

// LastModifiedFormat is how FunctionConfiguration's LastModified is
// written: ISO 8601 with milliseconds and a +0000 offset, the form the
// Lambda API reference shows.
const LastModifiedFormat = "2006-01-02T15:04:05.000-0700"
