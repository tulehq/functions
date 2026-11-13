//go:build e2e

package e2e

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// waitTimeout bounds every waiter: an image already present needs no pull,
// so a function that is not Active by then never will be.
const waitTimeout = 60 * time.Second

// createInput is a CreateFunction request for an Image function from the
// test image img, created with the host's architecture.
func createInput(name, img string) *lambda.CreateFunctionInput {
	return &lambda.CreateFunctionInput{
		FunctionName:  aws.String(name),
		PackageType:   types.PackageTypeImage,
		Code:          &types.FunctionCode{ImageUri: aws.String(image(img))},
		Role:          aws.String(role),
		Architectures: []types.Architecture{types.Architecture(hostArch())},
	}
}

// createFunction creates name from the test image img, with mutate applied
// to the request, and waits until it is Active.
func createFunction(
	t *testing.T,
	c *lambda.Client,
	name, img string,
	mutate func(*lambda.CreateFunctionInput),
) *lambda.CreateFunctionOutput {
	t.Helper()
	in := createInput(name, img)
	if mutate != nil {
		mutate(in)
	}
	out, err := c.CreateFunction(t.Context(), in)
	requireNoErr(t, err, "create function "+name)
	waitActive(t, c, name)
	return out
}

// waitActive waits for the function's State to be Active with the SDK's
// FunctionActiveV2 waiter, polling faster than its one-second default.
func waitActive(t *testing.T, c *lambda.Client, name string) *lambda.GetFunctionOutput {
	t.Helper()
	w := lambda.NewFunctionActiveV2Waiter(c, func(o *lambda.FunctionActiveV2WaiterOptions) {
		o.MinDelay, o.MaxDelay = 100*time.Millisecond, time.Second
	})
	out, err := w.WaitForOutput(t.Context(), &lambda.GetFunctionInput{
		FunctionName: aws.String(name),
	}, waitTimeout)
	requireNoErr(t, err, "wait for "+name+" to be Active")
	return out
}

// waitUpdated waits for the function's LastUpdateStatus to be Successful
// with the SDK's FunctionUpdatedV2 waiter.
func waitUpdated(t *testing.T, c *lambda.Client, name string) *lambda.GetFunctionOutput {
	t.Helper()
	w := lambda.NewFunctionUpdatedV2Waiter(c, func(o *lambda.FunctionUpdatedV2WaiterOptions) {
		o.MinDelay, o.MaxDelay = 100*time.Millisecond, time.Second
	})
	out, err := w.WaitForOutput(t.Context(), &lambda.GetFunctionInput{
		FunctionName: aws.String(name),
	}, waitTimeout)
	requireNoErr(t, err, "wait for "+name+" to be updated")
	return out
}

// invoke invokes name synchronously with payload, failing on any error.
func invoke(t *testing.T, c *lambda.Client, name string, payload any) *lambda.InvokeOutput {
	t.Helper()
	return invokeWith(t, c, &lambda.InvokeInput{
		FunctionName: aws.String(name),
		Payload:      marshal(t, payload),
	})
}

// invokeWith invokes with in, failing on any error.
func invokeWith(t *testing.T, c *lambda.Client, in *lambda.InvokeInput) *lambda.InvokeOutput {
	t.Helper()
	out, err := c.Invoke(t.Context(), in)
	requireNoErr(t, err, "invoke "+aws.ToString(in.FunctionName))
	return out
}

// invokeOK invokes name and fails unless the function succeeded, decoding
// its result into v when v is not nil.
func invokeOK(t *testing.T, c *lambda.Client, name string, payload, v any) *lambda.InvokeOutput {
	t.Helper()
	out := invoke(t, c, name, payload)
	requireEqual(t, out.StatusCode, int32(200), "status of a RequestResponse invocation")
	if out.FunctionError != nil {
		t.Fatalf("invoke %s: function error %q: %s", name, *out.FunctionError, out.Payload)
	}
	if v != nil {
		unmarshal(t, out.Payload, v)
	}
	return out
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	if b, ok := v.([]byte); ok {
		return b
	}
	b, err := json.Marshal(v)
	requireNoErr(t, err, "marshal payload")
	return b
}

func unmarshal(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

// functionError is the error object AWS answers a failed invocation with:
// errorMessage, errorType and, for a runtime that sends one, stackTrace
// (Runtime API, invocation error).
type functionError struct {
	ErrorMessage string            `json:"errorMessage"`
	ErrorType    string            `json:"errorType"`
	StackTrace   []json.RawMessage `json:"stackTrace"`
}

// requireFunctionError fails unless out is a function error: status 200,
// X-Amz-Function-Error present ("The status code in the API response
// doesn't reflect function errors", Invoke), and the payload an error
// object, which it returns.
func requireFunctionError(t *testing.T, out *lambda.InvokeOutput) functionError {
	t.Helper()
	requireEqual(t, out.StatusCode, int32(200), "status of a failed invocation")
	if aws.ToString(out.FunctionError) == "" {
		t.Fatalf("no X-Amz-Function-Error on a failed invocation: %s", out.Payload)
	}
	var e functionError
	unmarshal(t, out.Payload, &e)
	if e.ErrorMessage == "" {
		t.Fatalf("the error payload has no errorMessage: %s", out.Payload)
	}
	return e
}

func getConfig(t *testing.T, c *lambda.Client, name string) *lambda.GetFunctionConfigurationOutput {
	t.Helper()
	out, err := c.GetFunctionConfiguration(t.Context(), &lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(name),
	})
	requireNoErr(t, err, "get configuration of "+name)
	return out
}

func deleteFunction(t *testing.T, c *lambda.Client, name string) {
	t.Helper()
	_, err := c.DeleteFunction(t.Context(), &lambda.DeleteFunctionInput{
		FunctionName: aws.String(name),
	})
	requireNoErr(t, err, "delete function "+name)
}
