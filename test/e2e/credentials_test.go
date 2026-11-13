//go:build e2e

package e2e

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// Lambda sets AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to "The access
// keys obtained from the function's execution role", and they are among the
// keys that "are reserved and cannot be set in your function configuration"
// (Defined runtime environment variables). functions sets them to its own
// configured key, unless TULE_Functions_FunctionCredentials=none.

var credentialKeys = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}

func TestFunctionCredentialsByDefault(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "keyed", "env", nil)
	var r envResult
	invokeOK(t, c, "keyed", map[string]any{}, &r)
	requireEqual(t, r.Env["AWS_ACCESS_KEY_ID"], "test", "AWS_ACCESS_KEY_ID")
	requireEqual(t, r.Env["AWS_SECRET_ACCESS_KEY"], "test", "AWS_SECRET_ACCESS_KEY")
}

func TestFunctionCredentialsOff(t *testing.T) {
	srv := startServer(t, map[string]string{"TULE_Functions_FunctionCredentials": "none"})
	c := clientFor(srv)
	createFunction(t, c, "keyless", "env", nil)
	var r envResult
	invokeOK(t, c, "keyless", map[string]any{}, &r)
	for _, k := range credentialKeys {
		if v, ok := r.Env[k]; ok {
			t.Fatalf("%s=%q is set with function credentials off", k, v)
		}
	}

	// Assumption: the keys stay reserved with the setting off, as AWS
	// reserves them whatever the role.
	for _, k := range credentialKeys {
		in := createInput("override-"+k, "env")
		in.Environment = &types.Environment{Variables: map[string]string{k: "mine"}}
		requireModeled[*types.InvalidParameterValueException](
			t,
			errOf(c.CreateFunction(t.Context(), in)),
		)
	}
}

func TestFunctionCredentialsCannotBeOverridden(t *testing.T) {
	// The reserved keys are refused on CreateFunction and on
	// UpdateFunctionConfiguration. Assumption: as
	// InvalidParameterValueException, the error for a parameter that is not
	// valid; the page names no code.
	c, _ := newClient(t)
	for _, k := range credentialKeys {
		in := createInput("override-"+k, "env")
		in.Environment = &types.Environment{Variables: map[string]string{k: "mine"}}
		requireModeled[*types.InvalidParameterValueException](
			t,
			errOf(c.CreateFunction(t.Context(), in)),
		)
		err := errOf(
			c.GetFunction(t.Context(), &lambda.GetFunctionInput{FunctionName: in.FunctionName}),
		)
		requireModeled[*types.ResourceNotFoundException](t, err)
	}

	createFunction(t, c, "kept", "env", nil)
	for _, k := range credentialKeys {
		err := errOf(
			c.UpdateFunctionConfiguration(t.Context(), &lambda.UpdateFunctionConfigurationInput{
				FunctionName: aws.String("kept"),
				Environment:  &types.Environment{Variables: map[string]string{k: "mine"}},
			}),
		)
		requireModeled[*types.InvalidParameterValueException](t, err)
	}
	var r envResult
	invokeOK(t, c, "kept", map[string]any{}, &r)
	requireEqual(
		t,
		r.Env["AWS_ACCESS_KEY_ID"],
		"test",
		"AWS_ACCESS_KEY_ID after the refused updates",
	)
	requireEqual(
		t,
		r.Env["AWS_SECRET_ACCESS_KEY"],
		"test",
		"AWS_SECRET_ACCESS_KEY after the refused updates",
	)
}
