package lambda

import (
	"errors"
	"testing"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/lambdaapi"
)

func TestResolveNameTakesEveryFormLambdaDoes(t *testing.T) {
	m := &Module{settings: &contracts.Settings{AccountID: "123456789012", Region: "eu-west-1"}}
	for value, want := range map[string]string{
		"my-fn":                       "my-fn",
		"my-fn:$LATEST":               "my-fn",
		"123456789012:function:my-fn": "my-fn",
		"arn:aws:lambda:eu-west-1:123456789012:function:my-fn":         "my-fn",
		"arn:aws:lambda:eu-west-1:123456789012:function:my-fn:$LATEST": "my-fn",
	} {
		got, err := m.resolveName(value)
		if err != nil || got != want {
			t.Errorf("resolveName(%q) = %q, %v; want %q", value, got, err, want)
		}
	}
	for value, code := range map[string]string{
		"my-fn:v1": lambdaapi.CodeResourceNotFound,
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn": lambdaapi.CodeResourceNotFound,
		"999999999999:function:my-fn":                          lambdaapi.CodeResourceNotFound,
		"bad name":                                             lambdaapi.CodeValidation,
		"a:b:c:d:e":                                            lambdaapi.CodeValidation,
	} {
		_, err := m.resolveName(value)
		var apiErr *lambdaapi.Error
		if !errors.As(err, &apiErr) || apiErr.Code != code {
			t.Errorf("resolveName(%q) = %v, want %s", value, err, code)
		}
	}
}

func TestCheckEnvironmentRefusesReservedKeysAndSize(t *testing.T) {
	if err := checkEnvironment(map[string]string{"GOOD_KEY": "v"}); err != nil {
		t.Fatalf("good: %v", err)
	}
	for name, vars := range map[string]map[string]string{
		"reserved":  {"AWS_REGION": "x"},
		"pattern":   {"1BAD": "x"},
		"too short": {"A": "x"},
		"too large": {"BIG": string(make([]byte, 4096))},
	} {
		if err := checkEnvironment(vars); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
