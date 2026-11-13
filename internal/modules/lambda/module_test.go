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
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn":    lambdaapi.CodeResourceNotFound,
		"999999999999:function:my-fn":                             lambdaapi.CodeResourceNotFound,
		"arn:aws-cn:lambda:eu-west-1:123456789012:function:my-fn": lambdaapi.CodeResourceNotFound,
		"bad name":  lambdaapi.CodeValidation,
		"a:b:c:d:e": lambdaapi.CodeValidation,
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

func TestCaseCollisionFindsKeysDifferingOnlyInCase(t *testing.T) {
	for _, tt := range []struct {
		stored, set map[string]string
		name        string
		collides    bool
	}{
		{name: "distinct", set: map[string]string{"team": "a", "env": "b"}},
		{
			name: "within the request", set: map[string]string{"team": "a", "Team": "b"},
			collides: true,
		},
		{
			name: "with a stored key", stored: map[string]string{"team": "a"},
			set: map[string]string{"Team": "b"}, collides: true,
		},
		{
			name: "replacing a stored key", stored: map[string]string{"team": "a"},
			set: map[string]string{"team": "b"},
		},
	} {
		if _, got := caseCollision(tt.stored, tt.set); got != tt.collides {
			t.Errorf("%s: collides %v", tt.name, got)
		}
	}
	if err := checkTags(map[string]string{"team": "a", "Team": "b"}); err != nil {
		t.Errorf("checkTags refuses what root may store: %v", err)
	}
	if _, err := resourceTags(map[string]string{"team": "a", "Team": "b"}); !errors.Is(err,
		errStoredTags) {
		t.Errorf("stored keys differing in case: %v", err)
	}
}

func TestCheckRoleHoldsTheRoleToThisAccount(t *testing.T) {
	m := &Module{settings: &contracts.Settings{AccountID: "000000000000", Region: "us-east-1"}}
	role := func(s string) *string { return &s }
	if err := m.checkRole(role("arn:aws:iam::000000000000:role/path/r"), true); err != nil {
		t.Fatalf("own role: %v", err)
	}
	for value, code := range map[string]string{
		"arn:aws:iam::111111111111:role/r":    lambdaapi.CodeAccessDenied,
		"arn:aws-cn:iam::000000000000:role/r": lambdaapi.CodeValidation,
		"arn:aws:iam::000000000000:roler":     lambdaapi.CodeValidation,
		"arn:aws:iam::000000000000:user/r":    lambdaapi.CodeValidation,
	} {
		var apiErr *lambdaapi.Error
		if err := m.checkRole(role(value), true); !errors.As(err, &apiErr) || apiErr.Code != code {
			t.Errorf("%s: %v, want %s", value, err, code)
		}
	}
	var apiErr *lambdaapi.Error
	if err := m.checkRole(role("arn:aws:iam::111111111111:role/r"), true); !errors.As(err,
		&apiErr) || apiErr.Message != "Cross-account pass role is not allowed." ||
		apiErr.Status != 403 {
		t.Errorf("cross-account: %v", err)
	}
}
