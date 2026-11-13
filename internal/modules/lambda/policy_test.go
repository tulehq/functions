package lambda

import (
	"errors"
	"strings"
	"testing"

	"tule.dev/functions/internal/lambdaapi"
)

const policyFnARN = "arn:aws:lambda:us-east-1:123456789012:function:fn"

func str(s string) *string { return &s }

func permission() *lambdaapi.AddPermissionRequest {
	return &lambdaapi.AddPermissionRequest{
		StatementID: str("s-1_a"), Action: str("lambda:InvokeFunction"),
		Principal: str("111122223333"),
	}
}

func requireCode(t *testing.T, name string, err error, code string) {
	t.Helper()
	var apiErr *lambdaapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != code {
		t.Errorf("%s: got %v, want %s", name, err, code)
	}
}

// TestTheStatementIsLambdas checks the statements AddPermission writes
// against the Developer Guide's and the CLI reference's add-permission
// outputs.
// statementCase is an AddPermission request, as edit makes it from
// permission's, and the statement Lambda writes for it.
type statementCase struct {
	edit func(*lambdaapi.AddPermissionRequest)
	want string
}

// statementCases are the statements of TestTheStatementIsLambdas.
func statementCases() map[string]statementCase {
	return map[string]statementCase{
		"an account": {
			edit: func(*lambdaapi.AddPermissionRequest) {},
			want: `{"Sid":"s-1_a","Effect":"Allow","Principal":{"AWS":` +
				`"arn:aws:iam::111122223333:root"},"Action":"lambda:InvokeFunction",` +
				`"Resource":"` + policyFnARN + `"}`,
		},
		"a service with a source": {
			edit: func(r *lambdaapi.AddPermissionRequest) {
				r.Principal = str("sns.amazonaws.com")
				r.SourceArn = str("arn:aws:sns:us-east-1:111122223333:topic")
				r.SourceAccount = str("111122223333")
			},
			want: `{"Sid":"s-1_a","Effect":"Allow","Principal":{"Service":` +
				`"sns.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"` +
				policyFnARN + `","Condition":{"ArnLike":{"AWS:SourceArn":` +
				`"arn:aws:sns:us-east-1:111122223333:topic"},"StringEquals":` +
				`{"AWS:SourceAccount":"111122223333"}}}`,
		},
		"a role ARN": {
			edit: func(r *lambdaapi.AddPermissionRequest) {
				r.Principal = str("arn:aws:iam::111122223333:role/ci/runner")
			},
			want: `{"Sid":"s-1_a","Effect":"Allow","Principal":{"AWS":` +
				`"arn:aws:iam::111122223333:role/ci/runner"},"Action":"lambda:InvokeFunction",` +
				`"Resource":"` + policyFnARN + `"}`,
		},
		"everyone in an organization, by function URL": {
			edit: func(r *lambdaapi.AddPermissionRequest) {
				r.Principal = str("*")
				r.PrincipalOrgID = str("o-a1b2c3d4e5")
				r.FunctionURLAuthType = str("NONE")
				r.InvokedViaFunctionURL = new(true)
				r.EventSourceToken = str("tok.1")
			},
			want: `{"Sid":"s-1_a","Effect":"Allow","Principal":"*","Action":` +
				`"lambda:InvokeFunction","Resource":"` + policyFnARN + `","Condition":` +
				`{"Bool":{"lambda:InvokedViaFunctionUrl":"true"},"StringEquals":` +
				`{"aws:PrincipalOrgID":"o-a1b2c3d4e5","lambda:EventSourceToken":"tok.1",` +
				`"lambda:FunctionUrlAuthType":"NONE"}}}`,
		},
	}
}

func TestTheStatementIsLambdas(t *testing.T) {
	for name, tt := range statementCases() {
		req := permission()
		tt.edit(req)
		if err := checkAddPermission(req); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		s, err := statementOf(req, policyFnARN)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, tt.want)
		}
		doc, err := withStatement("", s)
		if err != nil {
			t.Fatal(err)
		}
		if err = checkPolicy(doc); err != nil {
			t.Errorf("%s: the policy does not parse: %v", name, err)
		}
	}
}

func TestAnInvalidPrincipalIsRefused(t *testing.T) {
	for _, p := range []string{
		"alice", "1234", "arn:aws:iam::111122223333:group/g", "arn:aws:iam::1:root",
		"arn:aws:iam::111122223333:user/a*", "SNS.amazonaws.com",
	} {
		req := permission()
		req.Principal = str(p)
		_, err := statementOf(req, policyFnARN)
		if !errors.Is(err, errInvalidPrincipal) {
			t.Errorf("%s: got %v", p, err)
		}
	}
}

func TestAddPermissionIsHeldToTheModel(t *testing.T) {
	for name, edit := range map[string]func(*lambdaapi.AddPermissionRequest){
		"no statement ID":      func(r *lambdaapi.AddPermissionRequest) { r.StatementID = nil },
		"no action":            func(r *lambdaapi.AddPermissionRequest) { r.Action = nil },
		"no principal":         func(r *lambdaapi.AddPermissionRequest) { r.Principal = nil },
		"a dot in the ID":      func(r *lambdaapi.AddPermissionRequest) { r.StatementID = str("a.b") },
		"an empty ID":          func(r *lambdaapi.AddPermissionRequest) { r.StatementID = str("") },
		"a long ID":            func(r *lambdaapi.AddPermissionRequest) { r.StatementID = str(strings.Repeat("a", 101)) },
		"another service":      func(r *lambdaapi.AddPermissionRequest) { r.Action = str("s3:GetObject") },
		"a space in principal": func(r *lambdaapi.AddPermissionRequest) { r.Principal = str("a b") },
		"an organization":      func(r *lambdaapi.AddPermissionRequest) { r.PrincipalOrgID = str("o-1") },
		"a source account":     func(r *lambdaapi.AddPermissionRequest) { r.SourceAccount = str("12") },
		"a source ARN":         func(r *lambdaapi.AddPermissionRequest) { r.SourceArn = str("bucket") },
		"an auth type":         func(r *lambdaapi.AddPermissionRequest) { r.FunctionURLAuthType = str("IAM") },
		"a token": func(r *lambdaapi.AddPermissionRequest) {
			r.EventSourceToken = str(strings.Repeat("t", 257))
		},
	} {
		req := permission()
		edit(req)
		requireCode(t, name, checkAddPermission(req), lambdaapi.CodeValidation)
	}
	req := permission()
	req.StatementID = str(strings.Repeat("a", 100))
	req.Action = str("lambda:*")
	if err := checkAddPermission(req); err != nil {
		t.Errorf("at the limits: %v", err)
	}
}

// statement is the statement of permission's request with the ID sid.
func statement(t *testing.T, sid string) *permissionStatement {
	t.Helper()
	req := permission()
	req.StatementID = str(sid)
	s, err := statementOf(req, policyFnARN)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStatementsAreAddedAndRemovedBySid(t *testing.T) {
	s1 := statement(t, "s-1_a")
	doc, err := withStatement("", s1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(
		doc,
		`{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"s-1_a"`,
	) {
		t.Fatalf("new policy %s", doc)
	}
	_, err = withStatement(doc, s1)
	requireCode(t, "the same Sid", err, lambdaapi.CodeResourceConflict)

	if doc, err = withStatement(doc, statement(t, "s2")); err != nil {
		t.Fatal(err)
	}
	if doc, err = withoutStatement(doc, "s-1_a"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc, "s-1_a") || !strings.Contains(doc, `"Sid":"s2"`) {
		t.Fatalf("after removing s-1_a: %s", doc)
	}
	_, err = withoutStatement(doc, "s-1_a")
	requireCode(t, "a removed Sid", err, lambdaapi.CodeResourceNotFound)
	if doc, err = withoutStatement(doc, "s2"); err != nil || doc != "" {
		t.Fatalf("the last statement: %q %v", doc, err)
	}
}

// TestAStatementIsAddedToAPutPolicy checks that AddPermission appends to a
// policy PutResourcePolicy stored, whose Statement is a single object and
// whose Sid may be missing.
func TestAStatementIsAddedToAPutPolicy(t *testing.T) {
	put := `{"Version": "2012-10-17", "Statement": {"Effect": "Deny", "Principal": "*",` +
		` "Action": "lambda:InvokeFunction", "Resource": "` + policyFnARN + `"}}`
	s, err := statementOf(permission(), policyFnARN)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := withStatement(put, s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*",` +
		`"Action":"lambda:InvokeFunction","Resource":"` + policyFnARN + `"},{"Sid":"s-1_a"`
	if !strings.HasPrefix(doc, want) {
		t.Fatalf("got %s", doc)
	}
	if err = checkPolicy(doc); err != nil {
		t.Fatal(err)
	}
}

func TestThePolicySizeIsCapped(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"s","Effect":"Allow","Principal":"*",` +
		`"Action":"lambda:GetPolicy","Resource":"` + policyFnARN + `","Condition":{` +
		`"StringEquals":{"aws:SourceIp":"`
	tail := `"}}}]}`
	at := doc + strings.Repeat("x", maxPolicySize-len(doc)-len(tail)) + tail
	if err := checkPolicy(at); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	over := doc + strings.Repeat("x", maxPolicySize-len(doc)-len(tail)+1) + tail
	requireCode(t, "over the limit", checkPolicy(over), lambdaapi.CodePolicyLengthExceeded)
}

func TestAMalformedPolicyIsRefused(t *testing.T) {
	for name, doc := range map[string]string{
		"not JSON":     `{`,
		"no principal": `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		"a group": `{"Statement":{"Effect":"Allow","Principal":{"AWS":` +
			`"arn:aws:iam::111122223333:group/g"},"Action":"*","Resource":"*"}}`,
		"a duplicate Sid": `{"Statement":[{"Sid":"a","Effect":"Allow","Principal":"*",` +
			`"Action":"*","Resource":"*"},{"Sid":"a","Effect":"Allow","Principal":"*",` +
			`"Action":"*","Resource":"*"}]}`,
	} {
		requireCode(t, name, checkPolicy(doc), lambdaapi.CodeInvalidParameterValue)
	}
}

func TestAPolicyRevisionIsAUUID(t *testing.T) {
	if err := checkPolicyRevision(str("a1b2c3d4-5678-90ab-cdef-111111111111")); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "x", "A1B2C3D4-5678-90AB-CDEF-111111111111"} {
		requireCode(t, v, checkPolicyRevision(str(v)), lambdaapi.CodeValidation)
	}
}
