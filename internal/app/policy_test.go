package app

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go"
)

// requireCode fails unless err is the Lambda error code with status.
func requireCode(t *testing.T, what string, err error, code string, status int) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != code {
		t.Fatalf("%s: got %v, want %s", what, err, code)
	}
	var re interface{ HTTPStatusCode() int }
	if !errors.As(err, &re) || re.HTTPStatusCode() != status {
		t.Fatalf("%s: status of %v, want %d", what, err, status)
	}
}

func addPermission(sid, principal string) *lambda.AddPermissionInput {
	return &lambda.AddPermissionInput{
		FunctionName: aws.String("fn"), StatementId: aws.String(sid),
		Action: aws.String("lambda:GetFunction"), Principal: aws.String(principal),
	}
}

// TestTheFunctionPolicyIsKeptAsLambdaKeepsIt drives AddPermission,
// GetPolicy and RemovePermission with the root key, through the SDK.
func TestTheFunctionPolicyIsKeptAsLambdaKeepsIt(t *testing.T) {
	root, _ := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	fn := aws.String("fn")

	_, err := root.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: fn})
	requireCode(t, "no policy", err, "ResourceNotFoundException", http.StatusNotFound)

	added, err := root.AddPermission(ctx, addPermission("acct-1", "111122223333"))
	if err != nil {
		t.Fatal(err)
	}
	wantStatement := `{"Sid":"acct-1","Effect":"Allow","Principal":{"AWS":` +
		`"arn:aws:iam::111122223333:root"},"Action":"lambda:GetFunction","Resource":"` +
		fnARN + `"}`
	if aws.ToString(added.Statement) != wantStatement {
		t.Fatalf("statement\n got %s\nwant %s", aws.ToString(added.Statement), wantStatement)
	}
	got, err := root.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: fn})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Version":"2012-10-17","Id":"default","Statement":[` + wantStatement + `]}`
	if aws.ToString(got.Policy) != want {
		t.Fatalf("policy\n got %s\nwant %s", aws.ToString(got.Policy), want)
	}
	revision := aws.ToString(got.RevisionId)

	_, err = root.AddPermission(ctx, addPermission("acct-1", "111122223333"))
	requireCode(t, "the same statement ID", err, "ResourceConflictException", http.StatusConflict)

	in := addPermission("acct-2", "222233334444")
	in.RevisionId = aws.String("a1b2c3d4-5678-90ab-cdef-111111111111")
	_, err = root.AddPermission(ctx, in)
	requireCode(t, "a stale revision", err, "PreconditionFailedException",
		http.StatusPreconditionFailed)
	in.RevisionId = aws.String(revision)
	if _, err = root.AddPermission(ctx, in); err != nil {
		t.Fatalf("the current revision: %v", err)
	}

	for _, sid := range []string{"acct-1", "acct-2"} {
		if _, err = root.RemovePermission(ctx, &lambda.RemovePermissionInput{
			FunctionName: fn, StatementId: aws.String(sid),
		}); err != nil {
			t.Fatalf("remove %s: %v", sid, err)
		}
	}
	_, err = root.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: fn})
	requireCode(t, "every statement removed", err, "ResourceNotFoundException",
		http.StatusNotFound)
}

// TestPermissionsAreRefusedAsLambdaRefusesThem checks AddPermission and
// RemovePermission's refusals.
func TestPermissionsAreRefusedAsLambdaRefusesThem(t *testing.T) {
	root, _ := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	in := addPermission("latest", "*")
	in.Qualifier = aws.String("$LATEST")
	_, err := root.AddPermission(ctx, in)
	requireCode(t, "$LATEST", err, "InvalidParameterValueException", http.StatusBadRequest)
	in.Qualifier = aws.String("v1")
	_, err = root.AddPermission(ctx, in)
	requireCode(t, "a version", err, "ResourceNotFoundException", http.StatusNotFound)
	_, err = root.AddPermission(ctx, addPermission("bad", "alice"))
	requireCode(t, "a principal", err, "InvalidParameterValueException", http.StatusBadRequest)
	in = addPermission("missing", "*")
	in.FunctionName = aws.String("missing")
	_, err = root.AddPermission(ctx, in)
	requireCode(t, "a missing function", err, "ResourceNotFoundException", http.StatusNotFound)

	_, err = root.RemovePermission(ctx, &lambda.RemovePermissionInput{
		FunctionName: aws.String("fn"), StatementId: aws.String("nope"),
	})
	requireCode(t, "no policy", err, "ResourceNotFoundException", http.StatusNotFound)
	if _, err = root.AddPermission(ctx, addPermission("s", "*")); err != nil {
		t.Fatal(err)
	}
	_, err = root.RemovePermission(ctx, &lambda.RemovePermissionInput{
		FunctionName: aws.String("fn"), StatementId: aws.String("nope"),
	})
	requireCode(t, "an unknown statement", err, "ResourceNotFoundException", http.StatusNotFound)
	_, err = root.RemovePermission(ctx, &lambda.RemovePermissionInput{
		FunctionName: aws.String("fn"), StatementId: aws.String("s"),
		RevisionId: aws.String("stale"),
	})
	requireCode(t, "a stale revision", err, "PreconditionFailedException",
		http.StatusPreconditionFailed)
}

// TestTheWholePolicyIsPutAndDeleted drives PutResourcePolicy,
// GetResourcePolicy and DeleteResourcePolicy with the root key.
func TestTheWholePolicyIsPutAndDeleted(t *testing.T) {
	root, _ := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	arn := aws.String(fnARN)
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"deny","Effect":"Deny",` +
		`"Principal":"*","Action":"lambda:InvokeFunction","Resource":"` + fnARN + `"}]}`

	put, err := root.PutResourcePolicy(ctx, &lambda.PutResourcePolicyInput{
		ResourceArn: arn, Policy: aws.String(doc),
	})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(put.Policy) != doc || len(aws.ToString(put.RevisionId)) != 36 {
		t.Fatalf("put: %s %s", aws.ToString(put.Policy), aws.ToString(put.RevisionId))
	}
	if _, err = root.AddPermission(ctx, addPermission("added", "111122223333")); err != nil {
		t.Fatal(err)
	}
	got, err := root.GetResourcePolicy(ctx, &lambda.GetResourcePolicyInput{ResourceArn: arn})
	if err != nil {
		t.Fatal(err)
	}
	if p := aws.ToString(got.Policy); !strings.Contains(p, `"Sid":"deny"`) ||
		!strings.Contains(p, `"Sid":"added"`) {
		t.Fatalf("AddPermission after PutResourcePolicy: %s", p)
	}

	if _, err = root.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{
		ResourceArn: arn, RevisionId: got.RevisionId,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = root.GetResourcePolicy(ctx, &lambda.GetResourcePolicyInput{ResourceArn: arn})
	requireCode(t, "deleted", err, "ResourceNotFoundException", http.StatusNotFound)
	_, err = root.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{ResourceArn: arn})
	requireCode(t, "deleted twice", err, "ResourceNotFoundException", http.StatusNotFound)
}

// TestAFunctionPolicyGrantsAndDenies checks the function policy in
// evaluation: a user of the service's account with no identity policy is
// allowed what it names the user for, and a Deny in it beats the identity
// policies' Allow.
func TestAFunctionPolicyGrantsAndDenies(t *testing.T) {
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t).URL)
	root, srv := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	createActiveOrFailed(t, root, "other")
	c := userClient(srv)

	if _, err := root.AddPermission(ctx, addPermission("user", userARN)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetFunction(ctx,
		&lambda.GetFunctionInput{FunctionName: aws.String("fn")}); err != nil {
		t.Fatalf("granted by the function policy: %v", err)
	}
	_, err := c.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String("other")})
	requireDenied(t, err, "lambda:GetFunction",
		"arn:aws:lambda:us-east-1:000000000000:function:other")

	// The policy grants only the actions Lambda's resource-based policies
	// support: a grant of UpdateFunctionConfiguration is not honored.
	in := addPermission("config", userARN)
	in.Action = aws.String("lambda:UpdateFunctionConfiguration")
	if _, err = root.AddPermission(ctx, in); err != nil {
		t.Fatal(err)
	}
	_, err = c.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String("fn"), Timeout: aws.Int32(9),
	})
	requireDenied(t, err, "lambda:UpdateFunctionConfiguration", fnARN)
}

func TestAnExplicitDenyInTheFunctionPolicyWins(t *testing.T) {
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, all).URL)
	root, srv := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	if _, err := root.PutResourcePolicy(ctx, &lambda.PutResourcePolicyInput{
		ResourceArn: aws.String(fnARN),
		Policy: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Deny",` +
			`"Principal":{"AWS":"` + userARN + `"},"Action":"lambda:GetFunction*",` +
			`"Resource":"` + fnARN + `"}}`),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := userClient(srv).GetFunctionConfiguration(ctx,
		&lambda.GetFunctionConfigurationInput{FunctionName: aws.String("fn")})
	var apiErr smithy.APIError
	want := "User: " + userARN + " is not authorized to perform: " +
		"lambda:GetFunctionConfiguration on resource: " + fnARN +
		" with an explicit deny in a resource-based policy"
	if !errors.As(err, &apiErr) || apiErr.ErrorMessage() != want {
		t.Fatalf("got %v\nwant %s", err, want)
	}
}

// TestAnotherAccountNeedsTheFunctionPolicy checks a member account's
// session whose identity policy allows everything: denied until the
// function policy grants its account, then allowed what it grants only.
func TestAnotherAccountNeedsTheFunctionPolicy(t *testing.T) {
	const member = "arn:aws:sts::111111111111:assumed-role/Admin/s"
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentityAs(t, "111111111111", member, all).URL)
	root, srv := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	c := userClient(srv)
	get := func() error {
		return errOf(c.GetFunctionConfiguration(ctx,
			&lambda.GetFunctionConfigurationInput{FunctionName: aws.String("fn")}))
	}
	err := get()
	var apiErr smithy.APIError
	want := "User: " + member + " is not authorized to perform: " +
		"lambda:GetFunctionConfiguration on resource: " + fnARN +
		" because no resource-based policy allows the lambda:GetFunctionConfiguration action"
	if !errors.As(err, &apiErr) || apiErr.ErrorMessage() != want {
		t.Fatalf("got %v\nwant %s", err, want)
	}
	in := addPermission("member", "111111111111")
	in.Action = aws.String("lambda:GetFunctionConfiguration")
	if _, err = root.AddPermission(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err = get(); err != nil {
		t.Fatalf("granted: %v", err)
	}
	_, err = c.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String("fn")})
	if !errors.As(err, &apiErr) || !strings.HasSuffix(apiErr.ErrorMessage(),
		"because no resource-based policy allows the lambda:GetFunction action") {
		t.Fatalf("an action not granted: %v", err)
	}
}

// TestPutResourcePolicyIsRefusedAsLambdaRefusesIt checks
// PutResourcePolicy's refusals.
func TestPutResourcePolicyIsRefusedAsLambdaRefusesIt(t *testing.T) {
	root, _ := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	arn := aws.String(fnARN)
	doc := `{"Statement":{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"}}`
	if _, err := root.PutResourcePolicy(ctx, &lambda.PutResourcePolicyInput{
		ResourceArn: arn, Policy: aws.String(doc),
	}); err != nil {
		t.Fatal(err)
	}
	for what, tt := range map[string]struct {
		in   *lambda.PutResourcePolicyInput
		code string
	}{
		"malformed": {
			&lambda.PutResourcePolicyInput{ResourceArn: arn, Policy: aws.String(`{"Statement":`)},
			"InvalidParameterValueException",
		},
		"no principal": {
			&lambda.PutResourcePolicyInput{ResourceArn: arn, Policy: aws.String(
				`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)},
			"InvalidParameterValueException",
		},
		"too long": {
			&lambda.PutResourcePolicyInput{
				ResourceArn: arn, Policy: aws.String(strings.Repeat(" ", 20481)),
			},
			"ValidationException",
		},
		"a stale revision": {&lambda.PutResourcePolicyInput{
			ResourceArn: arn, Policy: aws.String(doc),
			RevisionId: aws.String("a1b2c3d4-5678-90ab-cdef-111111111111"),
		}, "PreconditionFailedException"},
		"a bad revision": {&lambda.PutResourcePolicyInput{
			ResourceArn: arn, Policy: aws.String(doc), RevisionId: aws.String("x"),
		}, "ValidationException"},
		"another account": {&lambda.PutResourcePolicyInput{
			ResourceArn: aws.String("arn:aws:lambda:us-east-1:111122223333:function:fn"),
			Policy:      aws.String(doc),
		}, "ResourceNotFoundException"},
		"not an ARN": {&lambda.PutResourcePolicyInput{
			ResourceArn: aws.String("fn"), Policy: aws.String(doc),
		}, "ValidationException"},
		"$LATEST": {&lambda.PutResourcePolicyInput{
			ResourceArn: aws.String(fnARN + ":$LATEST"), Policy: aws.String(doc),
		}, "InvalidParameterValueException"},
	} {
		_, err := root.PutResourcePolicy(ctx, tt.in)
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != tt.code {
			t.Errorf("%s: got %v, want %s", what, err, tt.code)
		}
	}
}

// TestADenyInTheFunctionPolicyAppliesToEveryAction checks a Deny on an
// action the function policy cannot grant: it still beats the identity
// policies' Allow.
func TestADenyInTheFunctionPolicyAppliesToEveryAction(t *testing.T) {
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, all).URL)
	root, srv := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	if _, err := root.PutResourcePolicy(ctx, &lambda.PutResourcePolicyInput{
		ResourceArn: aws.String(fnARN),
		Policy: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Deny",` +
			`"Principal":"*","Action":"lambda:UpdateFunctionConfiguration",` +
			`"Resource":"` + fnARN + `"}}`),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := userClient(srv).UpdateFunctionConfiguration(ctx,
		&lambda.UpdateFunctionConfigurationInput{
			FunctionName: aws.String("fn"), Timeout: aws.Int32(9),
		})
	var apiErr smithy.APIError
	want := "User: " + userARN + " is not authorized to perform: " +
		"lambda:UpdateFunctionConfiguration on resource: " + fnARN +
		" with an explicit deny in a resource-based policy"
	if !errors.As(err, &apiErr) || apiErr.ErrorMessage() != want {
		t.Fatalf("got %v\nwant %s", err, want)
	}
}

// TestAGrantTheFunctionPolicyCannotMakeIsNotHonored grants another
// account UpdateFunctionConfiguration, which the Developer Guide does not
// list among the actions resource-based policies support: it is denied as
// if nothing granted it.
func TestAGrantTheFunctionPolicyCannotMakeIsNotHonored(t *testing.T) {
	const member = "arn:aws:sts::111111111111:assumed-role/Admin/s"
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentityAs(t, "111111111111", member, all).URL)
	root, srv := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	in := addPermission("member", "111111111111")
	in.Action = aws.String("lambda:UpdateFunctionConfiguration")
	if _, err := root.AddPermission(ctx, in); err != nil {
		t.Fatal(err)
	}
	_, err := userClient(srv).UpdateFunctionConfiguration(ctx,
		&lambda.UpdateFunctionConfigurationInput{
			FunctionName: aws.String("fn"), Timeout: aws.Int32(9),
		})
	var apiErr smithy.APIError
	want := "User: " + member + " is not authorized to perform: " +
		"lambda:UpdateFunctionConfiguration on resource: " + fnARN + " because no " +
		"resource-based policy allows the lambda:UpdateFunctionConfiguration action"
	if !errors.As(err, &apiErr) || apiErr.ErrorMessage() != want {
		t.Fatalf("got %v\nwant %s", err, want)
	}
}

// TestAnEmptyConditionIsRefused sends AddPermission's condition members
// empty: each is refused with ValidationException, and no statement is
// stored, so none becomes an unconditioned grant.
func TestAnEmptyConditionIsRefused(t *testing.T) {
	root, _ := startApp(t)
	ctx := t.Context()
	createActiveOrFailed(t, root, "fn")
	for name, edit := range map[string]func(*lambda.AddPermissionInput){
		"PrincipalOrgID":   func(in *lambda.AddPermissionInput) { in.PrincipalOrgID = aws.String("") },
		"SourceAccount":    func(in *lambda.AddPermissionInput) { in.SourceAccount = aws.String("") },
		"SourceArn":        func(in *lambda.AddPermissionInput) { in.SourceArn = aws.String("") },
		"EventSourceToken": func(in *lambda.AddPermissionInput) { in.EventSourceToken = aws.String("") },
	} {
		in := addPermission("public", "*")
		edit(in)
		_, err := root.AddPermission(ctx, in)
		requireCode(t, name, err, "ValidationException", http.StatusBadRequest)
	}
	_, err := root.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String("fn")})
	requireCode(t, "nothing stored", err, "ResourceNotFoundException", http.StatusNotFound)
}
