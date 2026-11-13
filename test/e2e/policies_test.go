//go:build e2e

package e2e

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// These tests run functions against the real identity service, as
// identity_test.go does, and check that identity-issued keys are held to
// their identity policies on every operation while the root key is not.

// userARN is the ARN of the IAM user name, in identity's default account.
func userARN(name string) string {
	return "arn:aws:iam::" + defaultAccountID + ":user/" + name
}

// allowDoc is an identity policy allowing actions on resources.
func allowDoc(actions, resources string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":` + actions +
		`,"Resource":` + resources + `}}`
}

// putUserPolicy gives the IAM user an inline identity policy.
func putUserPolicy(t *testing.T, ic *iam.Client, user, name, doc string) {
	t.Helper()
	_, err := ic.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName:       aws.String(user),
		PolicyName:     aws.String(name),
		PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "put policy "+name+" on "+user)
}

// policyUser creates an IAM user with the inline policies docs, and returns
// a Lambda client signing with its key.
func (s *identityStack) policyUser(t *testing.T, name string, docs ...string) *lambda.Client {
	t.Helper()
	key := createUserKey(t, s.iam, name)
	for i, doc := range docs {
		putUserPolicy(t, s.iam, name, "p"+string(rune('a'+i)), doc)
	}
	return lambdaClientWith(s.srv, key)
}

// requireAccessDenied fails unless err is Lambda's AccessDeniedException,
// 403, with AWS's message for principal, action and resource: an implicit
// deny unless explicit.
func requireAccessDenied(
	t *testing.T,
	err error,
	principal, action, resource string,
	explicit bool,
) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDeniedException" {
		t.Fatalf("want AccessDeniedException, got %v", err)
	}
	requireStatus(t, err, http.StatusForbidden)
	why := "because no identity-based policy allows the " + action + " action"
	if explicit {
		why = "with an explicit deny in an identity-based policy"
	}
	requireEqual(t, apiErr.ErrorMessage(), "User: "+principal+" is not authorized to perform: "+
		action+" on resource: "+resource+" "+why, "AccessDenied message")
}

func TestPolicies(t *testing.T) {
	s := startIdentityStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "alpha", "echo", func(in *lambda.CreateFunctionInput) {
		in.Tags = map[string]string{"team": "a"}
	})
	createFunction(t, root, "beta", "echo", nil)

	t.Run("a key with no policy is denied", func(t *testing.T) {
		c := s.policyUser(t, "nopolicy")
		requireAccessDenied(t, errOf(c.GetFunction(t.Context(),
			&lambda.GetFunctionInput{FunctionName: aws.String("alpha")})),
			userARN("nopolicy"), "lambda:GetFunction", functionARN("alpha"), false)
		key := createUserKey(t, s.iam, "nopolicy-history")
		res := historyWith(s.srv, key).do(t, http.MethodGet, "/_functions/invocations", nil)
		requireEqual(t, res.Status, http.StatusForbidden, "retrieval without tule:Inspect")
		requireContains(t, string(res.Body), "tule:Inspect", "retrieval denial")
	})
	t.Run("one allowed action allows exactly that", func(t *testing.T) {
		c := s.policyUser(t, "oneaction", allowDoc(`"lambda:GetFunctionConfiguration"`, `"*"`))
		getConfig(t, c, "alpha")
		requireAccessDenied(t, errOf(c.GetFunction(t.Context(),
			&lambda.GetFunctionInput{FunctionName: aws.String("alpha")})),
			userARN("oneaction"), "lambda:GetFunction", functionARN("alpha"), false)
		requireAccessDenied(t, errOf(c.ListFunctions(t.Context(), &lambda.ListFunctionsInput{})),
			userARN("oneaction"), "lambda:ListFunctions", "*", false)
	})
	t.Run("a resource-scoped policy allows one function", func(t *testing.T) {
		c := s.policyUser(t, "scoped",
			allowDoc(`"lambda:InvokeFunction"`, `"`+functionARN("alpha")+`"`))
		invokeOK(t, c, "alpha", map[string]string{"who": "scoped"}, nil)
		requireAccessDenied(t, errOf(c.Invoke(t.Context(),
			&lambda.InvokeInput{FunctionName: aws.String("beta")})),
			userARN("scoped"), "lambda:InvokeFunction", functionARN("beta"), false)
	})
	t.Run("an explicit deny beats an allow", func(t *testing.T) {
		deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny",` +
			`"Action":"lambda:DeleteFunction","Resource":"*"}}`
		c := s.policyUser(t, "denied", allowDoc(`"lambda:*"`, `"*"`), deny)
		getConfig(t, c, "beta")
		requireAccessDenied(t, errOf(c.DeleteFunction(t.Context(),
			&lambda.DeleteFunctionInput{FunctionName: aws.String("beta")})),
			userARN("denied"), "lambda:DeleteFunction", functionARN("beta"), true)
		getConfig(t, root, "beta")
	})
	t.Run("conditions are honored", s.testConditions)
	t.Run("iam:PassRole is needed to create", s.testPassRole)
	t.Run("a role session has its role's permissions", s.testRoleSession)
	t.Run("the root key is always allowed", func(t *testing.T) {
		getConfig(t, root, "alpha")
		requireOK(t, historyWith(s.srv, s.rootCreds).do(t, http.MethodGet,
			"/_functions/invocations", nil), "retrieval with the root key")
	})
}

// testConditions checks aws:SourceIp, which is 127.0.0.1 for these clients,
// and aws:ResourceTag from the function's tags.
func (s *identityStack) testConditions(t *testing.T) {
	cond := func(op, key, value string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Action":"lambda:GetFunctionConfiguration","Resource":"*",` +
			`"Condition":{"` + op + `":{"` + key + `":"` + value + `"}}}}`
	}
	local := s.policyUser(t, "local", cond("IpAddress", "aws:SourceIp", "127.0.0.0/8"))
	getConfig(t, local, "alpha")
	remote := s.policyUser(t, "remote", cond("IpAddress", "aws:SourceIp", "203.0.113.0/24"))
	requireAccessDenied(t, errOf(remote.GetFunctionConfiguration(t.Context(),
		&lambda.GetFunctionConfigurationInput{FunctionName: aws.String("alpha")})),
		userARN("remote"), "lambda:GetFunctionConfiguration", functionARN("alpha"), false)

	team := s.policyUser(t, "team", cond("StringEquals", "aws:ResourceTag/team", "a"))
	getConfig(t, team, "alpha")
	requireAccessDenied(t, errOf(team.GetFunctionConfiguration(t.Context(),
		&lambda.GetFunctionConfigurationInput{FunctionName: aws.String("beta")})),
		userARN("team"), "lambda:GetFunctionConfiguration", functionARN("beta"), false)
}

// testPassRole checks that CreateFunction needs iam:PassRole on the
// function's execution role besides lambda:CreateFunction.
func (s *identityStack) testPassRole(t *testing.T) {
	create := allowDoc(`["lambda:CreateFunction","lambda:GetFunction"]`, `"*"`)
	without := s.policyUser(t, "nopass", create)
	requireAccessDenied(t, errOf(without.CreateFunction(t.Context(),
		createInput("passless", "echo"))),
		userARN("nopass"), "iam:PassRole", role, false)

	pass := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:PassRole",` +
		`"Resource":"` + role + `","Condition":{"StringEquals":` +
		`{"iam:PassedToService":"lambda.amazonaws.com"}}}}`
	with := s.policyUser(t, "pass", create, pass)
	createFunction(t, with, "passed", "echo", nil)
}

// testRoleSession creates a role the user is trusted to assume, with a
// policy allowing ListFunctions, and checks the session has exactly that.
func (s *identityStack) testRoleSession(t *testing.T) {
	key := createUserKey(t, s.iam, "assumer")
	trust := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + userARN("assumer") + `"},"Action":"sts:AssumeRole"}}`
	_, err := s.iam.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("lister"),
		AssumeRolePolicyDocument: aws.String(trust),
	})
	requireNoErr(t, err, "create role")
	_, err = s.iam.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName:       aws.String("lister"),
		PolicyName:     aws.String("list"),
		PolicyDocument: aws.String(allowDoc(`"lambda:ListFunctions"`, `"*"`)),
	})
	requireNoErr(t, err, "put role policy")

	out, err := sts.New(sts.Options{
		Region:           region,
		BaseEndpoint:     aws.String(s.identityURL),
		Credentials:      credentials.StaticCredentialsProvider{Value: key},
		RetryMaxAttempts: 1,
	}).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::" + defaultAccountID + ":role/lister"),
		RoleSessionName: aws.String("s1"),
	})
	requireNoErr(t, err, "assume role")
	session := lambdaClientWith(s.srv, aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	})
	_, err = session.ListFunctions(t.Context(), &lambda.ListFunctionsInput{})
	requireNoErr(t, err, "list functions as the role")
	requireAccessDenied(t, errOf(session.GetFunction(t.Context(),
		&lambda.GetFunctionInput{FunctionName: aws.String("alpha")})),
		aws.ToString(out.AssumedRoleUser.Arn), "lambda:GetFunction", functionARN("alpha"), false)
	if !strings.HasPrefix(aws.ToString(out.AssumedRoleUser.Arn), "arn:aws:sts::") {
		t.Fatalf("session ARN %s", aws.ToString(out.AssumedRoleUser.Arn))
	}
}

// TestStandaloneEvaluatesNothing runs functions without an identity
// endpoint: its static key is root, and may call every operation and the
// retrieval API.
func TestStandaloneEvaluatesNothing(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "solo", "echo", func(in *lambda.CreateFunctionInput) {
		in.Tags = map[string]string{"k": "v"}
	})
	invokeOK(t, c, "solo", map[string]string{"who": "solo"}, nil)
	_, err := c.TagResource(t.Context(), &lambda.TagResourceInput{
		Resource: aws.String(functionARN("solo")), Tags: map[string]string{"k2": "v"},
	})
	requireNoErr(t, err, "tag")
	requireOK(t, historyFor(srv).do(t, http.MethodGet, "/_functions/invocations", nil),
		"retrieval with the static key")
	deleteFunction(t, c, "solo")
}
