//go:build e2e

package e2e

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// These tests run functions against real identity and accounts services and
// check that a function's policy is evaluated with the caller's identity
// policies, within the account and from a member account of the
// organization.

// accountsDirEnv names the accounts checkout to build, for a layout where
// it is not functions' sibling.
const accountsDirEnv = "TULE_E2E_ACCOUNTS_DIR"

// crossStack is an identity stack whose identity knows an organization
// with one member account, and an IAM client acting in that account.
type crossStack struct {
	*identityStack
	memberIAM *iam.Client
	member    string
}

// startCrossStack runs accounts with an organization of one member
// account, and identity asking it about member accounts, and reaches the
// member account through its OrganizationAccountAccessRole.
func startCrossStack(t *testing.T) *crossStack {
	t.Helper()
	root := aws.Credentials{AccessKeyID: identityRootKeyID, SecretAccessKey: identityRootSecret}
	accounts := startService(t, "accounts", accountsDirEnv, identityRootKeyID, identityRootSecret)
	oc := organizations.New(organizations.Options{
		Region:           region,
		BaseEndpoint:     aws.String(accounts.URL),
		Credentials:      credentials.StaticCredentialsProvider{Value: root},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
	_, err := oc.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	created, err := oc.CreateAccount(t.Context(), &organizations.CreateAccountInput{
		AccountName: aws.String("Member"), Email: aws.String("member@example.com"),
	})
	requireNoErr(t, err, "create account")
	st := created.CreateAccountStatus
	if st == nil || st.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("create account: %+v", st)
	}

	s := &crossStack{
		identityStack: startIdentityStack(t, "TULE_Identity_AccountsEndpoint="+accounts.URL),
		member:        aws.ToString(st.AccountId),
	}
	out, err := s.sts(root).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String(
			"arn:aws:iam::" + s.member + ":role/OrganizationAccountAccessRole",
		),
		RoleSessionName: aws.String("admin"),
	})
	requireNoErr(t, err, "assume the member account's role")
	s.memberIAM = iamClient(s.identityURL, sessionCreds(out))
	return s
}

func (s *identityStack) sts(creds aws.Credentials) *sts.Client {
	return sts.New(sts.Options{
		Region:           region,
		BaseEndpoint:     aws.String(s.identityURL),
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

func sessionCreds(out *sts.AssumeRoleOutput) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
}

// requireResourceDenied fails unless err is AccessDeniedException, 403,
// with AWS's message for principal, action and resource ending in why.
func requireResourceDenied(t *testing.T, err error, principal, action, resource, why string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDeniedException" {
		t.Fatalf("want AccessDeniedException, got %v", err)
	}
	requireStatus(t, err, http.StatusForbidden)
	requireEqual(t, apiErr.ErrorMessage(), "User: "+principal+" is not authorized to perform: "+
		action+" on resource: "+resource+" "+why, "AccessDenied message")
}

// The reasons AWS ends a denial with.
const (
	noResourceAllow = "because no resource-based policy allows the "
	noIdentityAllow = "because no identity-based policy allows the "
	resourceDeny    = "with an explicit deny in a resource-based policy"
)

// grant is AddPermission of action on the function fn to principal, as sid.
func grant(t *testing.T, c *lambda.Client, fn, sid, action, principal string) {
	t.Helper()
	_, err := c.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName: aws.String(fn), StatementId: aws.String(sid),
		Action: aws.String(action), Principal: aws.String(principal),
	})
	requireNoErr(t, err, "grant "+action+" on "+fn+" to "+principal)
}

// putFunctionPolicy replaces the function fn's policy with statements.
func putFunctionPolicy(t *testing.T, c *lambda.Client, fn, statements string) {
	t.Helper()
	_, err := c.PutResourcePolicy(t.Context(), &lambda.PutResourcePolicyInput{
		ResourceArn: aws.String(functionARN(fn)),
		Policy:      aws.String(`{"Version":"2012-10-17","Statement":[` + statements + `]}`),
	})
	requireNoErr(t, err, "put the policy of "+fn)
}

// getConfigErr is GetFunctionConfiguration of name's error.
func getConfigErr(t *testing.T, c *lambda.Client, name string) error {
	t.Helper()
	return errOf(c.GetFunctionConfiguration(t.Context(),
		&lambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}))
}

func TestAnotherAccountNeedsBothPolicies(t *testing.T) {
	s := startCrossStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "shared", "echo", nil)
	createFunction(t, root, "guarded", "echo", nil)
	key := createUserKey(t, s.memberIAM, "delegate")
	putUserPolicy(t, s.memberIAM, "delegate", "all", allowDoc(`"lambda:*"`, `"*"`))
	delegate := lambdaClientWith(s.srv, key)
	delegateARN := "arn:aws:iam::" + s.member + ":user/delegate"
	const get = "lambda:GetFunctionConfiguration"

	t.Run("denied without a resource policy", func(t *testing.T) {
		requireResourceDenied(t, getConfigErr(t, delegate, "shared"), delegateARN, get,
			functionARN("shared"), noResourceAllow+get+" action")
	})
	t.Run("allowed when the function policy grants its account", func(t *testing.T) {
		grant(t, root, "shared", "member", get, s.member)
		getConfig(t, delegate, "shared")
		invokeOut := errOf(delegate.Invoke(t.Context(),
			&lambda.InvokeInput{FunctionName: aws.String("shared")}))
		requireResourceDenied(t, invokeOut, delegateARN, "lambda:InvokeFunction",
			functionARN("shared"), noResourceAllow+"lambda:InvokeFunction action")
	})
	t.Run("denied without its own identity allow", func(t *testing.T) {
		other := lambdaClientWith(s.srv, createUserKey(t, s.memberIAM, "nopolicy"))
		requireResourceDenied(t, getConfigErr(t, other, "shared"),
			"arn:aws:iam::"+s.member+":user/nopolicy", get, functionARN("shared"),
			noIdentityAllow+get+" action")
	})
	t.Run("an explicit deny in the function policy beats both allows", func(t *testing.T) {
		putFunctionPolicy(t, root, "guarded",
			`{"Effect":"Allow","Principal":{"AWS":"`+s.member+`"},"Action":"lambda:*",`+
				`"Resource":"`+functionARN("guarded")+`"},`+
				`{"Effect":"Deny","Principal":{"AWS":"`+delegateARN+`"},"Action":"`+get+`",`+
				`"Resource":"`+functionARN("guarded")+`"}`)
		requireResourceDenied(t, getConfigErr(t, delegate, "guarded"), delegateARN, get,
			functionARN("guarded"), resourceDeny)
		_, err := delegate.GetFunction(t.Context(),
			&lambda.GetFunctionInput{FunctionName: aws.String("guarded")})
		requireNoErr(t, err, "an action the deny does not name")
	})
}

func TestAFunctionPolicyWithinTheAccount(t *testing.T) {
	s := startIdentityStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "fn", "echo", nil)
	const get = "lambda:GetFunctionConfiguration"

	t.Run("a user named by the policy needs no identity policy", func(t *testing.T) {
		c := s.policyUser(t, "named")
		requireResourceDenied(
			t,
			errOf(c.Invoke(t.Context(),
				&lambda.InvokeInput{FunctionName: aws.String("fn")})),
			userARN("named"),
			"lambda:InvokeFunction",
			functionARN("fn"),
			noIdentityAllow+"lambda:InvokeFunction action",
		)
		grant(t, root, "fn", "named", "lambda:InvokeFunction", userARN("named"))
		invokeOK(t, c, "fn", map[string]string{"who": "named"}, nil)
	})
	t.Run("a grant to the account needs an identity allow", func(t *testing.T) {
		grant(t, root, "fn", "account", get, defaultAccountID)
		without := s.policyUser(t, "accountonly")
		requireResourceDenied(t, getConfigErr(t, without, "fn"), userARN("accountonly"), get,
			functionARN("fn"), noIdentityAllow+get+" action")
		with := s.policyUser(t, "accountandidentity", allowDoc(`"`+get+`"`, `"*"`))
		getConfig(t, with, "fn")
	})
	t.Run("an explicit deny in the policy beats an identity allow", func(t *testing.T) {
		c := s.policyUser(t, "denied", allowDoc(`"lambda:*"`, `"*"`))
		getConfig(t, c, "fn")
		putFunctionPolicy(t, root, "fn", `{"Effect":"Deny","Principal":{"AWS":"`+
			userARN("denied")+`"},"Action":"`+get+`","Resource":"`+functionARN("fn")+`"}`)
		requireResourceDenied(t, getConfigErr(t, c, "fn"), userARN("denied"), get,
			functionARN("fn"), resourceDeny)
	})
	t.Run("the root key is never evaluated", func(t *testing.T) {
		putFunctionPolicy(t, root, "fn", `{"Effect":"Deny","Principal":"*","Action":"*",`+
			`"Resource":"`+functionARN("fn")+`"}`)
		getConfig(t, root, "fn")
		_, err := root.GetPolicy(
			t.Context(),
			&lambda.GetPolicyInput{FunctionName: aws.String("fn")},
		)
		requireNoErr(t, err, "get the policy as root")
	})
}

// TestAFunctionPolicyMatchesARoleWithItsPath grants a role at a path by its
// ARN, and conditions a grant on aws:PrincipalArn with the path: a session
// of the role matches both, and a session of a role of the same name at
// another path matches neither.
func TestAFunctionPolicyMatchesARoleWithItsPath(t *testing.T) {
	s := startIdentityStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "fn", "echo", nil)
	key := createUserKey(t, s.iam, "assumer")
	trust := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + userARN("assumer") + `"},"Action":"sts:AssumeRole"}}`
	session := func(name, path string) *lambda.Client {
		_, err := s.iam.CreateRole(t.Context(), &iam.CreateRoleInput{
			RoleName: aws.String(name), Path: aws.String(path),
			AssumeRolePolicyDocument: aws.String(trust),
		})
		requireNoErr(t, err, "create role "+name)
		out, err := s.sts(key).AssumeRole(t.Context(), &sts.AssumeRoleInput{
			RoleArn:         aws.String("arn:aws:iam::" + defaultAccountID + ":role" + path + name),
			RoleSessionName: aws.String("s1"),
		})
		requireNoErr(t, err, "assume "+name)
		return lambdaClientWith(s.srv, sessionCreds(out))
	}
	pathed := session("runner", "/team/")
	other := session("walker", "/other/")
	fn := functionARN("fn")
	putFunctionPolicy(t, root, "fn",
		`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::`+defaultAccountID+
			`:role/team/runner"},"Action":"lambda:GetFunctionConfiguration","Resource":"`+fn+`"},`+
			`{"Effect":"Allow","Principal":"*","Action":"lambda:GetFunction","Resource":"`+fn+
			`","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/team/*"}}}`)

	getConfig(t, pathed, "fn")
	_, err := pathed.GetFunction(
		t.Context(),
		&lambda.GetFunctionInput{FunctionName: aws.String("fn")},
	)
	requireNoErr(t, err, "GetFunction by aws:PrincipalArn with the path")
	otherARN := "arn:aws:sts::" + defaultAccountID + ":assumed-role/walker/s1"
	requireResourceDenied(
		t,
		getConfigErr(t, other, "fn"),
		otherARN,
		"lambda:GetFunctionConfiguration",
		fn,
		noIdentityAllow+"lambda:GetFunctionConfiguration action",
	)
	requireResourceDenied(t, errOf(other.GetFunction(t.Context(),
		&lambda.GetFunctionInput{FunctionName: aws.String("fn")})), otherARN,
		"lambda:GetFunction", fn, noIdentityAllow+"lambda:GetFunction action")
}

// TestAFunctionPolicyConditionOnAPrincipalTag grants ListTags to every
// principal tagged team=a: a user so tagged is allowed, one tagged
// otherwise is not.
func TestAFunctionPolicyConditionOnAPrincipalTag(t *testing.T) {
	s := startIdentityStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "fn", "echo", nil)
	fn := functionARN("fn")
	putFunctionPolicy(
		t,
		root,
		"fn",
		`{"Effect":"Allow","Principal":"*","Action":"lambda:ListTags",`+
			`"Resource":"`+fn+`","Condition":{"StringEquals":{"aws:PrincipalTag/team":"a"}}}`,
	)
	tagged := func(name, team string) *lambda.Client {
		_, err := s.iam.CreateUser(t.Context(), &iam.CreateUserInput{
			UserName: aws.String(name),
			Tags:     []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String(team)}},
		})
		requireNoErr(t, err, "create user "+name)
		out, err := s.iam.CreateAccessKey(t.Context(),
			&iam.CreateAccessKeyInput{UserName: aws.String(name)})
		requireNoErr(t, err, "create a key for "+name)
		return lambdaClientWith(s.srv, aws.Credentials{
			AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
			SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
		})
	}
	_, err := tagged(
		"ateam",
		"a",
	).ListTags(t.Context(), &lambda.ListTagsInput{Resource: aws.String(fn)})
	requireNoErr(t, err, "ListTags as team a")
	requireResourceDenied(t, errOf(tagged("bteam", "b").ListTags(t.Context(),
		&lambda.ListTagsInput{Resource: aws.String(fn)})), userARN("bteam"), "lambda:ListTags", fn,
		noIdentityAllow+"lambda:ListTags action")
}

// TestStandaloneServesTheFunctionPolicy checks the policy operations with
// the static key, which is root and never evaluated.
func TestStandaloneServesTheFunctionPolicy(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "solo", "echo", nil)
	grant(t, c, "solo", "everyone", "lambda:InvokeFunction", "*")
	out, err := c.GetPolicy(t.Context(), &lambda.GetPolicyInput{FunctionName: aws.String("solo")})
	requireNoErr(t, err, "get the policy")
	requireContains(t, aws.ToString(out.Policy), `"Sid":"everyone"`, "the policy")
	putFunctionPolicy(t, c, "solo", `{"Effect":"Deny","Principal":"*","Action":"*",`+
		`"Resource":"`+functionARN("solo")+`"}`)
	invokeOK(t, c, "solo", map[string]string{"who": "solo"}, nil)
	deleteFunction(t, c, "solo")
}
