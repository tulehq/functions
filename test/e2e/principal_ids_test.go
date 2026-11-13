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
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// These tests check, against real identity and accounts services, that a
// function policy names its IAM principals by their unique IDs, as AWS
// saves it, and that the organization keys are evaluated.

// functionPolicies are the function fn's policy as GetPolicy and
// GetResourcePolicy answer it.
func functionPolicies(t *testing.T, c *lambda.Client, fn string) map[string]string {
	t.Helper()
	got, err := c.GetPolicy(t.Context(), &lambda.GetPolicyInput{FunctionName: aws.String(fn)})
	requireNoErr(t, err, "GetPolicy of "+fn)
	whole, err := c.GetResourcePolicy(t.Context(),
		&lambda.GetResourcePolicyInput{ResourceArn: aws.String(functionARN(fn))})
	requireNoErr(t, err, "GetResourcePolicy of "+fn)
	return map[string]string{
		"GetPolicy":         aws.ToString(got.Policy),
		"GetResourcePolicy": aws.ToString(whole.Policy),
	}
}

// requirePolicyNames fails unless every read of fn's policy names want as a
// principal and never gone.
func requirePolicyNames(t *testing.T, c *lambda.Client, fn, want, gone string) {
	t.Helper()
	for op, doc := range functionPolicies(t, c, fn) {
		if !strings.Contains(doc, `"`+want+`"`) || strings.Contains(doc, `"`+gone+`"`) {
			t.Fatalf("%s of %s: %s, want %s and not %s", op, fn, doc, want, gone)
		}
	}
}

// deleteUser deletes the IAM user name and its one access key.
func deleteUser(t *testing.T, ic *iam.Client, name string, key aws.Credentials) {
	t.Helper()
	_, err := ic.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName: aws.String(name), AccessKeyId: aws.String(key.AccessKeyID),
	})
	requireNoErr(t, err, "delete the key of "+name)
	_, err = ic.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String(name)})
	requireNoErr(t, err, "delete user "+name)
}

// TestARecreatedUserDoesNotInheritAGrant grants a user by AddPermission on
// one function and by PutResourcePolicy on another, deletes the user and
// creates it again under the same name: the new user is denied, and the
// policies then name the old user's unique ID, where they named its ARN
// while it existed.
func TestARecreatedUserDoesNotInheritAGrant(t *testing.T) {
	s := startIdentityStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "added", "echo", nil)
	createFunction(t, root, "put", "echo", nil)
	const get = "lambda:GetFunctionConfiguration"
	arn := userARN("heir")
	key := createUserKey(t, s.iam, "heir")
	user, err := s.iam.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("heir")})
	requireNoErr(t, err, "get user heir")
	oldID := aws.ToString(user.User.UserId)

	grant(t, root, "added", "heir", get, arn)
	putFunctionPolicy(t, root, "put", `{"Sid":"heir","Effect":"Allow","Principal":{"AWS":"`+
		arn+`"},"Action":"`+get+`","Resource":"`+functionARN("put")+`"}`)
	old := lambdaClientWith(s.srv, key)
	for _, fn := range []string{"added", "put"} {
		getConfig(t, old, fn)
		requirePolicyNames(t, root, fn, arn, oldID)
	}

	deleteUser(t, s.iam, "heir", key)
	heir := lambdaClientWith(s.srv, createUserKey(t, s.iam, "heir"))
	for _, fn := range []string{"added", "put"} {
		requireResourceDenied(t, getConfigErr(t, heir, fn), arn, get, functionARN(fn),
			noIdentityAllow+get+" action")
		requirePolicyNames(t, root, fn, oldID, arn)
	}
}

// requireInvalidParameter fails unless err is InvalidParameterValueException,
// 400, with the message msg.
func requireInvalidParameter(t *testing.T, err error, msg, what string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "InvalidParameterValueException" {
		t.Fatalf("%s: want InvalidParameterValueException, got %v", what, err)
	}
	requireStatus(t, err, http.StatusBadRequest)
	requireEqual(t, apiErr.ErrorMessage(), msg, what)
}

// TestAPolicyNamingNoUserIsRefused names a user that does not exist, by
// AddPermission and PutResourcePolicy: both are refused and nothing is
// stored.
func TestAPolicyNamingNoUserIsRefused(t *testing.T) {
	s := startIdentityStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "fn", "echo", nil)
	createUserKey(t, s.iam, "real")
	nobody := userARN("nobody")

	_, err := root.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName: aws.String("fn"), StatementId: aws.String("nobody"),
		Action: aws.String("lambda:InvokeFunction"), Principal: aws.String(nobody),
	})
	requireInvalidParameter(t, err,
		"The provided principal was invalid. Please check the principal and try again.",
		"AddPermission")
	_, err = root.PutResourcePolicy(t.Context(), &lambda.PutResourcePolicyInput{
		ResourceArn: aws.String(functionARN("fn")),
		Policy: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":["` + userARN("real") + `","` + nobody + `"]},` +
			`"Action":"lambda:InvokeFunction","Resource":"` + functionARN("fn") + `"}}`),
	})
	requireInvalidParameter(t, err,
		"The provided principal was invalid. Please check the principal and try again.",
		"PutResourcePolicy")
	_, err = root.GetPolicy(t.Context(), &lambda.GetPolicyInput{FunctionName: aws.String("fn")})
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "ResourceNotFoundException" {
		t.Fatalf("a refused policy was stored: %v", err)
	}
}

// orgStack is an identity stack whose identity knows an organization with
// two member accounts, one of them removed from the organization after a
// session of it was issued.
type orgStack struct {
	*identityStack
	member, removed     aws.Credentials
	memberID, removedID string
	orgID, rootID       string
	removedARN          string
}

// orgClient is an Organizations client of accounts with the root key.
func orgClient(url string) *organizations.Client {
	return organizations.New(organizations.Options{
		Region:       region,
		BaseEndpoint: aws.String(url),
		Credentials: credentials.StaticCredentialsProvider{Value: aws.Credentials{
			AccessKeyID: identityRootKeyID, SecretAccessKey: identityRootSecret,
		}},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

// createMember creates the member account name and returns its ID.
func createMember(t *testing.T, oc *organizations.Client, name string) string {
	t.Helper()
	created, err := oc.CreateAccount(t.Context(), &organizations.CreateAccountInput{
		AccountName: aws.String(name), Email: aws.String(name + "@example.com"),
	})
	requireNoErr(t, err, "create account "+name)
	st := created.CreateAccountStatus
	if st == nil || st.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("create account %s: %+v", name, st)
	}
	return aws.ToString(st.AccountId)
}

// startOrgStack runs accounts with an organization of two member accounts
// and identity asking it, takes a session of each member account's
// OrganizationAccountAccessRole, and then removes the second account from
// the organization. The removed account's principals sign nothing before
// it is removed, so identity has no organization keys of it to keep.
func startOrgStack(t *testing.T) *orgStack {
	t.Helper()
	accounts := startService(t, "accounts", accountsDirEnv, identityRootKeyID, identityRootSecret)
	oc := orgClient(accounts.URL)
	org, err := oc.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	roots, err := oc.ListRoots(t.Context(), &organizations.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	if len(roots.Roots) != 1 {
		t.Fatalf("roots: %+v", roots.Roots)
	}
	s := &orgStack{
		identityStack: startIdentityStack(t, "TULE_Identity_AccountsEndpoint="+accounts.URL),
		memberID:      createMember(t, oc, "member"),
		removedID:     createMember(t, oc, "removed"),
		orgID:         aws.ToString(org.Organization.Id),
		rootID:        aws.ToString(roots.Roots[0].Id),
	}
	session := func(account string) aws.Credentials {
		out, aErr := s.sts(s.rootCreds).AssumeRole(t.Context(), &sts.AssumeRoleInput{
			RoleArn: aws.String(
				"arn:aws:iam::" + account + ":role/OrganizationAccountAccessRole"),
			RoleSessionName: aws.String("admin"),
		})
		requireNoErr(t, aErr, "assume the role of account "+account)
		return sessionCreds(out)
	}
	s.member = session(s.memberID)
	s.removed = session(s.removedID)
	s.removedARN = "arn:aws:sts::" + s.removedID +
		":assumed-role/OrganizationAccountAccessRole/admin"
	_, err = oc.RemoveAccountFromOrganization(t.Context(),
		&organizations.RemoveAccountFromOrganizationInput{AccountId: aws.String(s.removedID)})
	requireNoErr(t, err, "remove account "+s.removedID)
	return s
}

// TestOrganizationConditionsInAFunctionPolicy grants GetFunctionConfiguration
// to every principal of the organization, by AddPermission's
// PrincipalOrgID on one function and by aws:PrincipalOrgPaths in a policy
// put on another: a member account's session is allowed, and a session of
// an account removed from the organization is refused.
func TestOrganizationConditionsInAFunctionPolicy(t *testing.T) {
	s := startOrgStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "byid", "echo", nil)
	createFunction(t, root, "bypath", "echo", nil)
	const get = "lambda:GetFunctionConfiguration"

	_, err := root.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName: aws.String("byid"), StatementId: aws.String("org"),
		Action: aws.String(get), Principal: aws.String("*"),
		PrincipalOrgID: aws.String(s.orgID),
	})
	requireNoErr(t, err, "grant the organization by PrincipalOrgID")
	putFunctionPolicy(t, root, "bypath", `{"Effect":"Allow","Principal":"*","Action":"`+get+
		`","Resource":"`+functionARN("bypath")+`","Condition":{"ForAnyValue:StringLike":`+
		`{"aws:PrincipalOrgPaths":"`+s.orgID+`/`+s.rootID+`/*"}}}`)

	member := lambdaClientWith(s.srv, s.member)
	removed := lambdaClientWith(s.srv, s.removed)
	for _, fn := range []string{"byid", "bypath"} {
		t.Run(fn, func(t *testing.T) {
			getConfig(t, member, fn)
			requireResourceDenied(t, getConfigErr(t, removed, fn), s.removedARN, get,
				functionARN(fn), noResourceAllow+get+" action")
		})
	}
}
