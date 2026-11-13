//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

// These tests run functions against a real identity service: identity is
// built from its checkout and run as a process with the same root key, and
// functions is pointed at it through TULE_Auth_IdentityEndpoint.

// identityDirEnv names the identity checkout to build, for a layout where it
// is not functions' sibling.
const identityDirEnv = "TULE_E2E_IDENTITY_DIR"

// The root key both services are configured with: the AWS documentation's
// example key, since identity holds an access key ID to at least 16
// characters.
const (
	identityRootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	identityRootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

type identityStack struct {
	srv       *server
	iam       *iam.Client
	rootCreds aws.Credentials
}

func TestIdentityIssuedKeys(t *testing.T) {
	s := startIdentityStack(t)
	userKey := createUserKey(t, s.iam, "dev")

	t.Run("a user key works", func(t *testing.T) {
		c := lambdaClientWith(s.srv, userKey)
		createFunction(t, c, "from-user", "echo", nil)
		invokeOK(t, c, "from-user", map[string]string{"who": "user"}, nil)
		requireOK(
			t,
			historyWith(s.srv, userKey).do(t, http.MethodGet, "/_functions/invocations", nil),
			"retrieval with the user key",
		)
	})
	t.Run("the root key keeps working", func(t *testing.T) {
		getConfig(t, lambdaClientWith(s.srv, s.rootCreds), "from-user")
	})
	t.Run("an inactive key is refused", s.testInactiveKey)
	t.Run("a deleted key is refused", s.testDeletedKey)
}

func startIdentityStack(t *testing.T) *identityStack {
	t.Helper()
	identity := startService(t, "identity", identityDirEnv, identityRootKeyID, identityRootSecret)
	s := &identityStack{
		rootCreds: aws.Credentials{
			AccessKeyID:     identityRootKeyID,
			SecretAccessKey: identityRootSecret,
		},
	}
	s.srv = startServer(t, map[string]string{
		"TULE_Auth_AccessKeyID":      identityRootKeyID,
		"TULE_Auth_SecretAccessKey":  identityRootSecret,
		"TULE_Auth_IdentityEndpoint": identity.URL,
	})
	s.iam = iamClient(identity.URL, s.rootCreds)
	return s
}

func (s *identityStack) testInactiveKey(t *testing.T) {
	key := createUserKey(t, s.iam, "inactive")
	_, err := s.iam.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
		UserName:    aws.String("inactive"),
		AccessKeyId: aws.String(key.AccessKeyID),
		Status:      iamtypes.StatusTypeInactive,
	})
	requireNoErr(t, err, "deactivate the key")
	s.requireRefused(t, key)
}

func (s *identityStack) testDeletedKey(t *testing.T) {
	key := createUserKey(t, s.iam, "deleted")
	_, err := lambdaClientWith(s.srv, key).ListFunctions(t.Context(), &lambda.ListFunctionsInput{})
	requireNoErr(t, err, "list functions before the key is deleted")

	_, err = s.iam.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName:    aws.String("deleted"),
		AccessKeyId: aws.String(key.AccessKeyID),
	})
	requireNoErr(t, err, "delete the key")
	s.requireRefused(t, key)
}

// requireRefused fails unless both the Lambda API and the retrieval API
// refuse key with 403, and the refused call created nothing. The code is
// not asserted, as mailbox's REST-JSON API does not assert it.
func (s *identityStack) requireRefused(t *testing.T, key aws.Credentials) {
	t.Helper()

	err := errOf(lambdaClientWith(s.srv, key).CreateFunction(t.Context(),
		createInput("refused", "echo")))
	requireAPIError(t, err)
	requireStatus(t, err, http.StatusForbidden)
	_, err = lambdaClientWith(s.srv, s.rootCreds).GetFunction(t.Context(),
		&lambda.GetFunctionInput{FunctionName: aws.String("refused")})
	if err == nil {
		t.Fatal("the refused CreateFunction created the function")
	}

	requireAPIErrorBody(
		t,
		historyWith(s.srv, key).do(t, http.MethodGet, "/_functions/invocations", nil),
		http.StatusForbidden,
		"retrieval with a refused key",
	)
}

func iamClient(url string, creds aws.Credentials) *iam.Client {
	return iam.New(iam.Options{
		Region:           region,
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

// createUserKey creates an IAM user and an access key for it.
func createUserKey(t *testing.T, ic *iam.Client, user string) aws.Credentials {
	t.Helper()
	_, err := ic.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "create user "+user)
	out, err := ic.CreateAccessKey(
		t.Context(),
		&iam.CreateAccessKeyInput{UserName: aws.String(user)},
	)
	requireNoErr(t, err, "create access key for "+user)
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
	}
}
