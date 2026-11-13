//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// These tests run functions with their execution roles' credentials, the
// default with an identity endpoint: identity assumes each function's role
// as lambda.amazonaws.com, and the function's SDK, inside its container,
// calls object-store with the session, which object-store holds to the
// role's policies.

// objectStoreDirEnv names the object-store checkout to build, for a layout
// where it is not functions' sibling.
const objectStoreDirEnv = "TULE_E2E_OBJECT_STORE_DIR"

// s3Result is what the s3put function answers: the error its put met.
type s3Result struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func TestAFunctionRunsWithItsRolesCredentials(t *testing.T) {
	s := startIdentityStack(t)
	store := startService(t, "object-store", objectStoreDirEnv, identityRootKeyID,
		identityRootSecret, "TULE_Auth_IdentityEndpoint="+s.identityURL,
		"TULE_Storage_Buckets=allowed,other")
	createRole(t, s.iam, "writer", lambdaTrust, allowDoc(`"s3:PutObject"`,
		`"arn:aws:s3:::allowed/*"`))

	root := lambdaClientWith(s.srv, s.rootCreds)
	endpoint := strings.Replace(store.URL, "127.0.0.1", "host.docker.internal", 1)
	createFunction(t, root, "writer", "s3put", func(in *lambda.CreateFunctionInput) {
		in.Role = aws.String(roleARN("writer"))
		in.Environment = &types.Environment{Variables: map[string]string{
			"AWS_ENDPOINT_URL_S3": endpoint,
		}}
	})

	var r s3Result
	invokeOK(t, root, "writer",
		map[string]string{"bucket": "allowed", "key": "k", "body": "from the role"}, &r)
	if r.Code != "" {
		t.Fatalf("the put to the allowed bucket failed: %+v", r)
	}
	requireObject(t, store.URL, s.rootCreds, "allowed", "k", "from the role")

	r = s3Result{}
	invokeOK(t, root, "writer",
		map[string]string{"bucket": "other", "key": "k", "body": "denied"}, &r)
	requireEqual(t, r.Code, "AccessDenied", "the put to the other bucket")
	// The session is the role's, named after the function, as Lambda names
	// its sessions of an execution role.
	requireContains(t, r.Message, "assumed-role/writer/writer", "the denial's principal")

	// A new Role takes effect at once: the warm container, with the old
	// role's session, is replaced by one with the new role's.
	createRole(t, s.iam, "other-writer", lambdaTrust, allowDoc(`"s3:PutObject"`,
		`"arn:aws:s3:::other/*"`))
	_, err := root.UpdateFunctionConfiguration(
		t.Context(),
		&lambda.UpdateFunctionConfigurationInput{
			FunctionName: aws.String("writer"), Role: aws.String(roleARN("other-writer")),
		},
	)
	requireNoErr(t, err, "change the function's role")
	waitUpdated(t, root, "writer")
	r = s3Result{}
	invokeOK(t, root, "writer",
		map[string]string{"bucket": "other", "key": "k", "body": "the new role"}, &r)
	if r.Code != "" {
		t.Fatalf("the put with the new role failed: %+v", r)
	}
	requireObject(t, store.URL, s.rootCreds, "other", "k", "the new role")
	r = s3Result{}
	invokeOK(t, root, "writer",
		map[string]string{"bucket": "allowed", "key": "k2", "body": "the old role"}, &r)
	requireEqual(t, r.Code, "AccessDenied", "the put the old role allowed")
}

// requireObject fails unless bucket holds key with body, read with creds.
func requireObject(t *testing.T, url string, creds aws.Credentials, bucket, key, body string) {
	t.Helper()
	c := s3.New(s3.Options{
		Region:           region,
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		UsePathStyle:     true,
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
	out, err := c.GetObject(t.Context(), &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	requireNoErr(t, err, "get "+bucket+"/"+key)
	defer func() { _ = out.Body.Close() }()
	got, err := io.ReadAll(out.Body)
	requireNoErr(t, err, "read "+bucket+"/"+key)
	requireEqual(t, string(got), body, bucket+"/"+key)
}

func TestARoleLambdaCannotAssumeIsRefused(t *testing.T) {
	s := startIdentityStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createRole(t, s.iam, "not-lambdas", `{"Version":"2012-10-17","Statement":[{"Effect":`+
		`"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, "")
	for _, role := range []string{"missing", "not-lambdas"} {
		in := createInput("refused-"+role, "echo")
		in.Role = aws.String(roleARN(role))
		err := errOf(root.CreateFunction(t.Context(), in))
		requireModeled[*types.InvalidParameterValueException](t, err)
		requireContains(t, err.Error(),
			"The role defined for the function cannot be assumed by Lambda.", "the refusal")
	}
}

func TestAMappingPollsWithItsFunctionsRole(t *testing.T) {
	s := startIdentityStack(t)
	queues := startService(t, "queues", queuesDirEnv, identityRootKeyID, identityRootSecret,
		"TULE_Auth_IdentityEndpoint="+s.identityURL)
	srv := startServer(t, map[string]string{
		"TULE_Auth_AccessKeyID":         identityRootKeyID,
		"TULE_Auth_SecretAccessKey":     identityRootSecret,
		"TULE_Auth_IdentityEndpoint":    s.identityURL,
		"TULE_Functions_QueuesEndpoint": queues.URL,
	})
	ms := &mappingStack{
		srv:    srv,
		lambda: lambdaClientWith(srv, s.rootCreds),
		h:      historyWith(srv, s.rootCreds),
		sqs: sqs.New(sqs.Options{
			Region:           region,
			BaseEndpoint:     aws.String(queues.URL),
			Credentials:      credentials.StaticCredentialsProvider{Value: s.rootCreds},
			HTTPClient:       &http.Client{Timeout: clientTimeout},
			RetryMaxAttempts: 1,
		}),
	}
	// The actions of AWSLambdaSQSQueueExecutionRole, the managed policy the
	// Lambda Developer Guide gives a mapping's role, and sqs:GetQueueUrl,
	// with which the poller finds the queue.
	poll := func(actions string) string {
		return allowDoc(`["sqs:GetQueueUrl",`+actions+`]`, `"*"`)
	}
	full := poll(`"sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes"`)
	createRole(t, s.iam, "poller", lambdaTrust, full)
	createRole(t, s.iam, "revoked", lambdaTrust, full)
	createRole(t, s.iam, "deaf", lambdaTrust, poll(`"sqs:DeleteMessage","sqs:GetQueueAttributes"`))
	q := ms.createQueue(t, "orders", nil)
	unheard := ms.createQueue(t, "unheard", nil)
	for _, fn := range []string{"poller", "revoked", "deaf"} {
		createFunction(t, ms.lambda, fn, "sqs", func(in *lambda.CreateFunctionInput) {
			in.Role = aws.String(roleARN(fn))
		})
	}

	ms.mapping(t, q, "poller", nil)
	ms.waitDelivered(t, "poller", ms.sendBody(t, q, "hello"))

	// A role without sqs:ReceiveMessage can be mapped, since the mapping
	// only reads the queue's attributes when it is made, but its poller is
	// refused every receive, so nothing is delivered.
	ms.mapping(t, unheard, "deaf", nil)
	ms.sendBody(t, unheard, "unheard")
	time.Sleep(5 * time.Second)
	if got := ms.deliveries(t, "deaf"); len(got) != 0 {
		t.Fatalf("a role without sqs:ReceiveMessage was delivered %d messages", len(got))
	}
	requireEqual(t, ms.messagesIn(t, unheard), 1, "messages left in the unheard queue")

	// A role that no longer trusts Lambda cannot be used to read the queue,
	// so no mapping of its function is created: the poller's calls are its
	// role's, not the service's own key's.
	_, err := s.iam.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{
		RoleName: aws.String("revoked"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
	})
	requireNoErr(t, err, "revoke the role's trust of Lambda")
	err = errOf(ms.lambda.CreateEventSourceMapping(t.Context(),
		&lambda.CreateEventSourceMappingInput{
			EventSourceArn: aws.String(q.ARN), FunctionName: aws.String("revoked"),
		}))
	requireModeled[*types.InvalidParameterValueException](t, err)
}

// TestAnotherAccountsRoleIsRefused creates a function with a role of
// another account, as the root key: Lambda refuses a cross-account pass
// role with AccessDeniedException, whoever passes it.
func TestAnotherAccountsRoleIsRefused(t *testing.T) {
	s := startIdentityStack(t)
	in := createInput("cross", "echo")
	in.Role = aws.String("arn:aws:iam::111111111111:role/lambda-role")
	err := errOf(lambdaClientWith(s.srv, s.rootCreds).CreateFunction(t.Context(), in))
	requireAPIError(t, err)
	requireStatus(t, err, http.StatusForbidden)
	requireContains(t, err.Error(), "Cross-account pass role is not allowed.", "the refusal")
}
