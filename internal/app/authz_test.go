package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"
	"tule.dev/identity/keysource"
	"tule.dev/identity/servicerole"
	"tule.dev/sigv4"
)

// The key of an IAM user the fake identity below issued, and its ARN.
const (
	userKeyID  = "AKIAUSERKEYEXAMPLE01"
	userSecret = "user-secret"
	userARN    = "arn:aws:iam::000000000000:user/dev"
)

// fakeIdentity answers the signing-key endpoint at version 3 for one IAM
// user key, with policies as its identity policies. It does not check the
// caller's signature: the real identity's endpoint is exercised by the
// end-to-end tests.
func fakeIdentity(t *testing.T, policies ...string) *httptest.Server {
	t.Helper()
	return fakeIdentityAs(t, "000000000000", userARN, policies...)
}

// fakeIdentityAs is fakeIdentity for a principal of account with the ARN
// arn.
//
// The functions run with the root key, not their roles: the role tests
// below set role mode themselves.
func fakeIdentityAs(t *testing.T, account, arn string, policies ...string) *httptest.Server {
	t.Helper()
	t.Setenv("TULE_Functions_FunctionCredentials", "root")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == servicerole.Path {
			assumeRole(w, r)
			return
		}
		var req keysource.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AccessKeyID != userKeyID {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(keysource.ErrorResponse{Code: "UnknownAccessKey"})
			return
		}
		p := principalOf(account, arn)
		for _, doc := range policies {
			p.Policies = append(p.Policies, json.RawMessage(doc))
		}
		_ = json.NewEncoder(w).Encode(keysource.Response{
			SigningKey: sigv4.DeriveSigningKey(userSecret, req.Date, req.Region, req.Service),
			Principal:  p,
			Version:    keysource.Version,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// principalOf is the principal of the user key, with the attributes the
// signing-key endpoint gives at version 3 for arn: an IAM user, or a
// session of a role without a path.
func principalOf(account, arn string) keysource.Principal {
	p := keysource.Principal{
		AccountID: account, ARN: arn, AccessKeyID: userKeyID,
		PrincipalARN: arn, UserID: "AIDAEXAMPLEUSER00001",
		PrincipalType: string(sigv4.PrincipalTypeUser),
	}
	if rest, ok := strings.CutPrefix(arn, "arn:aws:sts::"+account+":assumed-role/"); ok {
		role, session, _ := strings.Cut(rest, "/")
		p.PrincipalARN = "arn:aws:iam::" + account + ":role/" + role
		p.UserID = "AROAEXAMPLEROLE00001:" + session
		p.PrincipalType = string(sigv4.PrincipalTypeAssumedRole)
	}
	return p
}

// userClient is a Lambda client of srv signing with the user's key.
func userClient(srv *httptest.Server) *lambda.Client {
	return lambda.New(lambda.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider(userKeyID, userSecret, ""),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
}

// The ARNs the denial tests name.
const (
	fnARN      = "arn:aws:lambda:us-east-1:000000000000:function:fn"
	mappingID  = "00000000-0000-4000-8000-000000000000"
	mappingARN = "arn:aws:lambda:us-east-1:000000000000:event-source-mapping:" + mappingID
)

// deniedCall is an operation called by a principal it is denied to, with
// the action and resource it is denied.
type deniedCall struct {
	call     func() error
	action   string
	resource string
}

// TestEveryOperationIsDeniedWithoutAPolicy calls every routed operation
// with an IAM user key that has no policy, and expects AccessDenied in
// AWS's words for each, with nothing changed.
func TestEveryOperationIsDeniedWithoutAPolicy(t *testing.T) {
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t).URL)
	root, srv := startApp(t)
	createActiveOrFailed(t, root, "fn")
	c := userClient(srv)
	calls := append(functionCalls(t, c), mappingCalls(t, c)...)
	calls = append(calls, policyCalls(t, c)...)
	for _, tt := range append(calls, requalifiedCalls(t, c)...) {
		t.Run(tt.action+" on "+tt.resource, func(t *testing.T) {
			requireDenied(t, tt.call(), tt.action, tt.resource)
		})
	}

	ctx := t.Context()
	if _, err := root.GetFunction(ctx,
		&lambda.GetFunctionInput{FunctionName: aws.String("fn")}); err != nil {
		t.Fatalf("the denied DeleteFunction deleted the function: %v", err)
	}
	if _, err := root.GetFunction(ctx,
		&lambda.GetFunctionInput{FunctionName: aws.String("new")}); err == nil {
		t.Fatal("the denied CreateFunction created the function")
	}
	tags, err := root.ListTags(ctx, &lambda.ListTagsInput{Resource: aws.String(fnARN)})
	if err != nil || len(tags.Tags) != 0 {
		t.Fatalf("the denied TagResource tagged: %v %v", tags, err)
	}
}

// functionCalls are the function, invocation and tagging operations on fn.
func functionCalls(t *testing.T, c *lambda.Client) []deniedCall {
	ctx, name := t.Context(), aws.String("fn")
	return []deniedCall{
		{
			func() error { return errOf(c.CreateFunction(ctx, createInput("new"))) },
			"lambda:CreateFunction", "arn:aws:lambda:us-east-1:000000000000:function:new",
		},
		{
			func() error { return errOf(c.ListFunctions(ctx, &lambda.ListFunctionsInput{})) },
			"lambda:ListFunctions", "*",
		},
		{func() error {
			return errOf(c.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: name}))
		}, "lambda:GetFunction", fnARN},
		{func() error {
			return errOf(c.GetFunction(ctx, &lambda.GetFunctionInput{
				FunctionName: name, Qualifier: aws.String("$LATEST"),
			}))
		}, "lambda:GetFunction", fnARN + ":$LATEST"},
		{func() error {
			return errOf(c.DeleteFunction(ctx, &lambda.DeleteFunctionInput{FunctionName: name}))
		}, "lambda:DeleteFunction", fnARN},
		{func() error {
			return errOf(c.GetFunctionConfiguration(ctx,
				&lambda.GetFunctionConfigurationInput{FunctionName: name}))
		}, "lambda:GetFunctionConfiguration", fnARN},
		{func() error {
			return errOf(c.UpdateFunctionConfiguration(
				ctx,
				&lambda.UpdateFunctionConfigurationInput{
					FunctionName: name,
					Timeout:      aws.Int32(9),
				},
			))
		}, "lambda:UpdateFunctionConfiguration", fnARN},
		{func() error {
			return errOf(c.UpdateFunctionCode(ctx, &lambda.UpdateFunctionCodeInput{
				FunctionName: name, ImageUri: aws.String("example:other"),
			}))
		}, "lambda:UpdateFunctionCode", fnARN},
		{
			func() error { return errOf(c.Invoke(ctx, &lambda.InvokeInput{FunctionName: name})) },
			"lambda:InvokeFunction", fnARN,
		},
		{func() error {
			return errOf(c.TagResource(ctx, &lambda.TagResourceInput{
				Resource: aws.String(fnARN), Tags: map[string]string{"k": "v"},
			}))
		}, "lambda:TagResource", fnARN},
		{func() error {
			return errOf(c.UntagResource(ctx, &lambda.UntagResourceInput{
				Resource: aws.String(fnARN), TagKeys: []string{"k"},
			}))
		}, "lambda:UntagResource", fnARN},
		{func() error {
			return errOf(c.ListTags(ctx, &lambda.ListTagsInput{Resource: aws.String(fnARN)}))
		}, "lambda:ListTags", fnARN},
	}
}

// policyCalls are the function policy operations on fn. The whole-policy
// operations are denied their own action, the first they are evaluated
// for.
func policyCalls(t *testing.T, c *lambda.Client) []deniedCall {
	ctx, name := t.Context(), aws.String("fn")
	return []deniedCall{
		{func() error {
			return errOf(c.AddPermission(ctx, &lambda.AddPermissionInput{
				FunctionName: name, StatementId: aws.String("s"),
				Action: aws.String("lambda:InvokeFunction"), Principal: aws.String("*"),
			}))
		}, "lambda:AddPermission", fnARN},
		{func() error {
			return errOf(c.RemovePermission(ctx, &lambda.RemovePermissionInput{
				FunctionName: name, StatementId: aws.String("s"),
			}))
		}, "lambda:RemovePermission", fnARN},
		{func() error {
			return errOf(c.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: name}))
		}, "lambda:GetPolicy", fnARN},
		{func() error {
			return errOf(c.PutResourcePolicy(ctx, &lambda.PutResourcePolicyInput{
				ResourceArn: aws.String(fnARN), Policy: aws.String(`{}`),
			}))
		}, "lambda:PutResourcePolicy", fnARN},
		{func() error {
			return errOf(c.GetResourcePolicy(ctx,
				&lambda.GetResourcePolicyInput{ResourceArn: aws.String(fnARN)}))
		}, "lambda:GetResourcePolicy", fnARN},
		{func() error {
			return errOf(c.DeleteResourcePolicy(ctx,
				&lambda.DeleteResourcePolicyInput{ResourceArn: aws.String(fnARN)}))
		}, "lambda:DeleteResourcePolicy", fnARN},
	}
}

// requalifiedCalls name the function with a qualifier where the operation
// takes none: they are evaluated on the function they act on.
func requalifiedCalls(t *testing.T, c *lambda.Client) []deniedCall {
	ctx := t.Context()
	return []deniedCall{
		{func() error {
			return errOf(
				c.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
					FunctionName: aws.String("fn:$LATEST"), Timeout: aws.Int32(9),
				}),
			)
		}, "lambda:UpdateFunctionConfiguration", fnARN},
		{func() error {
			return errOf(c.TagResource(ctx, &lambda.TagResourceInput{
				Resource: aws.String(fnARN + ":$LATEST"), Tags: map[string]string{"k": "v"},
			}))
		}, "lambda:TagResource", fnARN},
	}
}

// mappingCalls are the event source mapping operations, on fn and a
// mapping that does not exist.
func mappingCalls(t *testing.T, c *lambda.Client) []deniedCall {
	ctx, mapping := t.Context(), aws.String(mappingID)
	return []deniedCall{
		{func() error {
			return errOf(c.CreateEventSourceMapping(ctx, &lambda.CreateEventSourceMappingInput{
				FunctionName:   aws.String("fn"),
				EventSourceArn: aws.String("arn:aws:sqs:us-east-1:000000000000:q"),
			}))
		}, "lambda:CreateEventSourceMapping", "*"},
		{func() error {
			return errOf(c.ListEventSourceMappings(ctx, &lambda.ListEventSourceMappingsInput{}))
		}, "lambda:ListEventSourceMappings", "*"},
		{func() error {
			return errOf(c.GetEventSourceMapping(ctx,
				&lambda.GetEventSourceMappingInput{UUID: mapping}))
		}, "lambda:GetEventSourceMapping", mappingARN},
		{func() error {
			return errOf(c.UpdateEventSourceMapping(ctx,
				&lambda.UpdateEventSourceMappingInput{UUID: mapping, BatchSize: aws.Int32(5)}))
		}, "lambda:UpdateEventSourceMapping", mappingARN},
		{func() error {
			return errOf(c.DeleteEventSourceMapping(ctx,
				&lambda.DeleteEventSourceMappingInput{UUID: mapping}))
		}, "lambda:DeleteEventSourceMapping", mappingARN},
	}
}

func requireDenied(t *testing.T, err error, action, resource string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDeniedException" {
		t.Fatalf("got %v, want AccessDeniedException", err)
	}
	want := "User: " + userARN + " is not authorized to perform: " + action +
		" on resource: " + resource + " because no identity-based policy allows the " +
		action + " action"
	if apiErr.ErrorMessage() != want {
		t.Fatalf("message\n got %s\nwant %s", apiErr.ErrorMessage(), want)
	}
	var re interface{ HTTPStatusCode() int }
	if !errors.As(err, &re) || re.HTTPStatusCode() != http.StatusForbidden {
		t.Fatalf("status: %v", err)
	}
}

// TestCreateFunctionNeedsPassRole allows lambda:CreateFunction alone, which
// is not enough: the execution role must be passable too.
func TestCreateFunctionNeedsPassRole(t *testing.T) {
	createOnly := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Action":["lambda:CreateFunction","lambda:UpdateFunctionConfiguration"],"Resource":"*"}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, createOnly).URL)
	root, srv := startApp(t)
	createActiveOrFailed(t, root, "fn")
	c := userClient(srv)
	requireDenied(t, errOf(c.CreateFunction(t.Context(), createInput("new"))),
		"iam:PassRole", "arn:aws:iam::000000000000:role/r")
	requireDenied(t, errOf(c.UpdateFunctionConfiguration(t.Context(),
		&lambda.UpdateFunctionConfigurationInput{
			FunctionName: aws.String("fn"),
			Role:         aws.String("arn:aws:iam::000000000000:role/other"),
		})), "iam:PassRole", "arn:aws:iam::000000000000:role/other")
	// Without a Role the update passes none.
	if _, err := c.UpdateFunctionConfiguration(t.Context(),
		&lambda.UpdateFunctionConfigurationInput{
			FunctionName: aws.String("fn"), Timeout: aws.Int32(9),
		}); err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDeniedException" {
			t.Fatalf("an update without a Role was denied: %v", err)
		}
	}
}

// TestTheRetrievalAPINeedsInspect checks that /_functions/ is denied to a
// principal without tule:Inspect and allowed to one with it.
func TestTheRetrievalAPINeedsInspect(t *testing.T) {
	inspect := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"tule:Inspect",` +
		`"Resource":"arn:aws:lambda:us-east-1:000000000000:*"}}`
	for _, tt := range []struct {
		name     string
		policies []string
		status   int
	}{
		{"without", nil, http.StatusForbidden},
		{"with", []string{inspect}, http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, tt.policies...).URL)
			_, srv := startApp(t)
			req := userSigned(t, srv.URL+"/_functions/invocations")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var body struct{ Code, Message string }
			_ = json.NewDecoder(resp.Body).Decode(&body)
			_ = resp.Body.Close()
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d: %+v", resp.StatusCode, tt.status, body)
			}
			if tt.status == http.StatusForbidden && (body.Code != "AccessDeniedException" ||
				!strings.Contains(body.Message, "perform: tule:Inspect on resource: "+
					"arn:aws:lambda:us-east-1:000000000000:*")) {
				t.Fatalf("body %+v", body)
			}
		})
	}
}

func userSigned(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if err = v4.NewSigner().SignHTTP(t.Context(),
		aws.Credentials{AccessKeyID: userKeyID, SecretAccessKey: userSecret}, req, emptySHA256,
		"lambda", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	return req
}

func createInput(name string) *lambda.CreateFunctionInput {
	return &lambda.CreateFunctionInput{
		FunctionName: aws.String(name),
		Role:         aws.String("arn:aws:iam::000000000000:role/r"),
		PackageType:  types.PackageTypeImage,
		Code:         &types.FunctionCode{ImageUri: aws.String("example:latest")},
	}
}

// createActiveOrFailed creates a function whose image need not exist: the
// tests here need its record, not a running container.
func createActiveOrFailed(t *testing.T, c *lambda.Client, name string) {
	t.Helper()
	if _, err := c.CreateFunction(t.Context(), createInput(name)); err != nil {
		t.Fatal(err)
	}
}

// TestAnotherAccountsPrincipalIsDenied gives a member account's session an
// identity policy that allows everything: ListFunctions acts on no function,
// so no resource-based policy can allow it, and it is still denied, as AWS
// denies a cross-account request no resource-based policy allows.
func TestAnotherAccountsPrincipalIsDenied(t *testing.T) {
	const member = "arn:aws:sts::111111111111:assumed-role/OrganizationAccountAccessRole/s"
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	t.Setenv("TULE_Auth_IdentityEndpoint",
		fakeIdentityAs(t, "111111111111", member, all).URL)
	_, srv := startApp(t)
	_, err := userClient(srv).ListFunctions(t.Context(), &lambda.ListFunctionsInput{})
	var apiErr smithy.APIError
	want := "User: " + member + " is not authorized to perform: lambda:ListFunctions on " +
		"resource: * because no resource-based policy allows the lambda:ListFunctions action"
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDeniedException" ||
		apiErr.ErrorMessage() != want {
		t.Fatalf("got %v", err)
	}
	resp, err := srv.Client().Do(userSigned(t, srv.URL+"/_functions/invocations"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("retrieval: %d", resp.StatusCode)
	}
}

// escapedSlash is "/" written as a JSON escape.
const escapedSlash = `\u002f`

// TestADenyOnAnEscapedResourceTagApplies writes the slash of a Deny's
// condition key, aws:ResourceTag/team, as the JSON escape escapedSlash: the
// function's tags are supplied whatever the policy's bytes say, so the Deny
// still applies.
func TestADenyOnAnEscapedResourceTagApplies(t *testing.T) {
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"lambda:*",` +
		`"Resource":"*"}}`
	deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"lambda:*",` +
		`"Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag` + escapedSlash + `team":"a"}}}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, all, deny).URL)
	root, srv := startApp(t)
	in := createInput("tagged")
	in.Tags = map[string]string{"team": "a"}
	if _, err := root.CreateFunction(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	createActiveOrFailed(t, root, "untagged")
	c := userClient(srv)

	_, err := c.GetFunctionConfiguration(t.Context(),
		&lambda.GetFunctionConfigurationInput{FunctionName: aws.String("tagged")})
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || !strings.HasSuffix(apiErr.ErrorMessage(),
		"with an explicit deny in an identity-based policy") {
		t.Fatalf("the tagged function: %v", err)
	}
	if _, err = c.GetFunctionConfiguration(t.Context(),
		&lambda.GetFunctionConfigurationInput{FunctionName: aws.String("untagged")}); err != nil {
		t.Fatalf("the untagged function: %v", err)
	}
}

// TestAnARNOfAnotherPartitionOrRegionNamesNothing tags by ARNs this service
// does not have: they are answered as not found before any evaluation, even
// for a caller with no policy.
func TestAnARNOfAnotherPartitionOrRegionNamesNothing(t *testing.T) {
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t).URL)
	root, srv := startApp(t)
	createActiveOrFailed(t, root, "fn")
	c := userClient(srv)
	for _, arn := range []string{
		"arn:aws-cn:lambda:us-east-1:000000000000:function:fn",
		"arn:aws:lambda:eu-west-1:000000000000:function:fn",
		"arn:aws:lambda:us-east-1:111111111111:function:fn",
		"arn:aws:lambda:eu-west-1:000000000000:event-source-mapping:" + mappingID,
	} {
		_, err := c.TagResource(t.Context(), &lambda.TagResourceInput{
			Resource: aws.String(arn), Tags: map[string]string{"k": "v"},
		})
		var nf *types.ResourceNotFoundException
		if !errors.As(err, &nf) {
			t.Errorf("%s: got %v", arn, err)
		}
	}
}

// TestGetFunctionShowsTagsOnlyWithListTags checks that GetFunction leaves
// the tags out for a caller not allowed lambda:ListTags on the function.
func TestGetFunctionShowsTagsOnlyWithListTags(t *testing.T) {
	for _, tt := range []struct {
		name    string
		actions string
		tagged  bool
	}{
		{"without ListTags", `"lambda:GetFunction"`, false},
		{"with ListTags", `["lambda:GetFunction","lambda:ListTags"]`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":` +
				tt.actions + `,"Resource":"*"}}`
			t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, doc).URL)
			root, srv := startApp(t)
			in := createInput("fn")
			in.Tags = map[string]string{"team": "a"}
			if _, err := root.CreateFunction(t.Context(), in); err != nil {
				t.Fatal(err)
			}
			out, err := userClient(srv).GetFunction(t.Context(),
				&lambda.GetFunctionInput{FunctionName: aws.String("fn")})
			if err != nil {
				t.Fatal(err)
			}
			if got := out.Tags["team"] == "a"; got != tt.tagged {
				t.Fatalf("tags %v, want tagged %v", out.Tags, tt.tagged)
			}
		})
	}
}

// TestTagKeysDifferingOnlyInCase checks that an evaluated caller cannot set
// a tag key that differs only in case from another, while root can, and that
// a function root tagged so is not evaluated at all.
func TestTagKeysDifferingOnlyInCase(t *testing.T) {
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"lambda:*",` +
		`"Resource":"*"}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, all).URL)
	root, srv := startApp(t)
	in := createInput("fn")
	in.Tags = map[string]string{"team": "a"}
	if _, err := root.CreateFunction(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	c := userClient(srv)
	tag := func(cl *lambda.Client, tags map[string]string) error {
		return errOf(cl.TagResource(t.Context(),
			&lambda.TagResourceInput{Resource: aws.String(fnARN), Tags: tags}))
	}
	for name, tags := range map[string]map[string]string{
		"against a stored key": {"Team": "b"},
		"within the request":   {"env": "x", "Env": "y"},
	} {
		var bad *types.InvalidParameterValueException
		if err := tag(c, tags); !errors.As(err, &bad) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if err := tag(c, map[string]string{"team": "b"}); err != nil {
		t.Fatalf("replacing the stored key: %v", err)
	}

	if err := tag(root, map[string]string{"Team": "c"}); err != nil {
		t.Fatalf("root: %v", err)
	}
	_, err := c.GetFunctionConfiguration(t.Context(),
		&lambda.GetFunctionConfigurationInput{FunctionName: aws.String("fn")})
	var svc *types.ServiceException
	if !errors.As(err, &svc) {
		t.Fatalf("a function tagged team and Team was evaluated: %v", err)
	}
}

// TestLongRequestStringsAreRefusedBeforeEvaluation sends resource names and
// tag keys longer than Lambda's limits: each is refused, as Lambda refuses
// it, before any policy is evaluated against it.
func TestLongRequestStringsAreRefusedBeforeEvaluation(t *testing.T) {
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t).URL)
	root, srv := startApp(t)
	createActiveOrFailed(t, root, "fn")
	c, ctx, long := userClient(srv), t.Context(), strings.Repeat("a", 4096)
	var notFound *types.ResourceNotFoundException
	if err := errOf(c.GetEventSourceMapping(ctx,
		&lambda.GetEventSourceMappingInput{UUID: aws.String(long)})); !errors.As(err, &notFound) {
		t.Errorf("a long mapping UUID: %v", err)
	}
	var invalid smithy.APIError
	for name, err := range map[string]error{
		"a long tagging ARN": errOf(c.ListTags(ctx,
			&lambda.ListTagsInput{Resource: aws.String(fnARN + long)})),
		"a mapping ARN that is not a UUID": errOf(c.ListTags(ctx, &lambda.ListTagsInput{
			Resource: aws.String("arn:aws:lambda:us-east-1:000000000000:event-source-mapping:" +
				long[:100]),
		})),
		"a long role": errOf(c.CreateFunction(ctx, func() *lambda.CreateFunctionInput {
			in := createInput("new")
			in.Role = aws.String("arn:aws:iam::000000000000:role/" + long)
			return in
		}())),
		"a long tag key": errOf(c.UntagResource(ctx, &lambda.UntagResourceInput{
			Resource: aws.String(fnARN), TagKeys: []string{long},
		})),
		"a long tag key set": errOf(c.TagResource(ctx, &lambda.TagResourceInput{
			Resource: aws.String(fnARN), Tags: map[string]string{long: "v"},
		})),
	} {
		if !errors.As(err, &invalid) || invalid.ErrorCode() == "AccessDeniedException" {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// TestARequestSignedForAnotherRegionHasTheServicesRegion signs for
// eu-west-1, which verifies, against a Deny on aws:RequestedRegion
// us-east-1, the service's region: the Deny applies, since the request acts
// in the service's region whatever it was signed for.
func TestARequestSignedForAnotherRegionHasTheServicesRegion(t *testing.T) {
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*",` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, all, deny).URL)
	_, srv := startApp(t)
	c := lambda.New(lambda.Options{
		Region:           "eu-west-1",
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider(userKeyID, userSecret, ""),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
	_, err := c.ListFunctions(t.Context(), &lambda.ListFunctionsInput{})
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || !strings.HasSuffix(apiErr.ErrorMessage(),
		"with an explicit deny in an identity-based policy") {
		t.Fatalf("got %v", err)
	}
}

// rawSigned is a request to srv signed with the user's key, with body.
func rawSigned(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	sum := sha256.Sum256([]byte(body))
	if err = v4.NewSigner().SignHTTP(t.Context(),
		aws.Credentials{AccessKeyID: userKeyID, SecretAccessKey: userSecret}, req,
		hex.EncodeToString(sum[:]), "lambda", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	return req
}

// TestOneDecodingIsAuthorizedAndActedOn sends members the JSON decoder
// resolves silently, a Role given twice and in two cases, and a Qualifier
// given twice: the request is authorized on the value it acts on, since
// authorization and the operation share one decoding.
func TestOneDecodingIsAuthorizedAndActedOn(t *testing.T) {
	const (
		allowed = "arn:aws:iam::000000000000:role/allowed"
		other   = "arn:aws:iam::000000000000:role/other"
	)
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:*",` +
		`"Resource":"*"},{"Effect":"Allow","Action":"iam:PassRole","Resource":"` + allowed + `"}]}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, doc).URL)
	root, srv := startApp(t)
	create := func(name, roles string) int {
		body := `{"FunctionName":"` + name + `","PackageType":"Image",` +
			`"Code":{"ImageUri":"example:latest"},` + roles + `}`
		resp, err := srv.Client().Do(rawSigned(t, http.MethodPost,
			srv.URL+"/2015-03-31/functions", body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	roleOf := func(name string) string {
		out, err := root.GetFunctionConfiguration(t.Context(),
			&lambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
		if err != nil {
			return ""
		}
		return aws.ToString(out.Role)
	}
	for _, tt := range []struct {
		name, roles, stored string
		status              int
	}{
		{"denied-last", `"Role":"` + allowed + `","Role":"` + other + `"`, "", 403},
		{"allowed-last", `"Role":"` + other + `","Role":"` + allowed + `"`, allowed, 201},
		{"denied-case", `"Role":"` + allowed + `","role":"` + other + `"`, "", 403},
	} {
		if got := create(tt.name, tt.roles); got != tt.status || roleOf(tt.name) != tt.stored {
			t.Errorf("%s: status %d, stored role %q; want %d, %q", tt.name, got,
				roleOf(tt.name), tt.status, tt.stored)
		}
	}

	resp, err := srv.Client().Do(rawSigned(t, http.MethodGet, srv.URL+
		"/2015-03-31/functions/allowed-last/configuration?Qualifier=%24LATEST&Qualifier=v1", ""))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a repeated Qualifier: %d", resp.StatusCode)
	}
}

// assumeRole answers the fake identity's assume-role endpoint: a role named
// missing does not exist, one named untrusted does not trust Lambda, and
// any other is assumed as long as the request is Lambda's for its function.
func assumeRole(w http.ResponseWriter, r *http.Request) {
	var req servicerole.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch {
	case strings.HasSuffix(req.RoleArn, "/missing"):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(servicerole.ErrorResponse{Code: servicerole.CodeNoSuchRole})
		return
	case strings.HasSuffix(req.RoleArn, "/untrusted"),
		req.ServicePrincipal != "lambda.amazonaws.com",
		req.SourceAccount != "000000000000",
		!strings.HasPrefix(req.SourceArn, "arn:aws:lambda:us-east-1:000000000000:function:"):
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(servicerole.ErrorResponse{Code: servicerole.CodeNotTrusted})
		return
	}
	_ = json.NewEncoder(w).Encode(servicerole.Session{Credentials: servicerole.Credentials{
		Expiration: time.Now().Add(time.Hour), AccessKeyID: "ASIAFAKE",
		SecretAccessKey: "secret", SessionToken: "token",
	}})
}

// TestARoleLambdaCannotAssumeIsRefused creates and updates functions in
// role mode with roles that do not exist or do not trust Lambda, which
// Lambda refuses with InvalidParameterValueException.
func TestARoleLambdaCannotAssumeIsRefused(t *testing.T) {
	srv := fakeIdentity(t)
	t.Setenv("TULE_Auth_IdentityEndpoint", srv.URL)
	t.Setenv("TULE_Functions_FunctionCredentials", "role")
	root, _ := startApp(t)
	const msg = "The role defined for the function cannot be assumed by Lambda."
	refused := func(what string, err error) {
		t.Helper()
		var bad *types.InvalidParameterValueException
		if !errors.As(err, &bad) || aws.ToString(bad.Message) != msg {
			t.Errorf("%s: got %v", what, err)
		}
	}
	for _, role := range []string{"missing", "untrusted"} {
		in := createInput("fn-" + role)
		in.Role = aws.String("arn:aws:iam::000000000000:role/" + role)
		refused("create with "+role, errOf(root.CreateFunction(t.Context(), in)))
	}
	createActiveOrFailed(t, root, "fn")
	refused("update to missing", errOf(root.UpdateFunctionConfiguration(t.Context(),
		&lambda.UpdateFunctionConfigurationInput{
			FunctionName: aws.String("fn"),
			Role:         aws.String("arn:aws:iam::000000000000:role/missing"),
		})))
}

// TestAnotherAccountsRoleIsRefused passes a role of another account, as the
// root key, standalone: Lambda refuses a cross-account pass role whatever
// the caller and however the functions get credentials.
func TestAnotherAccountsRoleIsRefused(t *testing.T) {
	root, _ := startApp(t)
	in := createInput("fn")
	in.Role = aws.String("arn:aws:iam::111111111111:role/r")
	requireCrossAccount := func(what string, err error) {
		t.Helper()
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDeniedException" ||
			apiErr.ErrorMessage() != "Cross-account pass role is not allowed." {
			t.Errorf("%s: got %v", what, err)
		}
	}
	requireCrossAccount("create", errOf(root.CreateFunction(t.Context(), in)))
	createActiveOrFailed(t, root, "fn")
	requireCrossAccount("update", errOf(root.UpdateFunctionConfiguration(t.Context(),
		&lambda.UpdateFunctionConfigurationInput{
			FunctionName: aws.String("fn"),
			Role:         aws.String("arn:aws:iam::111111111111:role/r"),
		})))
}
