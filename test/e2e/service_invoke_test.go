//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"tule.dev/functions/serviceinvoke"
)

// These tests invoke functions through the service-invoke endpoint, as a
// Tule service invokes one as an AWS service principal, with the
// serviceinvoke client, on the real server.

const (
	secretsManager = "secretsmanager.amazonaws.com"
	secretARN      = "arn:aws:secretsmanager:us-east-1:" + defaultAccountID +
		":secret:db-AbCdEf"
)

// serviceClient returns a serviceinvoke client for srv, signing with creds.
func serviceClient(t *testing.T, srv *server, creds aws.Credentials) *serviceinvoke.Client {
	t.Helper()
	c, err := serviceinvoke.New(serviceinvoke.Config{
		HTTPClient:      srv.Client(),
		Endpoint:        srv.URL,
		Region:          region,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
	})
	requireNoErr(t, err, "new serviceinvoke client")
	return c
}

func rootServiceClient(t *testing.T, srv *server) *serviceinvoke.Client {
	t.Helper()
	return serviceClient(t, srv, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
}

// grantRotation is the AddPermission of a rotation function, on the
// function rotate: lambda:InvokeFunction for the service, conditioned on
// the secret's account, as the Secrets Manager User Guide's CLI setup
// grants it, and on the secret's ARN too.
func grantRotation(t *testing.T, c *lambda.Client) {
	const fn = "rotate"
	t.Helper()
	_, err := c.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName:  aws.String(fn),
		StatementId:   aws.String("secretsmanager"),
		Action:        aws.String("lambda:InvokeFunction"),
		Principal:     aws.String(secretsManager),
		SourceAccount: aws.String(defaultAccountID),
		SourceArn:     aws.String(secretARN),
	})
	requireNoErr(t, err, "grant the rotation permission on "+fn)
}

// asSecret are the options of an invocation for the secret.
func asSecret() []serviceinvoke.Option {
	return []serviceinvoke.Option{
		serviceinvoke.WithSourceArn(secretARN),
		serviceinvoke.WithSourceAccount(defaultAccountID),
	}
}

func requireIs(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

// requireServiceError fails unless err is an *serviceinvoke.Error with the
// status and code.
func requireServiceError(t *testing.T, err error, status int, code, what string) {
	t.Helper()
	var e *serviceinvoke.Error
	if !errors.As(err, &e) || e.Status != status || e.Code != code {
		t.Fatalf("%s: got %v, want %d %s", what, err, status, code)
	}
}

func TestServiceInvokeAllowedByAddPermission(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "rotate", "echo", nil)
	grantRotation(t, c)
	sc := rootServiceClient(t, srv)

	event := `{"SecretId":"` + secretARN + `","ClientRequestToken":"t","Step":"createSecret"}`
	res, err := sc.Invoke(t.Context(), "rotate", secretsManager, []byte(event), asSecret()...)
	requireNoErr(t, err, "invoke as the service")
	requireEqual(t, res.StatusCode, http.StatusOK, "status code")
	requireEqual(t, res.ExecutedVersion, "$LATEST", "executed version")
	requireEqual(t, res.FunctionError, "", "function error")
	requireJSONEqual(t, res.Payload, event, "the function's result")
	// The request ID is the invocation's, under which the history keeps it.
	h := historyFor(srv)
	requireEqual(t, h.get(t, res.RequestID).Source, "service", "source by the request ID")

	// By ARN too.
	_, err = sc.Invoke(t.Context(), functionARN("rotate"), secretsManager, nil, asSecret()...)
	requireNoErr(t, err, "invoke as the service by ARN")

	// The invocations are in the history, with source service.
	items := h.all(t, url.Values{"function": {"rotate"}, "source": {"service"}})
	requireEqual(t, len(items), 2, "service invocations in the history")
	got := h.get(t, items[1].RequestID)
	requireEqual(t, got.Source, "service", "source")
	requireEqual(t, got.Status, "succeeded", "status")
	requireJSONEqual(t, got.payloadJSON(t), event, "recorded payload")
	// Without a Payload, the event is {}.
	requireJSONEqual(t, h.get(t, items[0].RequestID).payloadJSON(t), `{}`, "default payload")
	requireEqual(t, len(h.all(t, url.Values{"function": {"rotate"}, "source": {"invoke"}})), 0,
		"invoke invocations in the history")
}

func TestServiceInvokeRefusals(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "rotate", "echo", nil)
	createFunction(t, c, "nopolicy", "echo", nil)
	grantRotation(t, c)
	sc := rootServiceClient(t, srv)
	ctx := t.Context()

	denied := map[string]func() error{
		"another service": func() error {
			return errOf(sc.Invoke(ctx, "rotate", "sns.amazonaws.com", nil, asSecret()...))
		},
		"another SourceArn": func() error {
			return errOf(sc.Invoke(ctx, "rotate", secretsManager, nil,
				serviceinvoke.WithSourceArn(secretARN+"x"),
				serviceinvoke.WithSourceAccount(defaultAccountID)))
		},
		"another SourceAccount": func() error {
			return errOf(sc.Invoke(ctx, "rotate", secretsManager, nil,
				serviceinvoke.WithSourceArn(secretARN),
				serviceinvoke.WithSourceAccount("111111111111")))
		},
		"no SourceArn or SourceAccount": func() error {
			return errOf(sc.Invoke(ctx, "rotate", secretsManager, nil))
		},
		// The policy's Resource is the unqualified ARN, and a request that
		// names $LATEST is evaluated on the qualified one, as Invoke is.
		"the $LATEST qualifier": func() error {
			return errOf(sc.Invoke(ctx, "rotate:$LATEST", secretsManager, nil, asSecret()...))
		},
		"no function policy": func() error {
			return errOf(sc.Invoke(ctx, "nopolicy", secretsManager, nil, asSecret()...))
		},
	}
	for what, call := range denied {
		requireIs(t, call(), serviceinvoke.ErrAccessDenied, what)
	}

	_, err := sc.Invoke(ctx, "missing", secretsManager, nil, asSecret()...)
	requireIs(t, err, serviceinvoke.ErrNotFound, "a missing function")
	_, err = sc.Invoke(ctx, "rotate", "not a service", nil)
	requireServiceError(t, err, http.StatusBadRequest, serviceinvoke.CodeInvalidRequest,
		"a malformed service principal")
	_, err = sc.Invoke(ctx, "rotate", secretsManager,
		[]byte(`{"big":"`+strings.Repeat("x", 1<<20)+`"}`),
		append(asSecret(), serviceinvoke.WithEvent())...)
	requireServiceError(t, err, http.StatusRequestEntityTooLarge,
		serviceinvoke.CodeRequestTooLarge, "an Event payload over 1 MB")

	// Nothing refused ran.
	requireEqual(t, len(historyFor(srv).all(t, url.Values{"source": {"service"}})), 0,
		"service invocations after the refusals")
}

func TestServiceInvokeDenyWins(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "rotate", "echo", nil)
	arn := functionARN("rotate")
	putFunctionPolicy(t, c, "rotate",
		`{"Effect":"Allow","Principal":{"Service":"`+secretsManager+`"},`+
			`"Action":"lambda:InvokeFunction","Resource":"`+arn+`"},`+
			`{"Effect":"Deny","Principal":{"Service":"`+secretsManager+`"},`+
			`"Action":"lambda:InvokeFunction","Resource":"`+arn+`",`+
			`"Condition":{"StringEquals":{"aws:SourceAccount":"`+defaultAccountID+`"}}}`)
	sc := rootServiceClient(t, srv)

	_, err := sc.Invoke(t.Context(), "rotate", secretsManager, nil, asSecret()...)
	requireIs(t, err, serviceinvoke.ErrAccessDenied, "an invocation the Deny matches")
	// The Allow alone grants a call the Deny's condition does not match.
	_, err = sc.Invoke(t.Context(), "rotate", secretsManager, nil,
		serviceinvoke.WithSourceAccount("111111111111"))
	requireNoErr(t, err, "an invocation the Deny does not match")

	// A Deny of Principal "*" applies to a service too.
	putFunctionPolicy(t, c, "rotate",
		`{"Effect":"Allow","Principal":{"Service":"`+secretsManager+`"},`+
			`"Action":"lambda:InvokeFunction","Resource":"`+arn+`"},`+
			`{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction",`+
			`"Resource":"`+arn+`"}`)
	_, err = sc.Invoke(t.Context(), "rotate", secretsManager, nil, asSecret()...)
	requireIs(t, err, serviceinvoke.ErrAccessDenied, "a Deny of Principal *")
}

// TestServiceInvokePrincipalStar checks an Allow of Principal "*" held to
// the secret by aws:SourceArn: it lets the service invoke for that secret
// and refuses it for another.
func TestServiceInvokePrincipalStar(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "public", "echo", nil)
	_, err := c.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName: aws.String("public"), StatementId: aws.String("any"),
		Action: aws.String("lambda:InvokeFunction"), Principal: aws.String("*"),
		SourceArn: aws.String(secretARN),
	})
	requireNoErr(t, err, "grant Principal * for the secret")
	sc := rootServiceClient(t, srv)

	res, err := sc.Invoke(t.Context(), "public", secretsManager, []byte(`{"n":2}`),
		serviceinvoke.WithSourceArn(secretARN))
	requireNoErr(t, err, "invoke for the secret")
	requireJSONEqual(t, res.Payload, `{"n":2}`, "the function's result")
	_, err = sc.Invoke(t.Context(), "public", secretsManager, nil,
		serviceinvoke.WithSourceArn(secretARN+"x"))
	requireIs(t, err, serviceinvoke.ErrAccessDenied, "an invocation for another secret")
}

func TestServiceInvokeEvent(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "rotate", "echo", nil)
	grantRotation(t, c)

	res, err := rootServiceClient(t, srv).Invoke(t.Context(), "rotate", secretsManager,
		[]byte(`{"Step":"setSecret"}`), append(asSecret(), serviceinvoke.WithEvent())...)
	requireNoErr(t, err, "invoke as the service, Event")
	requireEqual(t, res.StatusCode, http.StatusAccepted, "status code")
	requireEqual(t, len(res.Payload), 0, "payload of an Event invocation")

	h := historyFor(srv)
	it := awaitOnly(t, h, url.Values{"function": {"rotate"}, "source": {"service"}})
	requireEqual(t, it.RequestID, res.RequestID, "request ID of the Event invocation")
	requireEqual(t, it.Status, "succeeded", "status of the Event invocation")
	requireJSONEqual(t, h.get(t, it.RequestID).payloadJSON(t), `{"Step":"setSecret"}`,
		"recorded payload")
}

func TestServiceInvokeFunctionError(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "rotate", "errors", nil)
	grantRotation(t, c)

	res, err := rootServiceClient(t, srv).Invoke(t.Context(), "rotate", secretsManager,
		[]byte(`{"message":"no"}`), asSecret()...)
	requireNoErr(t, err, "invoke a failing function as the service")
	requireEqual(t, res.StatusCode, http.StatusOK, "status code")
	requireEqual(t, res.FunctionError, "Unhandled", "function error")
	var doc struct {
		ErrorMessage string `json:"errorMessage"`
	}
	requireNoErr(t, json.Unmarshal(res.Payload, &doc), "decode the error document")
	requireEqual(t, doc.ErrorMessage, "handled failure: no", "error message")
}

func TestServiceInvokeRefusesAnotherKey(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "rotate", "echo", nil)
	grantRotation(t, c)

	_, err := serviceClient(t, srv, aws.Credentials{AccessKeyID: "other", SecretAccessKey: "x"}).
		Invoke(t.Context(), "rotate", secretsManager, nil, asSecret()...)
	requireServiceError(t, err, http.StatusForbidden, "UnknownAccessKey", "an unknown key")
	_, err = serviceClient(t, srv, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "x"}).
		Invoke(t.Context(), "rotate", secretsManager, nil, asSecret()...)
	requireServiceError(t, err, http.StatusForbidden, "SignatureMismatch", "a wrong secret")
	requireEqual(t, len(historyFor(srv).all(t, url.Values{"source": {"service"}})), 0,
		"service invocations after the refusals")
}

// TestServiceInvokeWithIdentity checks the endpoint against a real
// identity: its root key may call it, and an IAM user's key may not, even
// one allowed every Lambda action, since the endpoint takes the root key
// alone.
func TestServiceInvokeWithIdentity(t *testing.T) {
	s := startIdentityStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "rotate", "echo", nil)
	grantRotation(t, root)

	res, err := serviceClient(t, s.srv, s.rootCreds).Invoke(t.Context(), "rotate",
		secretsManager, []byte(`{"n":1}`), asSecret()...)
	requireNoErr(t, err, "invoke as the service with identity's root key")
	requireJSONEqual(t, res.Payload, `{"n":1}`, "the function's result")

	userKey := createUserKey(t, s.iam, "dev")
	putUserPolicy(t, s.iam, "dev", "functions", allowDoc(`["lambda:*","tule:Inspect"]`, `"*"`))
	_, err = serviceClient(t, s.srv, userKey).Invoke(t.Context(), "rotate", secretsManager,
		nil, asSecret()...)
	requireServiceError(t, err, http.StatusForbidden, "UnknownAccessKey", "an IAM user's key")
	requireEqual(t, len(historyWith(s.srv, s.rootCreds).all(t,
		url.Values{"source": {"service"}})), 1, "service invocations")
}

// TestServiceInvokeKeepsThePayloadAsSent checks that a payload of <, > and
// & with white space reaches the function byte for byte, as the history
// records what the function was invoked with, and that the result comes
// back as the function sent it, as the history records it.
func TestServiceInvokeKeepsThePayloadAsSent(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "rotate", "echo", nil)
	grantRotation(t, c)
	const payload = `{ "html": "<b>a & b</b>",  "n": [1, 2] }`

	res, err := rootServiceClient(t, srv).Invoke(t.Context(), "rotate", secretsManager,
		[]byte(payload), asSecret()...)
	requireNoErr(t, err, "invoke with a payload of <, > and &")
	got := historyFor(srv).get(t, res.RequestID)
	requireEqual(t, string(got.payloadJSON(t)), payload, "the payload the function got")
	requireEqual(t, string(res.Payload), string(got.resultJSON(t)), "the result returned")
}

// TestServiceInvokeSuppliesTheFunctionsTags checks that the function's tags
// are aws:ResourceTag/<key> on the service path, as on Invoke: a policy
// conditioned on a tag allows the service while the function has it, and
// not once the tag changes.
func TestServiceInvokeSuppliesTheFunctionsTags(t *testing.T) {
	c, srv := newClient(t)
	createFunction(t, c, "rotate", "echo", func(in *lambda.CreateFunctionInput) {
		in.Tags = map[string]string{"team": "secrets"}
	})
	arn := functionARN("rotate")
	putFunctionPolicy(t, c, "rotate",
		`{"Effect":"Allow","Principal":{"Service":"`+secretsManager+`"},`+
			`"Action":"lambda:InvokeFunction","Resource":"`+arn+`",`+
			`"Condition":{"StringEquals":{"aws:ResourceTag/team":"secrets"}}}`)
	sc := rootServiceClient(t, srv)

	_, err := sc.Invoke(t.Context(), "rotate", secretsManager, nil, asSecret()...)
	requireNoErr(t, err, "invoke a function with the tag")
	_, err = c.TagResource(t.Context(), &lambda.TagResourceInput{
		Resource: aws.String(arn), Tags: map[string]string{"team": "other"},
	})
	requireNoErr(t, err, "change the tag")
	_, err = sc.Invoke(t.Context(), "rotate", secretsManager, nil, asSecret()...)
	requireIs(t, err, serviceinvoke.ErrAccessDenied, "a function whose tag changed")
}

// serviceCallAs posts body to the service-invoke endpoint of srv signed
// with creds, session token included, and returns the status and the
// error code.
func serviceCallAs(t *testing.T, srv *server, creds aws.Credentials, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+serviceinvoke.Path, strings.NewReader(body))
	requireNoErr(t, err, "build the call")
	sum := sha256.Sum256([]byte(body))
	err = v4.NewSigner().SignHTTP(t.Context(), creds, req, hex.EncodeToString(sum[:]),
		serviceinvoke.SigningName, region, time.Now())
	requireNoErr(t, err, "sign the call")
	resp, err := srv.Client().Do(req)
	requireNoErr(t, err, "call the endpoint")
	defer func() { _ = resp.Body.Close() }()
	var e serviceinvoke.ErrorResponse
	requireNoErr(t, json.NewDecoder(resp.Body).Decode(&e), "decode the answer")
	return resp.StatusCode, e.Code
}

// TestServiceInvokeRefusesRoleSessions checks that a role session's key is
// refused, one of the service's own account and one of a member account
// alike, whatever the session's policies allow.
func TestServiceInvokeRefusesRoleSessions(t *testing.T) {
	s := startCrossStack(t)
	root := lambdaClientWith(s.srv, s.rootCreds)
	createFunction(t, root, "rotate", "echo", nil)
	grantRotation(t, root)
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	createRole(t, s.iam, "admin", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"AWS":"arn:aws:iam::`+defaultAccountID+`:root"},`+
		`"Action":"sts:AssumeRole"}]}`, all)
	own, err := s.sts(s.rootCreds).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String(roleARN("admin")), RoleSessionName: aws.String("session"),
	})
	requireNoErr(t, err, "assume a role of the service's account")
	member, err := s.sts(s.rootCreds).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String("arn:aws:iam::" + s.member +
			":role/OrganizationAccountAccessRole"),
		RoleSessionName: aws.String("admin"),
	})
	requireNoErr(t, err, "assume the member account's role")

	body := `{"FunctionName":"rotate","ServicePrincipal":"` + secretsManager + `",` +
		`"SourceArn":"` + secretARN + `","SourceAccount":"` + defaultAccountID + `"}`
	for what, creds := range map[string]aws.Credentials{
		"a session of the service's account": sessionCreds(own),
		"a session of a member account":      sessionCreds(member),
	} {
		status, code := serviceCallAs(t, s.srv, creds, body)
		requireEqual(t, status, http.StatusForbidden, what+": status")
		requireEqual(t, code, "UnknownAccessKey", what+": code")
	}
	status, _ := serviceCallAs(t, s.srv, s.rootCreds, body)
	requireEqual(t, status, http.StatusOK, "the root key")
}
