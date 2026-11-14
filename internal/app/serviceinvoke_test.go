package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"tule.dev/identity/keysource"
	"tule.dev/sigv4"

	"tule.dev/functions/serviceinvoke"
)

// serviceCall posts body to the service-invoke endpoint of url, signed with
// the key for service unless keyID is empty, and returns the status and the
// error document.
func serviceCall(
	t *testing.T,
	url, keyID, secret, service string,
	body []byte,
) (int, serviceinvoke.ErrorResponse) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		url+serviceinvoke.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if keyID != "" {
		sum := sha256.Sum256(body)
		if err = v4.NewSigner().SignHTTP(t.Context(),
			aws.Credentials{AccessKeyID: keyID, SecretAccessKey: secret}, req,
			hex.EncodeToString(sum[:]), service, "us-east-1", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var e serviceinvoke.ErrorResponse
	if err = json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode the answer of %d: %v", resp.StatusCode, err)
	}
	return resp.StatusCode, e
}

// TestTheServiceInvokeEndpointTakesTheRootKeyAlone checks the endpoint's
// verification: an unsigned call, one signed for another service, and one
// signed with an IAM user's key, even a user allowed everything, are
// refused with the sigv4 Kind as the code, as identity's internal endpoints
// refuse them; the root key gets through to the endpoint.
func TestTheServiceInvokeEndpointTakesTheRootKeyAlone(t *testing.T) {
	all := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentity(t, all).URL)
	_, srv := startApp(t)
	body := []byte(`{"FunctionName":"missing","ServicePrincipal":"secretsmanager.amazonaws.com"}`)

	for what, c := range map[string]struct {
		keyID, secret, service, code string
	}{
		"unsigned":                      {"", "", "", "MissingAuth"},
		"signed for another service":    {"test", "test", "identity", "WrongService"},
		"signed with an IAM user's key": {userKeyID, userSecret, "lambda", "UnknownAccessKey"},
	} {
		status, e := serviceCall(t, srv.URL, c.keyID, c.secret, c.service, body)
		if status != http.StatusForbidden || e.Code != c.code || e.Message == "" {
			t.Errorf("%s: got %d %+v, want 403 %s", what, status, e, c.code)
		}
	}

	status, e := serviceCall(t, srv.URL, "test", "test", "lambda", body)
	if status != http.StatusNotFound || e.Code != serviceinvoke.CodeResourceNotFound {
		t.Fatalf("the root key: got %d %+v, want 404 %s", status, e,
			serviceinvoke.CodeResourceNotFound)
	}
}

// fakeIdentityOf is an identity whose signing-key endpoint answers the
// user key, userKeyID, with the principal p, which needs no policies: the
// endpoint never evaluates them.
func fakeIdentityOf(t *testing.T, p keysource.Principal) *httptest.Server {
	t.Helper()
	t.Setenv("TULE_Functions_FunctionCredentials", "root")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req keysource.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AccessKeyID != userKeyID {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(keysource.ErrorResponse{Code: "UnknownAccessKey"})
			return
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

// TestTheServiceInvokeEndpointRefusesOtherPrincipalsKeys checks, through
// the app, that a key identity issued another account's root user, or a
// role session of the service's own account, is refused as unknown: the
// endpoint takes the service's own root alone.
func TestTheServiceInvokeEndpointRefusesOtherPrincipalsKeys(t *testing.T) {
	body := []byte(`{"FunctionName":"missing","ServicePrincipal":"secretsmanager.amazonaws.com"}`)
	for what, p := range map[string]keysource.Principal{
		"another account's root": {
			AccountID: "111111111111", ARN: "arn:aws:iam::111111111111:root",
			PrincipalARN: "arn:aws:iam::111111111111:root", UserID: "111111111111",
			AccessKeyID: userKeyID, PrincipalType: string(sigv4.PrincipalTypeAccount), Root: true,
		},
		"a role session": principalOf("000000000000",
			"arn:aws:sts::000000000000:assumed-role/admin/s"),
	} {
		t.Run(what, func(t *testing.T) {
			t.Setenv("TULE_Auth_IdentityEndpoint", fakeIdentityOf(t, p).URL)
			_, srv := startApp(t)
			status, e := serviceCall(t, srv.URL, userKeyID, userSecret, "lambda", body)
			if status != http.StatusForbidden || e.Code != "UnknownAccessKey" {
				t.Fatalf("got %d %+v, want 403 UnknownAccessKey", status, e)
			}
		})
	}
}

// fixedKeys is a key source that answers every scope with one principal.
type fixedKeys struct {
	p sigv4.Principal
}

func (f fixedKeys) SigningKey(context.Context, sigv4.Scope) (sigv4.Key, error) {
	return sigv4.Key{Signing: []byte("k"), Principal: f.p}, nil
}

func TestRootOnlyPassesTheServicesOwnRootAlone(t *testing.T) {
	root := sigv4.Principal{Root: true, Type: sigv4.PrincipalTypeAccount, AccountID: "000000000000"}
	other := root
	other.AccountID = "111111111111"
	user := sigv4.Principal{Type: sigv4.PrincipalTypeUser, AccountID: "000000000000"}
	for what, c := range map[string]struct {
		want error
		p    sigv4.Principal
	}{
		"the service's root":     {p: root},
		"another account's root": {p: other, want: sigv4.ErrUnknownAccessKey},
		"a user":                 {p: user, want: sigv4.ErrUnknownAccessKey},
	} {
		_, err := rootOnly{keys: fixedKeys{c.p}, account: "000000000000"}.
			SigningKey(t.Context(), sigv4.Scope{})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", what, err, c.want)
		}
	}
}
