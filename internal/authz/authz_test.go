package authz

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"tule.dev/sigv4"
)

const (
	userARN    = "arn:aws:iam::123456789012:user/dev/alice"
	sessionARN = "arn:aws:sts::123456789012:assumed-role/runner/s1"
	fnARN      = "arn:aws:lambda:us-east-1:123456789012:function:f"
)

var now = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

func signed(p sigv4.Principal) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:4242"
	return r.WithContext(sigv4.NewContext(r.Context(), p))
}

func user(docs ...string) sigv4.Principal {
	p := sigv4.Principal{AccountID: "123456789012", ARN: userARN}
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	return p
}

func reqs(rs ...Request) func() ([]Request, error) {
	return func() ([]Request, error) { return rs, nil }
}

func allow(action, resource string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"` + action +
		`","Resource":"` + resource + `"}}`
}

func TestRootIsNeverEvaluated(t *testing.T) {
	a := New("123456789012", "us-east-1", func() time.Time { return now })
	built := false
	err := a.Authorize(signed(sigv4.Principal{
		Root: true, AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root",
	}),
		func() ([]Request, error) {
			built = true
			return nil, nil
		})
	if err != nil || built {
		t.Fatalf("root: err %v, built %v", err, built)
	}
}

func TestAnUnverifiedRequestFails(t *testing.T) {
	err := New(
		"123456789012",
		"us-east-1",
		time.Now,
	).Authorize(httptest.NewRequest(http.MethodGet, "/", nil), reqs())
	if !errors.Is(err, ErrNoPrincipal) {
		t.Fatalf("got %v", err)
	}
}

func TestNoPolicyIsDeniedInAWSsWords(t *testing.T) {
	err := New("123456789012", "us-east-1", time.Now).Authorize(signed(user()),
		reqs(Request{Action: "lambda:GetFunction", Resource: fnARN}))
	var d *Denied
	if !errors.As(err, &d) || d.Why != NoIdentityPolicy {
		t.Fatalf("got %v", err)
	}
	want := "User: " + userARN + " is not authorized to perform: lambda:GetFunction on " +
		"resource: " + fnARN + " because no identity-based policy allows the " +
		"lambda:GetFunction action"
	if err.Error() != want {
		t.Fatalf("message\n got %s\nwant %s", err, want)
	}
}

func TestAnExplicitDenyWinsAndSaysSo(t *testing.T) {
	deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"lambda:*",` +
		`"Resource":"*"}}`
	err := New(
		"123456789012",
		"us-east-1",
		time.Now,
	).Authorize(signed(user(allow("lambda:GetFunction", "*"), deny)),
		reqs(Request{Action: "lambda:GetFunction", Resource: fnARN}))
	var d *Denied
	if !errors.As(err, &d) || d.Why != ExplicitDeny {
		t.Fatalf("got %v", err)
	}
	if !strings.HasSuffix(err.Error(), "on resource: "+fnARN+
		" with an explicit deny in an identity-based policy") {
		t.Fatalf("message %s", err)
	}
}

func TestEveryRequestMustBeAllowed(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	p := user(allow("lambda:CreateFunction", "*"))
	err := a.Authorize(signed(p), reqs(
		Request{Action: "lambda:CreateFunction", Resource: fnARN},
		Request{Action: "iam:PassRole", Resource: "arn:aws:iam::123456789012:role/r"},
	))
	var d *Denied
	if !errors.As(err, &d) || d.Action != "iam:PassRole" {
		t.Fatalf("got %v", err)
	}
	if err = a.Authorize(signed(p),
		reqs(Request{Action: "lambda:CreateFunction", Resource: fnARN})); err != nil {
		t.Fatalf("allowed alone: %v", err)
	}
}

func TestARequestKeyIsEvaluated(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"lambda:GetFunction",` +
		`"Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"a"}}}}`
	a := New("123456789012", "us-east-1", time.Now)
	for team, ok := range map[string]bool{"a": true, "b": false} {
		err := a.Authorize(signed(user(doc)), reqs(Request{
			Action: "lambda:GetFunction", Resource: fnARN,
			Context: map[string][]string{"aws:ResourceTag/team": {team}},
		}))
		if (err == nil) != ok {
			t.Errorf("team %s: %v", team, err)
		}
	}
}

func TestAMalformedPolicyFailsClosed(t *testing.T) {
	err := New(
		"123456789012",
		"us-east-1",
		time.Now,
	).Authorize(signed(user(`{"Statement":`)), reqs())
	var d *Denied
	if err == nil || errors.As(err, &d) {
		t.Fatalf("got %v", err)
	}
}

func TestTheContextIsCapped(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	p := user(allow("*", "*"))
	cases := map[string]map[string][]string{
		"values": {"aws:TagKeys": make([]string, maxValues+1)},
		"length": {"aws:RequestTag/k": {strings.Repeat("x", maxValueLength+1)}},
		"keys":   manyKeys(maxKeys + 1),
		"key":    {"aws:RequestTag/" + strings.Repeat("k", maxKeyLength): {"v"}},
	}
	for name, ctx := range cases {
		err := a.Authorize(signed(p), reqs(Request{
			Action:   "lambda:TagResource",
			Resource: fnARN, Context: ctx,
		}))
		var tl *TooLarge
		if !errors.As(err, &tl) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if err := a.Authorize(signed(p), reqs(Request{
		Action:   "lambda:TagResource",
		Resource: fnARN, Context: map[string][]string{"aws:TagKeys": make([]string, maxValues)},
	},
	)); err != nil {
		t.Errorf("at the cap: %v", err)
	}
}

func manyKeys(n int) map[string][]string {
	m := map[string][]string{}
	for i := range n {
		m["aws:RequestTag/k"+strings.Repeat("x", i)] = []string{"v"}
	}
	return m
}

func TestParsedPoliciesAreCachedAndBounded(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	doc := allow("lambda:GetFunction", "*")
	for range 2 {
		if err := a.Authorize(signed(user(doc)),
			reqs(Request{Action: "lambda:GetFunction", Resource: fnARN})); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.cache) != 1 {
		t.Fatalf("cache holds %d", len(a.cache))
	}
	for i := range maxCached + 1 {
		doc = allow("lambda:GetFunction", "arn:aws:lambda:*:*:function:"+strings.Repeat("f", i+1))
		if err := a.Authorize(signed(user(doc)), reqs()); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.cache) > maxCached {
		t.Fatalf("cache holds %d, over %d", len(a.cache), maxCached)
	}
}

func TestTheGlobalKeysOfAUser(t *testing.T) {
	p := user()
	got := GlobalKeys(signed(p), &p, "us-east-1", now)
	want := map[string][]string{
		"aws:SourceIp":         {"203.0.113.7"},
		"aws:RequestedRegion":  {"us-east-1"},
		"aws:CurrentTime":      {"2026-11-13T10:00:00Z"},
		"aws:EpochTime":        {"1794564000"},
		"aws:SecureTransport":  {"false"},
		"aws:PrincipalAccount": {"123456789012"},
		"aws:PrincipalArn":     {userARN},
		"aws:PrincipalType":    {"User"},
		"aws:username":         {"alice"},
	}
	requireKeys(t, got, want)
}

func TestTheGlobalKeysOfARoleSession(t *testing.T) {
	p := sigv4.Principal{AccountID: "123456789012", ARN: sessionARN}
	r := signed(p)
	r.TLS = &tls.ConnectionState{}
	got := GlobalKeys(r, &p, "us-east-1", now)
	if _, ok := got["aws:username"]; ok {
		t.Error("a session has aws:username")
	}
	requireKeys(t, got, map[string][]string{
		"aws:PrincipalArn":    {"arn:aws:iam::123456789012:role/runner"},
		"aws:PrincipalType":   {"AssumedRole"},
		"aws:SecureTransport": {"true"},
	})
}

func TestASourceIpConditionIsHonored(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*",` +
		`"Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}}`
	a := New("123456789012", "us-east-1", time.Now)
	r := signed(user(doc))
	if err := a.Authorize(
		r,
		reqs(Request{Action: "lambda:GetFunction", Resource: fnARN}),
	); err != nil {
		t.Fatalf("inside the range: %v", err)
	}
	r.RemoteAddr = "198.51.100.1:1"
	if err := a.Authorize(
		r,
		reqs(Request{Action: "lambda:GetFunction", Resource: fnARN}),
	); err == nil {
		t.Fatal("outside the range: allowed")
	}
}

func TestARoleSessionMatchesItsRolesARN(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*",` +
		`"Condition":{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/runner"}}}}`
	p := sigv4.Principal{
		AccountID: "123456789012", ARN: sessionARN,
		Policies: []json.RawMessage{json.RawMessage(doc)},
	}
	if err := New("123456789012", "us-east-1", time.Now).Authorize(signed(p),
		reqs(Request{Action: "lambda:GetFunction", Resource: fnARN})); err != nil {
		t.Fatal(err)
	}
}

func requireKeys(t *testing.T, got, want map[string][]string) {
	t.Helper()
	for k, v := range want {
		if !slices.Equal(got[k], v) {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestAnotherAccountsPrincipalIsDenied(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	member := func(docs ...string) sigv4.Principal {
		p := sigv4.Principal{
			AccountID: "999999999999",
			ARN:       "arn:aws:sts::999999999999:assumed-role/OrganizationAccountAccessRole/s",
		}
		for _, d := range docs {
			p.Policies = append(p.Policies, json.RawMessage(d))
		}
		return p
	}
	get := reqs(Request{Action: "lambda:GetFunction", Resource: fnARN})
	for name, tt := range map[string]struct {
		tail string
		p    sigv4.Principal
		why  Denial
	}{
		"allowed": {
			p:    member(allow("*", "*")),
			why:  NoResourcePolicy,
			tail: "because no resource-based policy allows the lambda:GetFunction action",
		},
		"no policy": {
			p:    member(),
			why:  NoIdentityPolicy,
			tail: "because no identity-based policy allows the lambda:GetFunction action",
		},
		"denied": {
			p: member(allow("*", "*"), `{"Version":"2012-10-17","Statement":{"Effect":`+
				`"Deny","Action":"*","Resource":"*"}}`),
			why:  ExplicitDeny,
			tail: "with an explicit deny in an identity-based policy",
		},
	} {
		err := a.Authorize(signed(tt.p), get)
		var d *Denied
		if !errors.As(err, &d) || d.Why != tt.why || !strings.HasSuffix(err.Error(), tt.tail) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestRootOfAnotherAccountIsRefused(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	other := sigv4.Principal{
		Root: true, AccountID: "999999999999",
		ARN: "arn:aws:iam::999999999999:root",
	}
	err := a.Authorize(signed(other), reqs(Request{Action: "lambda:GetFunction", Resource: fnARN}))
	var d *Denied
	if !errors.As(err, &d) || d.Why != NoIdentityPolicy {
		t.Fatalf("got %v", err)
	}
}

// TestTheStaticKeyUnderAConfiguredAccountIsRoot checks a StaticKey of a
// non-default account, as the app builds it, against an Authorizer of that
// account.
func TestTheStaticKeyUnderAConfiguredAccountIsRoot(t *testing.T) {
	const account = "123456789012"
	key, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID: "test", SecretAccessKey: "test", AccountID: account,
		ARN: "arn:aws:iam::" + account + ":root",
	})
	if err != nil {
		t.Fatal(err)
	}
	k, err := key.SigningKey(t.Context(), sigv4.Scope{
		AccessKeyID: "test",
		Date:        "20261113", Region: "us-east-1", Service: "lambda",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = New(
		account,
		"us-east-1",
		time.Now,
	).Authorize(signed(k.Principal), func() ([]Request, error) {
		t.Fatal("root was evaluated")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}
