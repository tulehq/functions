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

	"tule.dev/policy"
	"tule.dev/sigv4"
)

const (
	userARN    = "arn:aws:iam::123456789012:user/dev/alice"
	userID     = "AIDAEXAMPLEUSER00001"
	sessionARN = "arn:aws:sts::123456789012:assumed-role/runner/s1"
	roleARN    = "arn:aws:iam::123456789012:role/ci/runner"
	roleID     = "AROAEXAMPLEROLE00001"
	fnARN      = "arn:aws:lambda:us-east-1:123456789012:function:f"
)

var now = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

func signed(p sigv4.Principal) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:4242"
	return r.WithContext(sigv4.NewContext(r.Context(), p))
}

// user is an IAM user of the service's account, with the attributes
// identity's signing-key endpoint gives at version 3.
func user(docs ...string) sigv4.Principal {
	p := sigv4.Principal{
		AccountID: "123456789012", ARN: userARN, PrincipalARN: userARN,
		UserID: userID, Type: sigv4.PrincipalTypeUser,
	}
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	return p
}

func reqs(rs ...Request) func() ([]Request, error) {
	return func() ([]Request, error) { return rs, nil }
}

// session is a session of the role runner, at the path /ci/, of account.
func session(account string, docs ...string) sigv4.Principal {
	p := sigv4.Principal{
		AccountID:    account,
		ARN:          "arn:aws:sts::" + account + ":assumed-role/runner/s1",
		PrincipalARN: "arn:aws:iam::" + account + ":role/ci/runner",
		UserID:       roleID + ":s1",
		Type:         sigv4.PrincipalTypeAssumedRole,
	}
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	return p
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
		PrincipalARN: "arn:aws:iam::123456789012:root", UserID: "123456789012",
		Type: sigv4.PrincipalTypeAccount,
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
	if !errors.As(err, &d) || d.Why != policy.NoIdentityAllow {
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
	if !errors.As(err, &d) || d.Why != policy.IdentityDeny {
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
	p.Tags = map[string]string{"team": "a"}
	got := GlobalKeys(signed(p), &p, "us-east-1", now)
	want := map[string][]string{
		"aws:SourceIp":          {"203.0.113.7"},
		"aws:RequestedRegion":   {"us-east-1"},
		"aws:CurrentTime":       {"2026-11-13T10:00:00Z"},
		"aws:EpochTime":         {"1794564000"},
		"aws:SecureTransport":   {"false"},
		"aws:PrincipalTag/team": {"a"},
	}
	requireKeys(t, got, want)
	if len(got) != len(want) {
		t.Errorf("keys %v, want only %v", got, want)
	}
}

func TestTheGlobalKeysOverTLS(t *testing.T) {
	p := session("123456789012")
	r := signed(p)
	r.TLS = &tls.ConnectionState{}
	requireKeys(t, GlobalKeys(r, &p, "us-east-1", now), map[string][]string{
		"aws:SecureTransport": {"true"},
	})
}

func TestTheCallerIsThePrincipals(t *testing.T) {
	p := session("123456789012")
	got := CallerOf(&p)
	want := policy.Caller{
		AccountID: "123456789012", ARN: sessionARN, PrincipalARN: roleARN,
		UserID: roleID + ":s1", Type: policy.PrincipalTypeAssumedRole,
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
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

// TestARoleSessionMatchesItsRolesARNWithItsPath checks aws:PrincipalArn of
// a session: its role's ARN with the role's path, so a condition on the path
// applies and one on the path-less ARN does not.
func TestARoleSessionMatchesItsRolesARNWithItsPath(t *testing.T) {
	cond := func(arn string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*",` +
			`"Resource":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"` + arn + `"}}}}`
	}
	a := New("123456789012", "us-east-1", time.Now)
	get := reqs(Request{Action: "lambda:GetFunction", Resource: fnARN})
	for arn, ok := range map[string]bool{
		roleARN:                                 true,
		"arn:aws:iam::123456789012:role/ci/*":   true,
		"arn:aws:iam::123456789012:role/runner": false,
	} {
		if err := a.Authorize(signed(session("123456789012", cond(arn))), get); (err == nil) != ok {
			t.Errorf("%s: %v", arn, err)
		}
	}
}

func TestAPrincipalTagConditionIsHonored(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*",` +
		`"Condition":{"StringEquals":{"aws:PrincipalTag/team":"a"}}}}`
	a := New("123456789012", "us-east-1", time.Now)
	get := reqs(Request{Action: "lambda:GetFunction", Resource: fnARN})
	for team, ok := range map[string]bool{"a": true, "b": false} {
		p := user(doc)
		p.Tags = map[string]string{"Team": team}
		if err := a.Authorize(signed(p), get); (err == nil) != ok {
			t.Errorf("team %s: %v", team, err)
		}
	}
}

// TestASessionWhoseRoleWasDeletedIsDenied checks the orphaned session rule:
// an empty PrincipalARN is never derived from the session's ARN.
func TestASessionWhoseRoleWasDeletedIsDenied(t *testing.T) {
	p := session("123456789012", allow("*", "*"))
	p.PrincipalARN = ""
	err := New("123456789012", "us-east-1", time.Now).Authorize(signed(p),
		reqs(Request{Action: "lambda:GetFunction", Resource: fnARN}))
	var d *Denied
	if !errors.As(err, &d) || d.Why != policy.NoIdentityAllow {
		t.Fatalf("got %v", err)
	}
}

// grant is a function policy allowing action on fnARN to principal, a JSON
// value of the Principal element.
func grant(effect, principal, action string) string {
	return `{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"s","Effect":"` +
		effect + `","Principal":` + principal + `,"Action":"` + action +
		`","Resource":"` + fnARN + `"}]}`
}

func TestTheResourcePolicyIsEvaluated(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	const get = "lambda:GetFunction"
	other := session("999999999999", allow("*", "*"))
	for name, tt := range map[string]struct {
		policy string
		p      sigv4.Principal
		why    policy.Reason
	}{
		"same account, granted by name": {
			p: user(), policy: grant("Allow", `{"AWS":"`+userARN+`"}`, get),
		},
		"same account, granted by role ARN": {
			p: session("123456789012"), policy: grant("Allow", `{"AWS":"`+roleARN+`"}`, get),
		},
		"same account, granted to the account only": {
			p: user(), policy: grant("Allow", `{"AWS":"123456789012"}`, get),
			why: policy.NoIdentityAllow,
		},
		"same account, account grant and identity allow": {
			p: user(allow(get, "*")), policy: grant("Allow", `{"AWS":"123456789012"}`, get),
		},
		"same account, resource deny": {
			p: user(allow("*", "*")), policy: grant("Deny", `"*"`, get),
			why: policy.ResourceDeny,
		},
		"another account, no resource policy": {
			p: other, why: policy.NoResourceAllow,
		},
		"another account, granted": {
			p: other, policy: grant("Allow", `{"AWS":"999999999999"}`, get),
		},
		"another account, granted another action": {
			p: other, policy: grant("Allow", `{"AWS":"999999999999"}`, "lambda:InvokeFunction"),
			why: policy.NoResourceAllow,
		},
		"another account, granted without an identity allow": {
			p: session("999999999999"), policy: grant("Allow", `{"AWS":"999999999999"}`, get),
			why: policy.NoIdentityAllow,
		},
		"another account, resource deny": {
			p: other, policy: grant("Deny", `{"AWS":"999999999999"}`, get),
			why: policy.ResourceDeny,
		},
	} {
		err := a.Authorize(signed(tt.p),
			reqs(Request{Action: get, Resource: fnARN, Policy: tt.policy}))
		if tt.why == policy.NoReason {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		var d *Denied
		if !errors.As(err, &d) || d.Why != tt.why ||
			!strings.HasSuffix(err.Error(), "on resource: "+fnARN+" "+tt.why.Message(get)) {
			t.Errorf("%s: got %v, want %s", name, err, tt.why)
		}
	}
}

func TestTheResourceBasedMessages(t *testing.T) {
	for why, tail := range map[policy.Reason]string{
		policy.IdentityDeny:    "with an explicit deny in an identity-based policy",
		policy.ResourceDeny:    "with an explicit deny in a resource-based policy",
		policy.NoIdentityAllow: "because no identity-based policy allows the lambda:X action",
		policy.NoResourceAllow: "because no resource-based policy allows the lambda:X action",
	} {
		d := &Denied{Principal: userARN, Action: "lambda:X", Resource: fnARN, Why: why}
		want := "User: " + userARN + " is not authorized to perform: lambda:X on resource: " +
			fnARN + " " + tail
		if d.Error() != want {
			t.Errorf("%s:\n got %s\nwant %s", why, d.Error(), want)
		}
	}
}

func TestAStoredPolicyThatDoesNotParseFailsClosed(t *testing.T) {
	err := New("123456789012", "us-east-1", time.Now).Authorize(signed(user(allow("*", "*"))),
		reqs(Request{Action: "lambda:GetFunction", Resource: fnARN, Policy: `{"Statement":`}))
	if !errors.Is(err, ErrStoredPolicy) {
		t.Fatalf("got %v", err)
	}
}

// TestTheSameDocumentIsCachedPerKind checks that a document parsed as an
// identity policy is not served from the cache as a resource-based one.
func TestTheSameDocumentIsCachedPerKind(t *testing.T) {
	doc := allow("*", "*")
	a := New("123456789012", "us-east-1", time.Now)
	if err := a.Authorize(signed(user(doc)), reqs()); err != nil {
		t.Fatal(err)
	}
	err := a.Authorize(signed(user(doc)),
		reqs(Request{Action: "lambda:GetFunction", Resource: fnARN, Policy: doc}))
	if !errors.Is(err, ErrStoredPolicy) {
		t.Fatalf("an identity policy as a resource policy: %v", err)
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

func TestRootOfAnotherAccountNeedsAResourceGrant(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	other := sigv4.Principal{
		Root: true, AccountID: "999999999999", ARN: "arn:aws:iam::999999999999:root",
		PrincipalARN: "arn:aws:iam::999999999999:root", UserID: "999999999999",
		Type: sigv4.PrincipalTypeAccount,
	}
	err := a.Authorize(signed(other), reqs(Request{Action: "lambda:GetFunction", Resource: fnARN}))
	var d *Denied
	if !errors.As(err, &d) || d.Why != policy.NoResourceAllow {
		t.Fatalf("no resource policy: %v", err)
	}
	if err = a.Authorize(signed(other), reqs(Request{
		Action: "lambda:GetFunction", Resource: fnARN,
		Policy: grant("Allow", `{"AWS":"999999999999"}`, "lambda:GetFunction"),
	})); err != nil {
		t.Fatalf("granted by the resource policy: %v", err)
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

// TestRootAndTypeMustAgree checks that a principal whose Root and Type
// disagree is a fault, never evaluated or skipped.
func TestRootAndTypeMustAgree(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	rootARN := "arn:aws:iam::123456789012:root"
	for name, p := range map[string]sigv4.Principal{
		"an account that is not root": {
			AccountID: "123456789012", ARN: rootARN, PrincipalARN: rootARN,
			UserID: "123456789012", Type: sigv4.PrincipalTypeAccount,
			Policies: []json.RawMessage{json.RawMessage(allow("*", "*"))},
		},
		"root of another type": func() sigv4.Principal {
			p := user()
			p.Root = true
			return p
		}(),
		"root of no type": {Root: true, AccountID: "123456789012", ARN: rootARN},
	} {
		err := a.Authorize(signed(p), func() ([]Request, error) {
			t.Errorf("%s: evaluated", name)
			return nil, nil
		})
		if !errors.Is(err, ErrInconsistentPrincipal) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// TestADenyOnlyPolicyDeniesButNeverGrants checks a request on an action the
// resource policy cannot grant: its Deny applies, and its Allow is dropped,
// so the request is decided by the identity policies within the account and
// denied across accounts.
func TestADenyOnlyPolicyDeniesButNeverGrants(t *testing.T) {
	a := New("123456789012", "us-east-1", time.Now)
	const update = "lambda:UpdateFunctionConfiguration"
	other := session("999999999999", allow("*", "*"))
	for name, tt := range map[string]struct {
		policy string
		p      sigv4.Principal
		why    policy.Reason
	}{
		"same account, granted by name only": {
			p: user(), policy: grant("Allow", `{"AWS":"`+userARN+`"}`, update),
			why: policy.NoIdentityAllow,
		},
		"same account, identity allow": {
			p: user(allow(update, "*")), policy: grant("Allow", `{"AWS":"`+userARN+`"}`, update),
		},
		"same account, resource deny": {
			p: user(allow("*", "*")), policy: grant("Deny", `"*"`, update),
			why: policy.ResourceDeny,
		},
		"another account, granted": {
			p: other, policy: grant("Allow", `{"AWS":"999999999999"}`, update),
			why: policy.NoResourceAllow,
		},
		"another account, resource deny": {
			p: other, policy: grant("Deny", `{"AWS":"999999999999"}`, update),
			why: policy.ResourceDeny,
		},
	} {
		err := a.Authorize(signed(tt.p), reqs(Request{
			Action: update, Resource: fnARN, Policy: tt.policy, DenyOnly: true,
		}))
		if tt.why == policy.NoReason {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		var d *Denied
		if !errors.As(err, &d) || d.Why != tt.why {
			t.Errorf("%s: got %v, want %s", name, err, tt.why)
		}
	}
}
