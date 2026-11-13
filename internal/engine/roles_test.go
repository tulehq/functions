package engine

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"tule.dev/identity/servicerole"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/runner"
)

// TestAnotherAccountsRoleIsNeverAssumed starts a container of a function
// stored with another account's role, as a function stored before roles
// were held to the account could be: its credentials are refused before
// identity is asked, as for a role Lambda cannot assume.
func TestAnotherAccountsRoleIsNeverAssumed(t *testing.T) {
	// An endpoint nothing listens on: the refusal must come first.
	roles, err := servicerole.New(servicerole.Config{
		Endpoint: "http://127.0.0.1:1", AccessKeyID: "AKID", SecretAccessKey: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{roles: roles, settings: &contracts.Settings{
		AccountID: "000000000000", Region: "us-east-1",
		FunctionCredentials: contracts.CredentialsRole,
	}}
	_, err = e.containerCredentials(t.Context(), &runner.Spec{
		Function: "fn", ARN: "arn:aws:lambda:us-east-1:000000000000:function:fn",
		Role: "arn:aws:iam::111111111111:role/r",
	})
	if !errors.Is(err, ErrRoleNotAssumable) {
		t.Fatalf("got %v", err)
	}
}

// fakeRoles is an assume-role endpoint that records the roles it assumes
// and answers sessions lasting an hour from now().
type fakeRoles struct {
	now     func() time.Time
	assumed []string
	mu      sync.Mutex
}

func (f *fakeRoles) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req servicerole.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.assumed = append(f.assumed, req.RoleArn)
	n := len(f.assumed)
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(servicerole.Session{Credentials: servicerole.Credentials{
		Expiration: f.now().Add(time.Hour), AccessKeyID: "ASIA" + strconv.Itoa(n),
		SecretAccessKey: "secret", SessionToken: "token",
	}})
}

func (f *fakeRoles) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.assumed)
}

// TestAMappingsRoleSessionFollowsTheFunction drives a mapping's credentials
// provider on a fake clock: the session is reused, the function's role is
// read again after a minute and a changed role assumed, and the session is
// renewed when it nears expiry.
func TestAMappingsRoleSessionFollowsTheFunction(t *testing.T) {
	clock := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	fake := &fakeRoles{now: now}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	roles, err := servicerole.New(servicerole.Config{
		Endpoint: srv.URL, AccessKeyID: "AKID", SecretAccessKey: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newStore(t)
	const first, second = "arn:aws:iam::000000000000:role/first",
		"arn:aws:iam::000000000000:role/second"
	if err = store.PutFunction(t.Context(), &contracts.Function{
		Name: "fn", ARN: "arn:aws:lambda:us-east-1:000000000000:function:fn", Role: first,
		Environment: map[string]string{}, Tags: map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	e := &Engine{store: store, roles: roles, settings: &contracts.Settings{
		AccountID: "000000000000", Region: "us-east-1",
		FunctionCredentials: contracts.CredentialsRole,
	}}
	p := &roleProvider{e: e, name: "fn", now: now}
	key := func(step string) string {
		t.Helper()
		c, rErr := p.Retrieve(t.Context())
		if rErr != nil {
			t.Fatalf("%s: %v", step, rErr)
		}
		return c.AccessKeyID
	}
	requireStep := func(step, got, want string, assumed int) {
		t.Helper()
		if got != want || fake.count() != assumed {
			t.Fatalf("%s: key %s after %d assumes, want %s after %d", step, got, fake.count(),
				want, assumed)
		}
	}

	requireStep("first", key("first"), "ASIA1", 1)
	clock = clock.Add(30 * time.Second)
	requireStep("within a minute", key("reuse"), "ASIA1", 1)

	if _, err = store.UpdateFunction(t.Context(), "fn", func(f *contracts.Function) error {
		f.Role = second
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	requireStep("changed, before the recheck", key("stale"), "ASIA1", 1)
	clock = clock.Add(31 * time.Second)
	requireStep("changed, at the recheck", key("recheck"), "ASIA2", 2)
	if fake.assumed[1] != second {
		t.Fatalf("assumed %s, want %s", fake.assumed[1], second)
	}

	clock = clock.Add(time.Hour - sessionMargin + time.Second)
	requireStep("near expiry", key("renew"), "ASIA3", 3)
}
