package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go"
	"tule.dev/identity/keysource"
	"tule.dev/identity/principals"
)

// directory is the users and roles the fake identity's principal-ID
// endpoint knows, by ARN and unique ID. It does not check the caller's
// signature: the real endpoint is exercised by the end-to-end tests.
type directory struct {
	ids map[string]string // ARN to unique ID
	// hold, while set, holds each call until it is closed, after telling
	// entered that the call arrived.
	hold    chan struct{}
	entered chan struct{}
	calls   int
	fail    bool
	mu      sync.Mutex
}

// directoryOf is a directory holding p's user, or its session's role.
func directoryOf(p keysource.Principal) *directory {
	id, _, _ := strings.Cut(p.UserID, ":")
	return &directory{ids: map[string]string{p.PrincipalARN: id}}
}

// rename gives the user or role with the ARN from the ARN to, keeping its
// unique ID, as IAM's UpdateUser does.
func (d *directory) rename(from, to string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ids[to] = d.ids[from]
	delete(d.ids, from)
}

// failing makes the endpoint answer 500 while on is set.
func (d *directory) failing(on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fail = on
}

// called is how many calls the endpoint has answered.
func (d *directory) called() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// holding holds each call from now until the returned release is called,
// and returns a channel that receives once per call held.
func (d *directory) holding(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hold, d.entered = make(chan struct{}), make(chan struct{}, 16)
	hold, once := d.hold, sync.Once{}
	release := func() {
		once.Do(func() {
			d.mu.Lock()
			d.hold = nil
			d.mu.Unlock()
			close(hold)
		})
	}
	t.Cleanup(release)
	return d.entered, release
}

func (d *directory) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.calls++
	if hold := d.hold; hold != nil {
		entered := d.entered
		d.mu.Unlock()
		entered <- struct{}{}
		<-hold
		d.mu.Lock()
	}
	defer d.mu.Unlock()
	if d.fail {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(principals.ErrorResponse{Code: "InternalFailure"})
		return
	}
	var req principals.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	out := principals.Response{IDs: map[string]string{}, ARNs: map[string]string{}}
	for _, arn := range req.ARNs {
		if id, ok := d.ids[arn]; ok {
			out.IDs[arn] = id
		}
	}
	for arn, id := range d.ids {
		for _, want := range req.IDs {
			if id == want {
				out.ARNs[id] = arn
			}
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

// boundStack is the app with a fake identity whose directory the test
// changes, a root client and the user's client.
type boundStack struct {
	dir  *directory
	root *lambda.Client
	user *lambda.Client
}

func startBoundStack(t *testing.T) *boundStack {
	t.Helper()
	dir := directoryOf(principalOf("000000000000", userARN))
	t.Setenv("TULE_Auth_IdentityEndpoint",
		fakeIdentityWith(t, dir, "000000000000", userARN).URL)
	root, srv := startApp(t)
	createActiveOrFailed(t, root, "fn")
	return &boundStack{dir: dir, root: root, user: userClient(srv)}
}

// policies are the function policy as GetPolicy and GetResourcePolicy
// answer it.
func (s *boundStack) policies(t *testing.T) map[string]string {
	t.Helper()
	got, err := s.root.GetPolicy(t.Context(),
		&lambda.GetPolicyInput{FunctionName: aws.String("fn")})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	whole, err := s.root.GetResourcePolicy(t.Context(),
		&lambda.GetResourcePolicyInput{ResourceArn: aws.String(fnARN)})
	if err != nil {
		t.Fatalf("GetResourcePolicy: %v", err)
	}
	return map[string]string{
		"GetPolicy":         aws.ToString(got.Policy),
		"GetResourcePolicy": aws.ToString(whole.Policy),
	}
}

// requireShown fails unless every read of the policy names want and not
// gone.
func (s *boundStack) requireShown(t *testing.T, want, gone string) {
	t.Helper()
	for op, doc := range s.policies(t) {
		if !strings.Contains(doc, `"`+want+`"`) || strings.Contains(doc, `"`+gone+`"`) {
			t.Errorf("%s: %s, want %s and not %s", op, doc, want, gone)
		}
	}
}

const (
	userID      = "AIDAEXAMPLEUSER00001"
	renamedARN  = "arn:aws:iam::000000000000:user/renamed"
	missingUser = "arn:aws:iam::000000000000:user/nobody"
)

// TestEveryWriteBindsAndEveryReadShows writes the policy by each write
// path, renames the user it names, and reads it by each read path: only a
// policy stored bound and shown through identity names the user by its new
// ARN, so a write that skips Bind or a read that skips Show fails.
func TestEveryWriteBindsAndEveryReadShows(t *testing.T) {
	for name, write := range writePaths() {
		t.Run(name, func(t *testing.T) {
			s := startBoundStack(t)
			write(t, s)
			s.requireShown(t, userARN, userID)
			if _, err := s.user.GetFunction(t.Context(),
				&lambda.GetFunctionInput{FunctionName: aws.String("fn")}); err != nil {
				t.Fatalf("granted by its unique ID: %v", err)
			}
			s.dir.rename(userARN, renamedARN)
			s.requireShown(t, renamedARN, userARN)
		})
	}
}

// writePaths write a policy granting lambda:GetFunction to the user by
// each operation that stores one, and check the policy each answers with.
func writePaths() map[string]func(t *testing.T, s *boundStack) {
	return map[string]func(t *testing.T, s *boundStack){
		"AddPermission": func(t *testing.T, s *boundStack) {
			added, err := s.root.AddPermission(t.Context(), addPermission("user", userARN))
			if err != nil {
				t.Fatal(err)
			}
			if st := aws.ToString(added.Statement); !strings.Contains(st, `"`+userARN+`"`) {
				t.Errorf("the statement added: %s", st)
			}
		},
		"PutResourcePolicy": func(t *testing.T, s *boundStack) {
			put, err := s.root.PutResourcePolicy(t.Context(), &lambda.PutResourcePolicyInput{
				ResourceArn: aws.String(fnARN),
				Policy: aws.String(`{"Version":"2012-10-17","Statement":[{"Sid":"user",` +
					`"Effect":"Allow","Principal":{"AWS":"` + userARN + `"},` +
					`"Action":"lambda:GetFunction","Resource":"` + fnARN + `"}]}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			if doc := aws.ToString(put.Policy); !strings.Contains(doc, `"`+userARN+`"`) ||
				strings.Contains(doc, userID) {
				t.Errorf("the policy put: %s", doc)
			}
		},
		"RemovePermission": func(t *testing.T, s *boundStack) {
			for _, sid := range []string{"user", "other"} {
				if _, err := s.root.AddPermission(t.Context(),
					addPermission(sid, userARN)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.root.RemovePermission(t.Context(), &lambda.RemovePermissionInput{
				FunctionName: aws.String("fn"), StatementId: aws.String("other"),
			}); err != nil {
				t.Fatal(err)
			}
		},
	}
}

// TestAPrincipalThatDoesNotExistIsRefused checks each write's refusal of a
// user no user has, and that nothing is stored.
func TestAPrincipalThatDoesNotExistIsRefused(t *testing.T) {
	s := startBoundStack(t)
	_, err := s.root.AddPermission(t.Context(), addPermission("nobody", missingUser))
	requireMessage(t, "AddPermission", err, "InvalidParameterValueException",
		http.StatusBadRequest,
		"The provided principal was invalid. Please check the principal and try again.")
	_, err = s.root.PutResourcePolicy(t.Context(), &lambda.PutResourcePolicyInput{
		ResourceArn: aws.String(fnARN),
		Policy: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":["` + userARN + `","` + missingUser + `"]},` +
			`"Action":"lambda:GetFunction","Resource":"` + fnARN + `"}}`),
	})
	requireMessage(t, "PutResourcePolicy", err, "InvalidParameterValueException",
		http.StatusBadRequest,
		"The provided principal was invalid. Please check the principal and try again.")
	_, err = s.root.GetPolicy(t.Context(), &lambda.GetPolicyInput{FunctionName: aws.String("fn")})
	requireCode(t, "nothing stored", err, "ResourceNotFoundException", http.StatusNotFound)
}

// TestIdentityUnreachableFailsWritesAndReads checks that a write fails,
// storing nothing, and a read fails, while the principal-ID endpoint fails,
// and that a policy naming no user or role needs no call.
func TestIdentityUnreachableFailsWritesAndReads(t *testing.T) {
	s := startBoundStack(t)
	if _, err := s.root.AddPermission(t.Context(), addPermission("user", userARN)); err != nil {
		t.Fatal(err)
	}
	before := s.policies(t)
	s.dir.failing(true)
	_, err := s.root.AddPermission(t.Context(), addPermission("again", userARN))
	requireCode(t, "AddPermission", err, "ServiceException", http.StatusInternalServerError)
	_, err = s.root.PutResourcePolicy(t.Context(), &lambda.PutResourcePolicyInput{
		ResourceArn: aws.String(fnARN),
		Policy: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":"` + userARN + `"},"Action":"lambda:GetFunction",` +
			`"Resource":"` + fnARN + `"}}`),
	})
	requireCode(t, "PutResourcePolicy", err, "ServiceException", http.StatusInternalServerError)
	_, err = s.root.GetPolicy(t.Context(), &lambda.GetPolicyInput{FunctionName: aws.String("fn")})
	requireCode(t, "GetPolicy", err, "ServiceException", http.StatusInternalServerError)
	_, err = s.root.GetResourcePolicy(t.Context(),
		&lambda.GetResourcePolicyInput{ResourceArn: aws.String(fnARN)})
	requireCode(t, "GetResourcePolicy", err, "ServiceException", http.StatusInternalServerError)
	if _, err = s.user.GetFunction(t.Context(),
		&lambda.GetFunctionInput{FunctionName: aws.String("fn")}); err != nil {
		t.Fatalf("evaluation needs no call: %v", err)
	}
	if _, err = s.root.AddPermission(t.Context(),
		addPermission("account", "111122223333")); err != nil {
		t.Fatalf("an account principal needs no call: %v", err)
	}
	s.dir.failing(false)
	after := s.policies(t)
	if !strings.Contains(after["GetPolicy"], `"Sid":"account"`) ||
		strings.Contains(after["GetPolicy"], `"Sid":"again"`) ||
		!strings.HasPrefix(after["GetPolicy"], strings.TrimSuffix(before["GetPolicy"], "]}")) {
		t.Fatalf("before %s\nafter %s", before["GetPolicy"], after["GetPolicy"])
	}
}

// TestADeniedCallerCausesNoPrincipalCall has a caller with no policy write
// a policy naming a user by AddPermission and PutResourcePolicy: both are
// denied before the policy is bound, so identity's principal-ID endpoint is
// never called.
func TestADeniedCallerCausesNoPrincipalCall(t *testing.T) {
	s := startBoundStack(t)
	_, err := s.user.AddPermission(t.Context(), addPermission("user", userARN))
	requireDenied(t, err, "lambda:AddPermission", fnARN)
	_, err = s.user.PutResourcePolicy(t.Context(), &lambda.PutResourcePolicyInput{
		ResourceArn: aws.String(fnARN),
		Policy: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":"` + userARN + `"},"Action":"lambda:GetFunction",` +
			`"Resource":"` + fnARN + `"}}`),
	})
	requireDenied(t, err, "lambda:PutResourcePolicy", fnARN)
	if n := s.dir.called(); n != 0 {
		t.Fatalf("the principal-ID endpoint was called %d times", n)
	}
	// The same writes by the root key do call it, so the count above is
	// the endpoint's.
	if _, err = s.root.AddPermission(t.Context(), addPermission("user", userARN)); err != nil {
		t.Fatal(err)
	}
	if s.dir.called() == 0 {
		t.Fatal("the root key's AddPermission did not call the principal-ID endpoint")
	}
}

// TestAHeldShowHoldsUpNoInvoke holds the principal-ID endpoint while a
// GetPolicy shows the policy, then removes a statement, which takes the
// function's lock for writing, and invokes the function: neither waits for
// the GetPolicy, since a read releases the lock before showing the policy.
// Were it held, the removal would wait for it, and the Invoke behind the
// waiting removal.
func TestAHeldShowHoldsUpNoInvoke(t *testing.T) {
	s := startBoundStack(t)
	for _, in := range []*lambda.AddPermissionInput{
		addPermission("user", userARN), addPermission("account", "111122223333"),
	} {
		if _, err := s.root.AddPermission(t.Context(), in); err != nil {
			t.Fatal(err)
		}
	}
	entered, release := s.dir.holding(t)
	got := make(chan error, 1)
	go func() {
		got <- errOf(s.root.GetPolicy(t.Context(),
			&lambda.GetPolicyInput{FunctionName: aws.String("fn")}))
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("GetPolicy never asked identity")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := s.root.RemovePermission(ctx, &lambda.RemovePermissionInput{
		FunctionName: aws.String("fn"), StatementId: aws.String("account"),
	}); err != nil {
		t.Fatalf("RemovePermission while a Show is held: %v", err)
	}
	_, err := s.root.Invoke(ctx, &lambda.InvokeInput{FunctionName: aws.String("fn")})
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Invoke waited for the held Show: %v", err)
	}
	release()
	if err = <-got; err != nil {
		t.Fatalf("GetPolicy once released: %v", err)
	}
}

// requireMessage is requireCode that also checks the message.
func requireMessage(t *testing.T, what string, err error, code string, status int, msg string) {
	t.Helper()
	requireCode(t, what, err, code, status)
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorMessage() != msg {
		t.Fatalf("%s: message %q, want %q", what, apiErr.ErrorMessage(), msg)
	}
}
