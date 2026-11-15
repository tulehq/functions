package lambda

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"
	"github.com/go-chi/chi/v5/middleware"
	_ "modernc.org/sqlite"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/engine"
	"tule.dev/functions/internal/runner"
	"tule.dev/functions/internal/services/functions/sqlimpl"
	"tule.dev/functions/serviceinvoke"
)

// TestAnEmptyResultIsAnsweredWithoutAPayload checks the answer to each kind
// of result. A runtime may post an empty response, which the Runtime API
// keeps as it is: it is a 200 with no Payload, as Invoke answers an empty
// 200, and only a result that is not JSON is InvalidFunctionResponse.
func TestAnEmptyResultIsAnsweredWithoutAPayload(t *testing.T) {
	for what, c := range map[string]struct {
		payload string
		status  int
	}{
		"empty":    {"", http.StatusOK},
		"JSON":     {`{"a":"<&>"}`, http.StatusOK},
		"not JSON": {"plain text", http.StatusBadGateway},
	} {
		status, v, payload := serviceResult(&runner.Result{Payload: []byte(c.payload)})
		if status != c.status {
			t.Errorf("%s: status %d, want %d", what, status, c.status)
			continue
		}
		if status == http.StatusOK && string(payload) != c.payload {
			t.Errorf("%s: payload %q, want %q", what, payload, c.payload)
		}
		if e, ok := v.(serviceinvoke.ErrorResponse); status != http.StatusOK &&
			(!ok || e.Code != serviceinvoke.CodeInvalidFunctionResponse) {
			t.Errorf("%s: document %+v", what, v)
		}
	}
}

// TestASourceArnOverTheConditionValueCapIsRefused checks that a SourceArn
// too long to be evaluated is refused with a message about SourceArn,
// rather than reaching the authorizer's cap.
func TestASourceArnOverTheConditionValueCapIsRefused(t *testing.T) {
	const prefix = "arn:aws:secretsmanager:us-east-1:000000000000:secret:"
	req := func(arn string) *serviceinvoke.Request {
		return &serviceinvoke.Request{
			ServicePrincipal: "secretsmanager.amazonaws.com", SourceArn: arn,
		}
	}
	atCap := prefix + strings.Repeat("a", authz.MaxValueLength-len(prefix))
	if r := checkServiceRequest(req(atCap)); r != nil {
		t.Fatalf("a SourceArn of %d characters: %v", len(atCap), r)
	}
	r := checkServiceRequest(req(atCap + "a"))
	if r == nil || r.status != http.StatusBadRequest ||
		r.code != serviceinvoke.CodeInvalidRequest || !strings.Contains(r.message, "SourceArn") {
		t.Fatalf("a SourceArn of %d characters: %v", len(atCap)+1, r)
	}
}

// TestADryRunIsHeldToTheRequestResponseLimit checks that checkPayload takes
// a DryRun, and holds its payload to the 6 MB of RequestResponse, as Invoke
// holds a DryRun's, not to Event's 1 MB.
func TestADryRunIsHeldToTheRequestResponseLimit(t *testing.T) {
	req := func(n int) *serviceinvoke.Request {
		return &serviceinvoke.Request{
			InvocationType: serviceinvoke.InvocationDryRun,
			Payload:        []byte(`"` + strings.Repeat("a", n-2) + `"`),
		}
	}
	if r := checkPayload(req(MaxSyncPayload)); r != nil {
		t.Fatalf("a DryRun payload of %d bytes: %v", MaxSyncPayload, r)
	}
	r := checkPayload(req(MaxSyncPayload + 1))
	if r == nil || r.status != http.StatusRequestEntityTooLarge ||
		r.code != serviceinvoke.CodeRequestTooLarge {
		t.Fatalf("a DryRun payload of %d bytes: %v", MaxSyncPayload+1, r)
	}
	r = checkPayload(&serviceinvoke.Request{InvocationType: "Dryrun"})
	if r == nil || r.status != http.StatusBadRequest || !strings.Contains(r.message, "DryRun") {
		t.Fatalf("an unknown invocation type: %v", r)
	}
}

// newStore opens a store on a fresh database, as the app wires it.
func newStore(t *testing.T) *sqlimpl.Service {
	t.Helper()
	ctx := context.Background()
	logger := &gas.NopLogger{}
	cfg := database.DefaultConfig()
	cfg.Database.Dialect = database.DialectSQLite
	cfg.Database.DSN = gas.Secret("file:" + filepath.Join(t.TempDir(), "functions.db"))
	cfg.Database.MaxOpenConns = 1
	cfg.Database.MaxIdleConns = 1
	db, err := database.New(database.WithConfig(cfg))(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Init(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(ctx) })
	mm, err := migrate.New()(db, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err = mm.Init(ctx); err != nil {
		t.Fatal(err)
	}
	s := sqlimpl.NewService(db, mm)
	if err = s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err = mm.RunPendingContext(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestADryRunRunsNothing serves service invocations of an Active function
// whose policy allows the service, from a module whose engine was never
// started: it has no runner, so an invocation that reaches the engine
// panics. A DryRun is answered 204 with the call's request ID and no body,
// and leaves the history empty; a RequestResponse of the same function
// reaches the engine, which shows that the DryRun did not.
func TestADryRunRunsNothing(t *testing.T) {
	settings := &contracts.Settings{
		AccountID: "000000000000", Region: "us-east-1", HistoryLimit: 100,
		HistoryMaxBytes: 1 << 30,
	}
	store := newStore(t)
	arn := settings.FunctionARN("fn")
	if err := store.PutFunction(t.Context(), &contracts.Function{
		Name: "fn", ARN: arn, State: contracts.StateActive,
		Image: contracts.Image{ID: "sha256:0"},
		Policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Principal":{"Service":"s3.amazonaws.com"},"Action":"lambda:InvokeFunction",` +
			`"Resource":"` + arn + `"}]}`,
	}); err != nil {
		t.Fatal(err)
	}
	m := &Module{
		store:    store,
		engine:   engine.New(settings, "", "", nil)(store, &gas.NopLogger{}, nil),
		authz:    authz.New(settings.AccountID, settings.Region, time.Now),
		settings: settings,
		names:    newNameLocks(),
	}
	call := func(invocationType string) (rec *httptest.ResponseRecorder, panicked any) {
		rec = httptest.NewRecorder()
		body := `{"FunctionName":"fn","ServicePrincipal":"s3.amazonaws.com",` +
			`"InvocationType":"` + invocationType + `"}`
		parent := context.WithValue(t.Context(), middleware.RequestIDKey, "req-1")
		r := httptest.NewRequestWithContext(parent, http.MethodPost, serviceinvoke.Path,
			bytes.NewReader([]byte(body)))
		defer func() { panicked = recover() }()
		if err := m.serviceInvoke(gas.NewContext(parent, rec, r)); err != nil {
			t.Fatalf("%s: %v", invocationType, err)
		}
		return rec, nil
	}

	rec, panicked := call(serviceinvoke.InvocationDryRun)
	if panicked != nil {
		t.Fatalf("a DryRun reached the engine: %v", panicked)
	}
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 ||
		rec.Header().Get(serviceinvoke.RequestIDHeader) != "req-1" {
		t.Fatalf("a DryRun: %d %q, request ID %q", rec.Code, rec.Body,
			rec.Header().Get(serviceinvoke.RequestIDHeader))
	}
	page, err := store.ListInvocations(t.Context(), contracts.InvocationFilter{},
		contracts.PageInput{Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("the history after a DryRun: %+v", page.Items)
	}

	if _, panicked = call(serviceinvoke.InvocationRequestResponse); panicked == nil {
		t.Fatal("a RequestResponse did not reach the engine")
	}
}
