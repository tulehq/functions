package sqlimpl

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"
	_ "modernc.org/sqlite"

	"tule.dev/functions/internal/contracts"
)

// newStore opens a store on a fresh database file the way the app wires it:
// gas/database, then gas/migrate applying the schema the store registers.
func newStore(t *testing.T) *Service {
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
		t.Fatalf("new database: %v", err)
	}
	if err = db.Init(ctx); err != nil {
		t.Fatalf("init database: %v", err)
	}
	t.Cleanup(func() {
		if cErr := db.Close(ctx); cErr != nil {
			t.Errorf("close database: %v", cErr)
		}
	})
	mm, err := migrate.New()(db, logger)
	if err != nil {
		t.Fatalf("new migrate: %v", err)
	}
	if err = mm.Init(ctx); err != nil {
		t.Fatalf("init migrate: %v", err)
	}
	s := NewService(db, mm)
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if err = mm.RunPendingContext(ctx); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return s
}

func TestTheInstanceIDIsMadeOnceAndKept(t *testing.T) {
	s := newStore(t)
	first, err := s.InstanceID(t.Context())
	if err != nil || len(first) != 16 {
		t.Fatalf("instance ID = %q, %v", first, err)
	}
	again, err := s.InstanceID(t.Context())
	if err != nil || again != first {
		t.Fatalf("second instance ID = %q, %v; want %q", again, err, first)
	}
}

// must fails the test on err.
func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// requireIs fails unless err is want.
func requireIs(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s = %v, want %v", what, err, want)
	}
}

func putFunctions(t *testing.T, s *Service, names ...string) {
	t.Helper()
	for _, name := range names {
		must(
			t,
			s.PutFunction(t.Context(), &contracts.Function{Name: name, Timeout: 3}),
			"put "+name,
		)
	}
}

func TestAFunctionIsStoredOnce(t *testing.T) {
	s := newStore(t)
	putFunctions(t, s, "a")
	requireIs(t, s.PutFunction(t.Context(), &contracts.Function{Name: "a"}),
		contracts.ErrFunctionExists, "put a again")
}

func TestAnUpdateCommitsOnlyWhenItSucceeds(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	putFunctions(t, s, "b")
	_, err := s.UpdateFunction(ctx, "b", func(fn *contracts.Function) error {
		fn.Timeout = 9
		return nil
	})
	must(t, err, "update")
	refused := errors.New("refused")
	_, err = s.UpdateFunction(ctx, "b", func(fn *contracts.Function) error {
		fn.Timeout = 99
		return refused
	})
	requireIs(t, err, refused, "refused update")
	fn, err := s.GetFunction(ctx, "b")
	must(t, err, "get")
	if fn.Timeout != 9 {
		t.Fatalf("timeout = %d, want 9", fn.Timeout)
	}
}

func TestFunctionsAreListedInPages(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	putFunctions(t, s, "a", "b", "c")
	page, err := s.ListFunctions(ctx, contracts.PageInput{Size: 2})
	must(t, err, "first page")
	if len(page.Items) != 2 || page.NextToken == "" {
		t.Fatalf("first page = %+v", page)
	}
	rest, err := s.ListFunctions(ctx, contracts.PageInput{Size: 2, Token: page.NextToken})
	must(t, err, "second page")
	if len(rest.Items) != 1 || rest.Items[0].Name != "c" || rest.NextToken != "" {
		t.Fatalf("second page = %+v", rest)
	}
	_, err = s.ListFunctions(ctx, contracts.PageInput{Size: 2, Token: "bogus"})
	requireIs(t, err, contracts.ErrInvalidToken, "bogus token")
}

func TestADeletedFunctionIsGone(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	putFunctions(t, s, "a")
	must(t, s.DeleteFunction(ctx, "a"), "delete")
	_, err := s.GetFunction(ctx, "a")
	requireIs(t, err, contracts.ErrFunctionNotFound, "get deleted")
	requireIs(t, s.DeleteFunction(ctx, "a"), contracts.ErrFunctionNotFound, "delete again")
}

// mappingUUIDs lists the mappings f matches.
func mappingUUIDs(t *testing.T, s *Service, f contracts.MappingFilter) []string {
	t.Helper()
	page, err := s.ListMappings(t.Context(), f, contracts.PageInput{Size: 10})
	must(t, err, "list mappings")
	out := make([]string, 0, len(page.Items))
	for _, m := range page.Items {
		out = append(out, m.UUID)
	}
	return out
}

func TestMappingsAreFilteredByFunctionAndSource(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	for _, m := range []contracts.Mapping{
		{UUID: "u1", FunctionName: "f", EventSourceARN: "q1"},
		{UUID: "u2", FunctionName: "g", EventSourceARN: "q1"},
		{UUID: "u3", FunctionName: "f", EventSourceARN: "q2"},
	} {
		must(t, s.PutMapping(ctx, &m), "put "+m.UUID)
	}
	if got := mappingUUIDs(t, s, contracts.MappingFilter{FunctionName: "f"}); !slices.Equal(got,
		[]string{"u1", "u3"}) {
		t.Fatalf("by function = %v", got)
	}
	both := contracts.MappingFilter{FunctionName: "f", EventSourceARN: "q1"}
	if got := mappingUUIDs(t, s, both); !slices.Equal(got, []string{"u1"}) {
		t.Fatalf("by both = %v", got)
	}
	_, err := s.UpdateMapping(ctx, "u1", func(m *contracts.Mapping) error {
		m.FunctionName = "g"
		return nil
	})
	must(t, err, "update")
	if got := mappingUUIDs(t, s, contracts.MappingFilter{FunctionName: "g"}); !slices.Equal(got,
		[]string{"u1", "u2"}) {
		t.Fatalf("after moving u1 = %v", got)
	}
	must(t, s.DeleteMapping(ctx, "u1"), "delete")
	_, err = s.GetMapping(ctx, "u1")
	requireIs(t, err, contracts.ErrMappingNotFound, "get deleted")
}

// rows3 keeps 3 invocations, of any size.
var rows3 = contracts.HistoryBounds{Rows: 3, Bytes: 1 << 30}

var base = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

// putHistory records r1 to r4, a minute apart, every other one failed,
// keeping 3.
func putHistory(t *testing.T, s *Service) {
	t.Helper()
	for i, id := range []string{"r1", "r2", "r3", "r4"} {
		status := []string{contracts.StatusSucceeded, contracts.StatusFailed}[i%2]
		must(t, s.PutInvocation(t.Context(), invocation(id, status,
			base.Add(time.Duration(i)*time.Minute)), rows3), "put "+id)
	}
}

func requestIDs(t *testing.T, s *Service, f contracts.InvocationFilter) []string {
	t.Helper()
	page, err := s.ListInvocations(t.Context(), f, contracts.PageInput{Size: 10})
	must(t, err, "list invocations")
	out := make([]string, 0, len(page.Items))
	for _, inv := range page.Items {
		out = append(out, inv.RequestID)
	}
	return out
}

func TestTheHistoryIsNewestFirstFilteredAndBounded(t *testing.T) {
	s := newStore(t)
	putHistory(t, s)
	since := base.Add(3 * time.Minute)
	for _, tt := range []struct {
		filter contracts.InvocationFilter
		want   []string
	}{
		{contracts.InvocationFilter{}, []string{"r4", "r3", "r2"}},
		{contracts.InvocationFilter{Status: contracts.StatusFailed}, []string{"r4", "r2"}},
		{contracts.InvocationFilter{Since: &since}, []string{"r4"}},
		{contracts.InvocationFilter{Function: "other"}, []string{}},
	} {
		if got := requestIDs(t, s, tt.filter); !slices.Equal(got, tt.want) {
			t.Errorf("%+v = %v, want %v", tt.filter, got, tt.want)
		}
	}
}

func TestARetriedRequestReplacesItsRecord(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	putHistory(t, s)
	retry := invocation("r2", contracts.StatusSucceeded, base.Add(10*time.Minute))
	retry.Attempts = 2
	must(t, s.PutInvocation(ctx, retry, rows3), "put the retry")
	if got := requestIDs(t, s, contracts.InvocationFilter{}); !slices.Equal(got,
		[]string{"r2", "r4", "r3"}) {
		t.Fatalf("history = %v", got)
	}
	whole, err := s.GetInvocation(ctx, "r2")
	must(t, err, "get")
	want := *retry
	if !reflect.DeepEqual(*whole, want) {
		t.Fatalf("r2 = %+v, want %+v", *whole, want)
	}
	must(t, s.DeleteInvocations(ctx), "reset")
	_, err = s.GetInvocation(ctx, "r2")
	requireIs(t, err, contracts.ErrInvocationNotFound, "after reset")
}

func invocation(id, status string, at time.Time) *contracts.Invocation {
	return &contracts.Invocation{
		RequestID: id, Function: "f", Status: status, Source: contracts.SourceInvoke,
		Time: at, Payload: []byte(`{}`), Result: []byte(`"ok"`), Log: "START\n", Attempts: 1,
		ErrorType: "", ErrorMessage: "", Duration: 1.5,
	}
}

func TestTheHistoryIsBoundedByBytes(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	bounds := contracts.HistoryBounds{Rows: 100, Bytes: 2500}
	for i, id := range []string{"r1", "r2", "r3", "r4"} {
		inv := invocation(id, contracts.StatusSucceeded, base.Add(time.Duration(i)*time.Minute))
		inv.Payload = make([]byte, 1000)
		inv.Result, inv.Log = nil, ""
		must(t, s.PutInvocation(ctx, inv, bounds), "put "+id)
	}
	if got := requestIDs(t, s, contracts.InvocationFilter{}); !slices.Equal(got,
		[]string{"r4", "r3"}) {
		t.Fatalf("history = %v, want the 2 newest of 1000 bytes each within 2500", got)
	}
	// The newest is kept however large.
	huge := invocation("r5", contracts.StatusSucceeded, base.Add(time.Hour))
	huge.Payload = make([]byte, 5000)
	must(t, s.PutInvocation(ctx, huge, bounds), "put r5")
	if got := requestIDs(t, s, contracts.InvocationFilter{}); !slices.Equal(got, []string{"r5"}) {
		t.Fatalf("history = %v, want r5 alone", got)
	}
}

func TestALargeFieldIsTruncatedWithAMarker(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	inv := invocation("big", contracts.StatusSucceeded, base)
	inv.Payload = make([]byte, contracts.MaxHistoryField+10)
	inv.Log = string(make([]byte, contracts.MaxHistoryField+1))
	must(t, s.PutInvocation(ctx, inv, rows3), "put")
	got, err := s.GetInvocation(ctx, "big")
	must(t, err, "get")
	for name, v := range map[string]string{"payload": string(got.Payload), "log": got.Log} {
		if len(v) != contracts.MaxHistoryField || !strings.HasSuffix(v, contracts.TruncatedMarker) {
			t.Errorf("%s is %d bytes, ending %q", name, len(v), v[len(v)-30:])
		}
	}
	if string(got.Result) != `"ok"` {
		t.Errorf("result = %s, want it untouched", got.Result)
	}
}
