package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/lambdaapi"
)

func TestARequestWithoutALoggerFailsAsAServiceException(t *testing.T) {
	// A request scope whose container has no request logger registered, so
	// resolving one fails. The request must fail visibly rather than answer
	// an empty 200.
	ctx := t.Context()
	scope := gas.NewServiceContainer().NewScope(ctx)
	t.Cleanup(func() {
		if err := scope.Close(ctx); err != nil {
			t.Errorf("close scope: %v", err)
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/2015-03-31/functions", http.NoBody)
	req = req.WithContext(gas.WithRequestScope(ctx, scope))

	called := false
	h := withRequestLogger(&gas.NopLogger{})(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { called = true }))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if called {
		t.Fatal("the handler ran without a request logger")
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if got := w.Header().Get(lambdaapi.ErrorTypeHeader); got != lambdaapi.CodeService {
		t.Fatalf("error type = %s, want %s", got, lambdaapi.CodeService)
	}
}
