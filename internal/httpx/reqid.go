// Package httpx holds HTTP plumbing shared by the modules: request IDs and the
// request-scoped logger.
package httpx

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/gasmod/gas/config"
	"github.com/go-chi/chi/v5/middleware"
)

// RequestID returns middleware that puts a request ID on the request context.
// Production-like environments get chi's random IDs; everywhere else the IDs
// are short and sequential ("dev-1", "dev-2", ...), which is easier to follow
// when reading logs by hand.
func RequestID(env config.Environment) func(http.Handler) http.Handler {
	if env.IsProductionLike() {
		return middleware.RequestID
	}

	var reqID atomic.Uint64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := fmt.Sprintf("dev-%d", reqID.Add(1))
			ctx := context.WithValue(r.Context(), middleware.RequestIDKey, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequestIDOf returns the request ID carried by ctx, or "" when it has none.
func RequestIDOf(ctx context.Context) string {
	return middleware.GetReqID(ctx)
}
