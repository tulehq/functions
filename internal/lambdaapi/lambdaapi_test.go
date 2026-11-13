package lambdaapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestErrorsUseTheModelsMessageMember(t *testing.T) {
	tests := []struct {
		err    error
		code   string
		kind   string
		member string
		status int
	}{
		{ErrInvalidParameter("bad"), CodeInvalidParameterValue, "User", "message", 400},
		{ErrNotFound("gone"), CodeResourceNotFound, "User", "Message", 404},
		{ErrConflict("busy"), CodeResourceConflict, "User", "message", 409},
		{errors.New("boom"), CodeService, "Service", "Message", 500},
	}
	for _, tt := range tests {
		w := httptest.NewRecorder()
		WriteHTTPError(w, httptest.NewRequest(http.MethodGet, "/", nil), tt.err)
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != tt.status || w.Header().Get("X-Amzn-ErrorType") != tt.code ||
			body["Type"] != tt.kind || body[tt.member] == "" || len(body) != 2 {
			t.Errorf(
				"%v answered %d %s %v",
				tt.err,
				w.Code,
				w.Header().Get("X-Amzn-ErrorType"),
				body,
			)
		}
	}
}

func TestEpochSecondsKeepsTheMilliseconds(t *testing.T) {
	b, err := json.Marshal(EpochSeconds(time.UnixMilli(1700000000123)))
	if err != nil || string(b) != "1700000000.123" {
		t.Fatalf("marshal = %s, %v", b, err)
	}
}
