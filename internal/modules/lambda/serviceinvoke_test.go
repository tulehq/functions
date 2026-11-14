package lambda

import (
	"net/http"
	"strings"
	"testing"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/runner"
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
