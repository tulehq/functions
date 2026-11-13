package lambdaapi

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestRequestTagsRefuseDuplicateKeys(t *testing.T) {
	for name, body := range map[string]string{
		"a key twice":             `{"Tags":{"team":"a","team":"b"}}`,
		"the member twice":        `{"Tags":{"team":"a"},"Tags":{"env":"b"}}`,
		"the member in two cases": `{"Tags":{"team":"a"},"tags":{"team":"b"}}`,
	} {
		var req TagResourceRequest
		err := json.Unmarshal([]byte(body), &req)
		var dup *DuplicateTagError
		if !errors.As(err, &dup) {
			t.Errorf("%s: got %v, tags %v", name, err, req.Tags)
		}
		if apiErr, ok := duplicateTag(err); !ok || apiErr.Code != CodeInvalidParameterValue {
			t.Errorf("%s: answered %v", name, apiErr)
		}
	}
}

func TestRequestTagsDecodeDistinctKeys(t *testing.T) {
	for body, n := range map[string]int{
		`{"Tags":{"team":"a","env":"b"}}`:  2,
		`{"Tags":{"Team":"a","team":"b"}}`: 2,
		`{"Tags":null}`:                    0,
		`{}`:                               0,
	} {
		var req TagResourceRequest
		if err := json.Unmarshal([]byte(body), &req); err != nil || len(req.Tags) != n {
			t.Errorf("%s: %v, %v", body, req.Tags, err)
		}
	}
	var req TagResourceRequest
	if err := json.Unmarshal([]byte(`{"Tags":{"team":1}}`), &req); err == nil {
		t.Error("a number value was accepted")
	}
}
