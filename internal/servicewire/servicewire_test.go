package servicewire

import (
	"encoding/json"
	"errors"
	"testing"
)

type envelope struct {
	Name    string          `json:"Name"`
	Note    string          `json:"Note,omitempty"`
	Payload json.RawMessage `json:"Payload,omitempty"`
}

func TestThePayloadIsEncodedAsItIs(t *testing.T) {
	const payload = `{ "html": "<b>a & b</b>",  "n": [1, 2] }`
	got, err := Encode(envelope{Name: "<fn>"}, []byte(payload))
	if want := `{"Name":"<fn>","Payload":` + payload + `}`; err != nil || string(got) != want {
		t.Fatalf("got %s, %v; want %s", got, err, want)
	}
	if got, err = Encode(envelope{Name: "fn"}, nil); err != nil || string(got) != `{"Name":"fn"}` {
		t.Fatalf("without a payload: got %s, %v", got, err)
	}
}

func TestEncodeRefusesWhatWouldBreakTheBody(t *testing.T) {
	for what, c := range map[string]struct {
		want    error
		v       any
		payload string
	}{
		// Spliced in, it would add a member of its own.
		"an injected member": {
			v: envelope{Name: "fn"}, payload: `1,"Name":"other"`, want: ErrPayloadNotJSON,
		},
		"an empty object": {v: struct{}{}, payload: `{}`, want: ErrHeadNotObject},
		"a number":        {v: 5, payload: `{}`, want: ErrHeadNotObject},
		"an array":        {v: []string{"a"}, payload: `{}`, want: ErrHeadNotObject},
		"a null envelope": {v: nil, payload: `{}`, want: ErrHeadNotObject},
		"its own Payload": {
			v: envelope{Name: "fn", Payload: json.RawMessage(`1`)}, payload: `2`,
			want: ErrHeadHasPayload,
		},
		"a payload member in another case": {
			v: map[string]int{"Name": 1, "payload": 2}, payload: `2`, want: ErrHeadHasPayload,
		},
	} {
		if _, err := Encode(c.v, []byte(c.payload)); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", what, err, c.want)
		}
	}
}
