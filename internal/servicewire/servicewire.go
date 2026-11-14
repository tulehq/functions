// Package servicewire encodes the bodies of the service-invoke endpoint,
// its requests and its responses, with their Payload member byte for byte.
// encoding/json would compact a payload and escape its <, > and &, so the
// function would get other bytes than were sent and the payload limits
// would measure the escaped ones. tule.dev/functions/serviceinvoke and the
// endpoint both encode through it.
package servicewire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// PayloadMember is the member the payload is encoded as.
const PayloadMember = "Payload"

// The errors Encode fails with when its arguments break its preconditions.
var (
	ErrPayloadNotJSON = errors.New("servicewire: the payload is not JSON")
	ErrHeadNotObject  = errors.New("servicewire: the envelope is not a JSON object " +
		"with at least one member")
	ErrHeadHasPayload = errors.New("servicewire: the envelope already has a Payload member")
)

// Encode encodes v, the envelope, as a JSON object with payload, when it
// is not empty, as its Payload member, byte for byte. payload must be JSON,
// and v must encode, without escaping HTML, as an object of at least one
// member and none named Payload in any case, which encoding/json would
// decode as the same member. A Payload member comes from payload alone, so
// the body has at most one.
func Encode(v any, payload []byte) ([]byte, error) {
	if len(payload) > 0 && !json.Valid(payload) {
		return nil, ErrPayloadNotJSON
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("servicewire: encode the envelope: %w", err)
	}
	head := bytes.TrimSpace(buf.Bytes())
	var members map[string]json.RawMessage
	if err := json.Unmarshal(head, &members); err != nil || len(members) == 0 {
		return nil, ErrHeadNotObject
	}
	for name := range members {
		if strings.EqualFold(name, PayloadMember) {
			return nil, ErrHeadHasPayload
		}
	}
	if len(payload) == 0 {
		return head, nil
	}
	head = head[:len(head)-1] // the object's closing brace
	out := make([]byte, 0, len(head)+len(payload)+len(`,"Payload":}`))
	out = append(out, head...)
	out = append(out, `,"`+PayloadMember+`":`...)
	out = append(out, payload...)
	return append(out, '}'), nil
}
