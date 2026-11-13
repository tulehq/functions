package lambdaapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// RequestTags are the Tags member of a request that sets tags. Decoding
// refuses a key that appears twice and a Tags member that appears twice,
// which JSON decoding would otherwise keep one of silently. Lambda
// documents no answer for either; a request with them is refused with
// InvalidParameterValueException. Keys that differ only in case are refused
// where a request is evaluated against policies, not here.
type RequestTags map[string]string

// DuplicateTagError is a request whose tags repeat a key.
type DuplicateTagError struct {
	Key string
}

func (e *DuplicateTagError) Error() string {
	if e.Key == "" {
		return "The request has more than one Tags member."
	}
	return fmt.Sprintf("The request has the tag key %s more than once, or keys that "+
		"differ from it only in case.", e.Key)
}

// UnmarshalJSON decodes the tags, refusing duplicate keys.
func (t *RequestTags) UnmarshalJSON(b []byte) error {
	if *t != nil {
		return &DuplicateTagError{}
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err //nolint:wrapcheck // Decode answers it as the body's parse error
	}
	if m == nil {
		return nil
	}
	if err := duplicateKey(b); err != nil {
		return err
	}
	*t = m
	return nil
}

// duplicateKey returns a *DuplicateTagError for the first key of the JSON
// object b that repeats another.
func duplicateKey(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil { // the opening brace
		return fmt.Errorf("lambdaapi: read the tags: %w", err)
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("lambdaapi: read a tag key: %w", err)
		}
		key, _ := tok.(string)
		if seen[key] {
			return &DuplicateTagError{Key: key}
		}
		seen[key] = true
		var skip json.RawMessage
		if err = dec.Decode(&skip); err != nil {
			return fmt.Errorf("lambdaapi: read a tag value: %w", err)
		}
	}
	return nil
}

// duplicateTag reports err as InvalidParameterValueException when it is a
// *DuplicateTagError.
func duplicateTag(err error) (*Error, bool) {
	var dup *DuplicateTagError
	if errors.As(err, &dup) {
		return ErrInvalidParameter(dup.Error()), true
	}
	return nil, false
}
