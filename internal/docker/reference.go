package docker

import (
	"fmt"

	"github.com/distribution/reference"
)

// Reference is an image reference Docker's grammar accepts
// (name[:tag][@digest]), normalized as Docker normalizes it: Name is the
// repository with its registry (docker.io/library/... for a bare name),
// TagOrDigest the digest when it has one, else its tag, latest when it has
// neither.
type Reference struct {
	Name        string
	TagOrDigest string
	full        string
}

// String is the normalized reference, which Docker resolves as it would
// the reference as given.
func (r *Reference) String() string {
	return r.full
}

// ParseReference checks ref against Docker's reference grammar, as
// github.com/distribution/reference implements it, and normalizes it.
func ParseReference(ref string) (*Reference, error) {
	named, err := reference.ParseDockerRef(ref)
	if err != nil {
		return nil, fmt.Errorf("docker: %q is not an image reference: %w", ref, err)
	}
	out := &Reference{Name: named.Name(), full: named.String()}
	switch r := named.(type) {
	case reference.Canonical:
		out.TagOrDigest = r.Digest().String()
	case reference.Tagged:
		out.TagOrDigest = r.Tag()
	}
	return out, nil
}
