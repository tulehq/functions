// Package authz authorizes a verified request against the identity
// policies of the principal that signed it, with tule.dev/policy, as AWS
// authorizes a request within one account by identity-based policies.
//
// The root principal (the configured static key, or identity's root key) is
// never evaluated, as AWS never evaluates the root user against policies.
// Every other principal comes from identity, which supplies its policies,
// and is evaluated on every request: without an identity endpoint there is
// none, so a standalone service evaluates nothing.
package authz

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"tule.dev/policy"
	"tule.dev/sigv4"
)

// Request is one action on one resource that a request needs allowed, with
// the condition keys the operation supplies beside the global ones.
type Request struct {
	Context  map[string][]string
	Action   string
	Resource string
}

// Denial is why a request is denied.
type Denial int

const (
	// NoIdentityPolicy is an implicit deny: no identity policy allows it.
	NoIdentityPolicy Denial = iota + 1
	// ExplicitDeny is a Deny statement in an identity policy that applies.
	ExplicitDeny
	// NoResourcePolicy is a request of another account's principal its
	// identity policies allow: across accounts AWS also needs a resource-based
	// policy to allow it, and none is evaluated here, so none ever does.
	NoResourcePolicy
)

// Denied is a denied request. Its message is AWS's for the Denial.
type Denied struct {
	Principal string
	Action    string
	Resource  string
	Why       Denial
}

func (d *Denied) Error() string {
	var why string
	switch d.Why {
	case ExplicitDeny:
		why = "with an explicit deny in an identity-based policy"
	case NoResourcePolicy:
		why = "because no resource-based policy allows the " + d.Action + " action"
	default:
		why = "because no identity-based policy allows the " + d.Action + " action"
	}
	return "User: " + d.Principal + " is not authorized to perform: " + d.Action +
		" on resource: " + d.Resource + " " + why
}

// TooLarge is a request whose condition keys exceed the caps the policy
// library asks services to apply: more keys, values or longer values than
// any operation here legitimately supplies.
type TooLarge struct {
	Reason string
}

func (e *TooLarge) Error() string {
	return "the request carries too many condition values: " + e.Reason
}

// The caps on the condition keys of one evaluation. A request carries at
// most 50 tags (Lambda's tag limit), each a key of 128 characters and a
// value of 256, which with the global keys and the resource's tags stays
// well inside these.
const (
	maxKeys        = 128
	maxKeyLength   = 256
	maxValues      = 50
	maxValueLength = 1024
)

// ErrNoPrincipal is a request that reached authorization without a verified
// principal, which only a wiring fault can produce.
var ErrNoPrincipal = errors.New("authz: the request carries no verified principal")

// maxCached bounds the parsed policy documents kept. Past it the cache is
// emptied and refilled, which costs a parse per document and nothing else.
const maxCached = 256

// Authorizer evaluates requests. It caches parsed policy documents by the
// SHA-256 of their content, so an unchanged policy is parsed once.
type Authorizer struct {
	now     func() time.Time
	cache   map[[sha256.Size]byte]*policy.Policy
	account string
	region  string
	mu      sync.Mutex
}

// New returns an Authorizer for the service's account and region that reads
// the time from now.
func New(account, region string, now func() time.Time) *Authorizer {
	return &Authorizer{
		now:     now,
		cache:   map[[sha256.Size]byte]*policy.Policy{},
		account: account,
		region:  region,
	}
}

// Authorize returns nil when the principal that signed r may make every
// request build returns, a *Denied for the first it may not, a *TooLarge
// for one whose condition keys exceed the caps, or another error when the
// principal's policies cannot be read or build fails. Each request is
// evaluated on its own, as AWS evaluates each action and resource a request
// needs. build is called only for a principal that is evaluated, so the
// root principal costs no lookups.
//
// A principal of another account than the service's is denied every
// request: AWS allows a cross-account request only when a resource-based
// policy allows it too, and resource-based policies are not evaluated here.
// Its identity policies are still evaluated first, so a Deny or a missing
// Allow is reported as such.
func (a *Authorizer) Authorize(r *http.Request, build func() ([]Request, error)) error {
	p, ok := sigv4.PrincipalFrom(r.Context())
	if !ok {
		return ErrNoPrincipal
	}
	// Root is the root user of the service's own account only: a key
	// source's Root marks full access to the principal's account, which
	// says nothing of this one.
	if p.Root && p.AccountID == a.account {
		return nil
	}
	policies, err := a.parse(p.Policies)
	if err != nil {
		return err
	}
	reqs, err := build()
	if err != nil {
		return err
	}
	global := GlobalKeys(r, &p, a.region, a.now())
	for _, req := range reqs {
		keys := union(global, req.Context)
		if err = checkSize(keys); err != nil {
			return err
		}
		res := policy.Evaluate(policy.Request{
			Action:    req.Action,
			Resource:  req.Resource,
			Principal: p.ARN,
			Context:   keys,
		}, policies...)
		if why, denied := a.denial(res.Decision, &p); denied {
			return &Denied{Principal: p.ARN, Action: req.Action, Resource: req.Resource, Why: why}
		}
	}
	return nil
}

// union is the keys of a and b, b's where both have one.
func union(a, b map[string][]string) map[string][]string {
	out := make(map[string][]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// denial is why a request decided d is denied to p, if it is.
func (a *Authorizer) denial(d policy.Decision, p *sigv4.Principal) (Denial, bool) {
	switch {
	case d == policy.ExplicitDeny:
		return ExplicitDeny, true
	case d != policy.Allow:
		return NoIdentityPolicy, true
	case p.AccountID != a.account:
		return NoResourcePolicy, true
	}
	return 0, false
}

// parse returns the parsed documents, from the cache where it has them. A
// document identity sent that does not parse fails the request: identity
// checked it when it was stored, so it is a fault, and skipping it could
// drop a Deny.
func (a *Authorizer) parse(docs []json.RawMessage) ([]*policy.Policy, error) {
	out := make([]*policy.Policy, 0, len(docs))
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, doc := range docs {
		sum := sha256.Sum256(doc)
		if p, ok := a.cache[sum]; ok {
			out = append(out, p)
			continue
		}
		p, err := policy.ParseIdentity(doc)
		if err != nil {
			return nil, fmt.Errorf("authz: parse an identity policy: %w", err)
		}
		if len(a.cache) >= maxCached {
			clear(a.cache)
		}
		a.cache[sum] = p
		out = append(out, p)
	}
	return out, nil
}

func checkSize(keys map[string][]string) error {
	if len(keys) > maxKeys {
		return &TooLarge{Reason: strconv.Itoa(len(keys)) + " condition keys"}
	}
	for k, vs := range keys {
		if len(k) > maxKeyLength {
			return &TooLarge{Reason: "a condition key of " + strconv.Itoa(len(k)) + " bytes"}
		}
		if len(vs) > maxValues {
			return &TooLarge{Reason: strconv.Itoa(len(vs)) + " values of " + k}
		}
		for _, v := range vs {
			if len(v) > maxValueLength {
				return &TooLarge{
					Reason: "a value of " + k + " of " + strconv.Itoa(len(v)) + " bytes",
				}
			}
		}
	}
	return nil
}

// GlobalKeys are the global condition keys the service supplies for every
// request of p: aws:SourceIp, aws:CurrentTime, aws:EpochTime,
// aws:SecureTransport, aws:RequestedRegion, aws:PrincipalAccount,
// aws:PrincipalArn, aws:PrincipalType, and aws:username for an IAM user.
//
// aws:RequestedRegion is region, the service's own: in AWS the endpoint
// fixes the region a request acts in, and here a request signed for any
// region verifies and acts on this one, so the signed region would let a
// caller choose the key's value.
//
// aws:PrincipalArn of a role session is its role's ARN, which AWS gives
// with the role's path; the session's assumed-role ARN carries no path and
// identity does not send it, so here it is the role's ARN without a path.
// aws:userid needs the principal's unique ID, which identity does not send
// either, and is not supplied.
func GlobalKeys(
	r *http.Request,
	p *sigv4.Principal,
	region string,
	now time.Time,
) map[string][]string {
	keys := map[string][]string{
		"aws:RequestedRegion":  {region},
		"aws:CurrentTime":      {now.UTC().Format(time.RFC3339)},
		"aws:EpochTime":        {strconv.FormatInt(now.Unix(), 10)},
		"aws:SecureTransport":  {strconv.FormatBool(r.TLS != nil)},
		"aws:PrincipalAccount": {p.AccountID},
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		keys["aws:SourceIp"] = []string{host}
	}
	if arn, typ, user, ok := principalKeys(p.ARN); ok {
		keys["aws:PrincipalArn"] = []string{arn}
		keys["aws:PrincipalType"] = []string{typ}
		if user != "" {
			keys["aws:username"] = []string{user}
		}
	}
	return keys
}

// principalKeys returns aws:PrincipalArn, aws:PrincipalType and, for a
// user, aws:username of the principal arn names: an IAM user
// (arn:aws:iam::<account>:user<path><name>) or a role session
// (arn:aws:sts::<account>:assumed-role/<role>/<session>), whose
// aws:PrincipalArn is arn:aws:iam::<account>:role/<role>. The values are
// the ones the IAM User Guide's global condition keys page gives for each.
func principalKeys(arn string) (principalARN, typ, user string, ok bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return "", "", "", false
	}
	partition, service, account, resource := parts[1], parts[2], parts[4], parts[5]
	switch {
	case service == "iam" && strings.HasPrefix(resource, "user/"):
		return arn, "User", resource[strings.LastIndexByte(resource, '/')+1:], true
	case service == "sts" && strings.HasPrefix(resource, "assumed-role/"):
		role, _, found := strings.Cut(strings.TrimPrefix(resource, "assumed-role/"), "/")
		if !found || role == "" {
			return "", "", "", false
		}
		return "arn:" + partition + ":iam::" + account + ":role/" + role, "AssumedRole", "", true
	}
	return "", "", "", false
}
