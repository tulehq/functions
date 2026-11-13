// Package authz authorizes a verified request against the identity
// policies of the principal that signed it and the resource-based policy of
// the resource it acts on, with tule.dev/policy's Authorize, as AWS
// evaluates the two kinds together, within one account and across
// accounts.
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
	"sync"
	"time"

	"tule.dev/policy"
	"tule.dev/sigv4"
)

// Request is one action on one resource that a request needs allowed, with
// the condition keys the operation supplies beside the global ones, and the
// resource's resource-based policy document as stored, empty when it has
// none or the action is not one the policy governs.
type Request struct {
	Context  map[string][]string
	Action   string
	Resource string
	Policy   string
}

// Denied is a denied request. Its message is AWS's: "User: <arn> is not
// authorized to perform: <action> on resource: <arn>" and the phrase for
// Why that tule.dev/policy's Reason.Message gives, the IAM User Guide's
// ("Troubleshooting access denied error messages").
type Denied struct {
	Principal string
	Action    string
	Resource  string
	Why       policy.Reason
}

func (d *Denied) Error() string {
	return "User: " + d.Principal + " is not authorized to perform: " + d.Action +
		" on resource: " + d.Resource + " " + d.Why.Message(d.Action)
}

// ErrInconsistentPrincipal is a principal whose Root and Type disagree: a
// root principal that is not of type Account, or one of type Account that
// is not root. Its key source broke its contract, so it is a fault.
var ErrInconsistentPrincipal = errors.New("authz: the principal's Root and Type disagree")

// ErrStoredPolicy is a resource whose stored resource-based policy does not
// parse. The request fails rather than be evaluated without it: the policy
// was checked when it was stored, so this is a fault, and evaluating without
// it could drop a Deny.
var ErrStoredPolicy = errors.New(
	"authz: the resource's stored resource-based policy does not parse",
)

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
// value of 256, a resource as many, and a principal at most 50
// (keysource.MaxTags), which with the global and the operation's own keys
// stays inside these.
const (
	maxKeys        = 192
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

// cacheKey is a parsed document's kind and the SHA-256 of its content: the
// same bytes parse differently as an identity and a resource-based policy.
type cacheKey struct {
	sum      [sha256.Size]byte
	resource bool
}

// Authorizer evaluates requests. It caches parsed policy documents by kind
// and content, so an unchanged policy is parsed once.
type Authorizer struct {
	now     func() time.Time
	cache   map[cacheKey]*policy.Policy
	account string
	region  string
	mu      sync.Mutex
}

// New returns an Authorizer for the service's account and region that reads
// the time from now.
func New(account, region string, now func() time.Time) *Authorizer {
	return &Authorizer{
		now:     now,
		cache:   map[cacheKey]*policy.Policy{},
		account: account,
		region:  region,
	}
}

// Authorize returns nil when the principal that signed r may make every
// request build returns, a *Denied for the first it may not, a *TooLarge
// for one whose condition keys exceed the caps, an error wrapping
// ErrStoredPolicy for one whose resource-based policy does not parse, or
// another error when the principal's policies cannot be read or build
// fails. Each request is evaluated on its own, as AWS evaluates each action
// and resource a request needs. build is called only for a principal that
// is evaluated, so the root principal costs no lookups.
//
// Every resource here is the service's own account's, so a principal of
// that account is allowed by an identity-based Allow or by a resource-based
// one that names it directly, and a principal of another account needs
// both; tule.dev/policy's Authorize decides, and gives the reason a denial
// is reported with.
func (a *Authorizer) Authorize(r *http.Request, build func() ([]Request, error)) error {
	p, ok := sigv4.PrincipalFrom(r.Context())
	if !ok {
		return ErrNoPrincipal
	}
	// Root decides whether p is evaluated here, and Type whether
	// tule.dev/policy grants it a root user's full identity access: they
	// must agree, or one would decide what the other does not.
	if p.Root != (p.Type == sigv4.PrincipalTypeAccount) {
		return fmt.Errorf("%w: Root %t with type %q", ErrInconsistentPrincipal, p.Root, p.Type)
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
	caller := CallerOf(&p)
	for _, req := range reqs {
		if err = a.evaluate(&req, global, caller, policies); err != nil {
			return err
		}
	}
	return nil
}

// evaluate authorizes req of caller, whose identity policies are policies,
// with the global keys global.
func (a *Authorizer) evaluate(
	req *Request,
	global map[string][]string,
	caller policy.Caller,
	policies []*policy.Policy,
) error {
	keys := union(global, req.Context)
	if err := checkSize(keys); err != nil {
		return err
	}
	var resource *policy.Policy
	if req.Policy != "" {
		var err error
		if resource, err = a.parseResource([]byte(req.Policy)); err != nil {
			return err
		}
	}
	az := policy.Authorize(policy.AuthorizeRequest{
		Action:          req.Action,
		Resource:        req.Resource,
		ResourceAccount: a.account,
		Caller:          caller,
		Context:         keys,
	}, resource, policies...)
	if az.Decision != policy.Allow {
		return &Denied{
			Principal: caller.ARN, Action: req.Action, Resource: req.Resource, Why: az.Reason,
		}
	}
	return nil
}

// CallerOf is the policy library's description of p, from the principal
// attributes identity's signing-key endpoint gives at version 3. It supplies
// aws:PrincipalArn (the role's ARN with its path for a session, none for a
// session whose role was deleted), aws:PrincipalAccount, aws:userid,
// aws:PrincipalType and, for an IAM user, aws:username, and matches p
// against a resource-based policy's Principal element.
func CallerOf(p *sigv4.Principal) policy.Caller {
	return policy.Caller{
		AccountID:    p.AccountID,
		ARN:          p.ARN,
		PrincipalARN: p.PrincipalARN,
		UserID:       p.UserID,
		Type:         policy.PrincipalType(p.Type),
	}
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

// parse returns the parsed documents, from the cache where it has them. A
// document identity sent that does not parse fails the request: identity
// checked it when it was stored, so it is a fault, and skipping it could
// drop a Deny.
func (a *Authorizer) parse(docs []json.RawMessage) ([]*policy.Policy, error) {
	out := make([]*policy.Policy, 0, len(docs))
	for _, doc := range docs {
		p, err := a.cached(doc, false)
		if err != nil {
			return nil, fmt.Errorf("authz: parse an identity policy: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}

// parseResource returns the parsed resource-based policy doc, from the
// cache when it has it.
func (a *Authorizer) parseResource(doc []byte) (*policy.Policy, error) {
	p, err := a.cached(doc, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoredPolicy, err)
	}
	return p, nil
}

// cached returns doc parsed as a resource-based policy when resource is
// set, else as an identity policy, from the cache when it has it.
func (a *Authorizer) cached(doc []byte, resource bool) (*policy.Policy, error) {
	key := cacheKey{sum: sha256.Sum256(doc), resource: resource}
	a.mu.Lock()
	defer a.mu.Unlock()
	if p, ok := a.cache[key]; ok {
		return p, nil
	}
	parse := policy.ParseIdentity
	if resource {
		parse = policy.ParseResource
	}
	p, err := parse(doc)
	if err != nil {
		return nil, err
	}
	if len(a.cache) >= maxCached {
		clear(a.cache)
	}
	a.cache[key] = p
	return p, nil
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
// aws:SecureTransport, aws:RequestedRegion and aws:PrincipalTag/<key> for
// each of p's tags. The principal's own keys (aws:PrincipalArn,
// aws:PrincipalAccount, aws:userid, aws:PrincipalType, aws:username) come
// from CallerOf, through tule.dev/policy's Authorize.
//
// aws:RequestedRegion is region, the service's own: in AWS the endpoint
// fixes the region a request acts in, and here a request signed for any
// region verifies and acts on this one, so the signed region would let a
// caller choose the key's value.
func GlobalKeys(
	r *http.Request,
	p *sigv4.Principal,
	region string,
	now time.Time,
) map[string][]string {
	keys := map[string][]string{
		"aws:RequestedRegion": {region},
		"aws:CurrentTime":     {now.UTC().Format(time.RFC3339)},
		"aws:EpochTime":       {strconv.FormatInt(now.Unix(), 10)},
		"aws:SecureTransport": {strconv.FormatBool(r.TLS != nil)},
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		keys["aws:SourceIp"] = []string{host}
	}
	for k, v := range p.Tags {
		keys["aws:PrincipalTag/"+k] = []string{v}
	}
	return keys
}
