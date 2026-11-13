package lambda

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/lambdaapi"
)

// keys are an operation's own condition keys.
type keys = map[string][]string

// authorize authorizes the request against the requests build returns, and
// answers a denial with AccessDeniedException in AWS's message form. build
// runs only for a principal that is evaluated: the root principal is
// allowed without it.
func (m *Module) authorize(ctx gas.Context, build func() ([]authz.Request, error)) error {
	err := m.authz.Authorize(ctx.Request(), build)
	var denied *authz.Denied
	var tooLarge *authz.TooLarge
	var dup *lambdaapi.DuplicateTagError
	switch {
	case errors.As(err, &denied):
		return lambdaapi.ErrAccessDenied(denied.Error())
	case errors.As(err, &dup):
		return lambdaapi.ErrInvalidParameter(dup.Error())
	case errors.As(err, &tooLarge):
		return lambdaapi.ErrInvalidParameter("The request carries more tag keys or longer " +
			"values than this service evaluates policies for.")
	}
	return err
}

// one is a build of the single request of op on resource.
func one(op, resource string, k keys) func() ([]authz.Request, error) {
	return func() ([]authz.Request, error) {
		return []authz.Request{request(op, resource, k)}, nil
	}
}

// request is op's action on resource with the keys k. An operation missing
// from operations is a fault the mapping test catches.
func request(op, resource string, k keys) authz.Request {
	o, ok := operations[op]
	if !ok {
		panic("lambda: no IAM action is mapped for " + op)
	}
	return authz.Request{Action: o.action, Resource: resource, Context: k}
}

// passRole is the iam:PassRole a function's execution role needs.
func passRole(role string) authz.Request {
	return authz.Request{
		Action:   actionPassRole,
		Resource: role,
		Context:  keys{keyPassedToService: {lambdaServicePrincipal}},
	}
}

// errStoredTags is a resource whose stored tags have keys that differ only
// in case, which the policy library would read as one condition key with
// two values: an evaluated request on it fails rather than be evaluated.
var errStoredTags = errors.New("lambda: the resource's tags have keys that differ only in case")

// caseCollision returns a key of b that differs only in case from another
// key of b, or from a key of a; a key of b equal to one of a does not
// collide, since it replaces it.
func caseCollision(a, b map[string]string) (string, bool) {
	seen := make(map[string]string, len(a)+len(b))
	for k := range a {
		seen[strings.ToLower(k)] = k
	}
	inB := make(map[string]bool, len(b))
	for k := range b {
		f := strings.ToLower(k)
		if other, ok := seen[f]; ok && other != k || inB[f] {
			return k, true
		}
		inB[f] = true
	}
	return "", false
}

// resourceTags are aws:ResourceTag/<key> for each of the stored tags.
func resourceTags(tags map[string]string) (keys, error) {
	if key, ok := caseCollision(nil, tags); ok {
		return nil, fmt.Errorf("%w: %s", errStoredTags, key)
	}
	k := keys{}
	for t, v := range tags {
		k[prefixResourceTag+t] = []string{v}
	}
	return k, nil
}

// requestTags are aws:RequestTag/<key> for each of tags and aws:TagKeys,
// their keys, for a request that sets tags. Keys that differ only in case
// are refused as duplicates, since the policy library matches condition
// keys without regard to case.
func requestTags(tags map[string]string) (keys, error) {
	if key, ok := caseCollision(nil, tags); ok {
		return nil, &lambdaapi.DuplicateTagError{Key: key}
	}
	k := keys{}
	if len(tags) == 0 {
		return k, nil
	}
	names := make([]string, 0, len(tags))
	for t, v := range tags {
		k[prefixRequestTag+t] = []string{v}
		names = append(names, t)
	}
	slices.Sort(names)
	k[keyTagKeys] = names
	return k, nil
}

// merge returns the union of ks; a later key replaces an earlier one.
func merge(ks ...keys) keys {
	out := keys{}
	for _, k := range ks {
		for name, v := range k {
			out[name] = v
		}
	}
	return out
}

// functionTags returns the tags of the function name, none when it does not
// exist: the request is evaluated on the function's ARN either way, and is
// answered as not found after it is allowed, as Lambda authorizes a request
// before it looks the function up.
func (m *Module) functionTags(ctx gas.Context, name string) (keys, error) {
	tags, err := m.storedFunctionTags(ctx, name)
	if err != nil {
		return nil, err
	}
	return resourceTags(tags)
}

// storedFunctionTags returns the tags of the function name, none when it
// does not exist.
func (m *Module) storedFunctionTags(ctx gas.Context, name string) (map[string]string, error) {
	fn, err := m.store.GetFunction(ctx, name)
	if errors.Is(err, contracts.ErrFunctionNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fn.Tags, nil
}

// authorizeFunction authorizes op, an operation that takes no qualifier,
// on the function name's unqualified ARN, rebuilt from the service's own
// partition, region and account. extra are further requests to authorize
// with it.
func (m *Module) authorizeFunction(ctx gas.Context, op, name string, extra ...authz.Request) error {
	return m.authorizeOn(ctx, op, name, m.settings.FunctionARN(name), extra...)
}

// authorizeQualifiedFunction authorizes op, an operation that takes a
// qualifier, on the function name with the qualifier the request gives in
// its FunctionName or Qualifier, if any: Lambda compares the policy's
// resource with both the FunctionName and the Qualifier (the Lambda
// Developer Guide, "Referencing functions in the Resource section of
// policies"), so :$LATEST is evaluated as given.
func (m *Module) authorizeQualifiedFunction(ctx gas.Context, op, name string) error {
	return m.authorizeOn(ctx, op, name, m.qualifiedARN(ctx, name))
}

func (m *Module) authorizeOn(
	ctx gas.Context,
	op, name, resource string,
	extra ...authz.Request,
) error {
	return m.authorize(ctx, func() ([]authz.Request, error) {
		tags, err := m.functionTags(ctx, name)
		if err != nil {
			return nil, err
		}
		reqs := make([]authz.Request, 0, 1+len(extra))
		reqs = append(reqs, request(op, resource, tags))
		return append(reqs, extra...), nil
	})
}

// qualifiedARN is the ARN of the function name with the qualifier the
// request gives in its FunctionName or Qualifier, if any. Only $LATEST
// resolves, so it is the only qualifier a resolved request carries.
func (m *Module) qualifiedARN(ctx gas.Context, name string) string {
	arn := m.settings.FunctionARN(name)
	if v, err := lambdaapi.PathParam(ctx, "FunctionName"); err == nil {
		if ref, ok := parseFunctionRef(v); ok && ref.qualifier != "" {
			return arn + ":" + ref.qualifier
		}
	}
	if q := ctx.Query("Qualifier"); q != "" {
		return arn + ":" + q
	}
	return arn
}

// mappingKeys are the condition keys of an operation on the mapping uuid:
// lambda:FunctionArn, the ARN of the function it invokes, and the mapping's
// tags. A mapping that does not exist has neither; the request is answered
// as not found after it is allowed.
func (m *Module) mappingKeys(ctx gas.Context, uuid string) (keys, error) {
	tags, k, err := m.storedMapping(ctx, uuid)
	if err != nil {
		return nil, err
	}
	own, err := resourceTags(tags)
	if err != nil {
		return nil, err
	}
	return merge(own, k), nil
}

// storedMapping returns the tags of the mapping uuid and its
// lambda:FunctionArn, none when it does not exist.
func (m *Module) storedMapping(ctx gas.Context, uuid string) (map[string]string, keys, error) {
	mp, err := m.store.GetMapping(ctx, uuid)
	if errors.Is(err, contracts.ErrMappingNotFound) {
		return nil, keys{}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return mp.Tags, keys{keyFunctionARN: {mp.FunctionARN}}, nil
}

// mayListTags reports whether GetFunction returns fn's tags: "Lambda
// returns tag data only if you have explicit allow permissions for
// lambda:ListTags" (the GetFunction API reference, Tags), so a caller
// denied lambda:ListTags on the function gets the function without them.
func (m *Module) mayListTags(ctx gas.Context, fn *contracts.Function) (bool, error) {
	err := m.authz.Authorize(ctx.Request(), func() ([]authz.Request, error) {
		tags, err := resourceTags(fn.Tags)
		if err != nil {
			return nil, err
		}
		return []authz.Request{request("ListTags", m.settings.FunctionARN(fn.Name), tags)}, nil
	})
	var denied *authz.Denied
	if errors.As(err, &denied) {
		return false, nil
	}
	return err == nil, err
}
