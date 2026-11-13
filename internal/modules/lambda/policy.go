package lambda

// The function policy: a function's resource-based policy, which
// AddPermission and RemovePermission change a statement at a time,
// PutResourcePolicy and DeleteResourcePolicy replace and delete whole, and
// GetPolicy and GetResourcePolicy return. Each operation's request and
// answer are the Lambda API Reference's. The policy is evaluated with the
// identity policies of the caller on every action on the function, its
// Allow statements only on the actions it can grant (policyActions).
//
// With an identity endpoint, a policy is stored bound, as AWS saves it:
// each IAM user or role ARN in its Principal and NotPrincipal elements is
// replaced by that user's or role's unique ID, so a user or role deleted
// and created again under the same name is not the principal the policy
// names. It is evaluated bound, and returned shown: each unique ID that a
// user or role still has as its current ARN, and one that none has as the
// ID.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gasmod/gas"
	"tule.dev/identity/principals"
	"tule.dev/policy"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/lambdaapi"
)

// maxPolicySize is the function policy's limit: "Function resource-based
// policy: 20 KB" (the Lambda Developer Guide, "Lambda quotas"), and
// PutResourcePolicy's Policy, "Maximum length of 20480". It is counted in
// bytes of the policy as stored.
const maxPolicySize = 20480

// The constraints of the policy operations' members, from the Lambda API
// Reference.
var (
	actionPattern           = regexp.MustCompile(`^(lambda:[*]|lambda:[a-zA-Z]+|[*])$`)
	principalPattern        = regexp.MustCompile(`^[^\s]+$`)
	addStatementIDPattern   = regexp.MustCompile(`^[a-zA-Z0-9-_]+$`)
	statementIDPattern      = regexp.MustCompile(`^[a-zA-Z0-9-_.]+$`)
	eventSourceTokenPattern = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)
	orgIDPattern            = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	sourceAccountPattern    = regexp.MustCompile(`^\d{12}$`)
	sourceARNPattern        = regexp.MustCompile(
		`^arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)$`)
	policyRevisionPattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	resourceARNPattern = regexp.MustCompile(`^arn:(aws[a-zA-Z-]*)?:lambda:(eusc-)?` +
		`[a-z]{2}((-gov)|(-iso([a-z]?)))?-[a-z]+-\d{1}:\d{12}:function:[a-zA-Z0-9-_]+` +
		`(:(\$LATEST(\.PUBLISHED)?|[a-zA-Z0-9-_])+)?$`)
	serviceDomainPattern = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)
	accountIDPattern     = regexp.MustCompile(`^\d{12}$`)
)

// The members' maximum lengths.
const (
	maxStatementID      = 100
	maxEventSourceToken = 256
	maxResourceARN      = 256
	minOrgID            = 12
)

// The further actions the whole-policy operations need, which the Service
// Authorization Reference lists among their authorized actions:
// PutResourcePolicy needs lambda:AddPermission and lambda:RemovePermission,
// GetResourcePolicy lambda:GetPolicy, and DeleteResourcePolicy
// lambda:RemovePermission (as the Lambda Developer Guide's "Required
// permissions" table says too).
const (
	actionAddPermission    = "lambda:AddPermission"
	actionRemovePermission = "lambda:RemovePermission"
	actionGetPolicy        = "lambda:GetPolicy"
)

// The keys of AddPermission's own condition keys.
const (
	keyPrincipal           = "lambda:Principal"
	keyFunctionURLAuthType = "lambda:FunctionUrlAuthType"
)

// The policy errors whose messages AWS documents nowhere: these are this
// service's wording, in the form Lambda's other messages take.
var (
	errLatest = lambdaapi.ErrInvalidParameter(
		"We currently do not support adding policies for $LATEST.")
	// errInvalidPrincipal is the message Lambda is reported to give an
	// AddPermission whose principal is invalid or no longer exists (AWS
	// re:Post, "lambda functional url permission"), though the reference
	// documents none. PutResourcePolicy refuses a user or role that does not
	// exist with it too, so both writes answer alike.
	errInvalidPrincipal = lambdaapi.ErrInvalidParameter(
		"The provided principal was invalid. Please check the principal and try again.")
	errNoPolicy = lambdaapi.ErrNotFound("The resource you requested does not exist.")
)

// Principals binds a function policy's principals to unique IDs when it is
// saved and shows a bound policy as AWS shows it, as identity's
// tule.dev/identity/principals Client does. Bind's error for a user or role
// ARN that no user or role has matches principals.ErrInvalidPrincipal.
type Principals interface {
	Bind(ctx context.Context, doc string) (string, error)
	Show(ctx context.Context, doc string) (string, error)
}

// bind is doc bound, as it is stored, or doc itself when the service runs
// standalone. A policy naming a user or role that does not exist is refused
// with invalid, the operation's error; a failure to reach identity fails the
// write.
func (m *Module) bind(ctx context.Context, doc string, invalid error) (string, error) {
	if m.principals == nil {
		return doc, nil
	}
	out, err := m.principals.Bind(ctx, doc)
	if errors.Is(err, principals.ErrInvalidPrincipal) {
		return "", invalid
	}
	if err != nil {
		return "", fmt.Errorf("lambda: bind the function policy's principals: %w", err)
	}
	return out, nil
}

// show is the stored doc as it is returned, or doc itself when the service
// runs standalone. A failure to reach identity fails the read.
func (m *Module) show(ctx context.Context, doc string) (string, error) {
	if m.principals == nil {
		return doc, nil
	}
	out, err := m.principals.Show(ctx, doc)
	if err != nil {
		return "", fmt.Errorf("lambda: show the function policy's principals: %w", err)
	}
	return out, nil
}

// bindStatement is the statement s bound, as AddPermission adds it. Only
// the new statement is bound: the policy's other statements are kept as
// they are stored, so one a release before binding stored keeps matching by
// ARN, and one naming a principal deleted since does not fail the call.
func (m *Module) bindStatement(
	ctx context.Context,
	s *permissionStatement,
) (json.RawMessage, error) {
	b, err := marshal(s)
	if err != nil {
		return nil, err
	}
	if m.principals == nil {
		return json.RawMessage(b), nil
	}
	doc, err := marshal(policyDoc{
		Version: "2012-10-17", Statement: []json.RawMessage{json.RawMessage(b)},
	})
	if err != nil {
		return nil, err
	}
	if doc, err = m.bind(ctx, doc, errInvalidPrincipal); err != nil {
		return nil, err
	}
	p, err := decodePolicy(doc)
	if err != nil {
		return nil, err
	}
	if len(p.Statement) != 1 {
		return nil, fmt.Errorf("lambda: binding a statement gave %d statements", len(p.Statement))
	}
	return p.Statement[0], nil
}

// revisionMismatch is PreconditionFailedException, as the API Reference
// describes it, pointing to op for the latest RevisionId.
func revisionMismatch(op string) error {
	return lambdaapi.ErrPreconditionFailed("The RevisionId provided does not match the " +
		"latest RevisionId for the Lambda function or alias. Call the " + op +
		" API to retrieve the latest RevisionId for your resource.")
}

// patternError is the ValidationException of a value of member that
// pattern, anchored, does not match; the message gives the model's
// pattern, without the anchors.
func patternError(member, value, pattern string) error {
	pattern = strings.TrimSuffix(strings.TrimPrefix(pattern, "^"), "$")
	return lambdaapi.ErrValidation(fmt.Sprintf("1 validation error detected: Value '%s' at "+
		"'%s' failed to satisfy constraint: Member must satisfy regular expression pattern: %s",
		value, member, pattern))
}

func nullError(member string) error {
	return lambdaapi.ErrValidation("1 validation error detected: Value null at '" + member +
		"' failed to satisfy constraint: Member must not be null")
}

// policyDoc is a function policy's top level. A stored policy parsed with
// policy.ParseResource, which refuses any other element and repeated keys,
// so these are all it has. Statement is always written as an array.
type policyDoc struct {
	Version   string            `json:"Version,omitempty"`
	ID        string            `json:"Id,omitempty"`
	Statement []json.RawMessage `json:"Statement"`
}

// decodePolicy splits the stored policy doc into its top level and
// statements; Statement may be one statement or an array of them.
func decodePolicy(doc string) (policyDoc, error) {
	var raw struct {
		Version   string          `json:"Version"`
		ID        string          `json:"Id"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return policyDoc{}, fmt.Errorf("lambda: decode a stored policy: %w", err)
	}
	out := policyDoc{Version: raw.Version, ID: raw.ID}
	if s := bytes.TrimSpace(raw.Statement); len(s) > 0 && s[0] == '{' {
		out.Statement = []json.RawMessage{s}
		return out, nil
	}
	if err := json.Unmarshal(raw.Statement, &out.Statement); err != nil {
		return policyDoc{}, fmt.Errorf("lambda: decode a stored policy's statements: %w", err)
	}
	return out, nil
}

// statementID is the Sid of the statement s, and whether it has one.
func statementID(s json.RawMessage) (string, bool) {
	var st struct {
		Sid *string `json:"Sid"`
	}
	if json.Unmarshal(s, &st) != nil || st.Sid == nil {
		return "", false
	}
	return *st.Sid, true
}

// marshal is v as compact JSON, with no HTML escaping, as Lambda writes
// policies.
func marshal(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("lambda: encode a policy: %w", err)
	}
	return string(bytes.TrimSuffix(b.Bytes(), []byte("\n"))), nil
}

// checkPolicy refuses doc, a whole function policy, when it is over the
// size limit or does not parse as a resource-based policy.
func checkPolicy(doc string) error {
	if len(doc) > maxPolicySize {
		return lambdaapi.NewError(http.StatusBadRequest, lambdaapi.CodePolicyLengthExceeded,
			"The final policy size ("+strconv.Itoa(len(doc))+") is bigger than the limit ("+
				strconv.Itoa(maxPolicySize)+").")
	}
	if _, err := policy.ParseResource([]byte(doc)); err != nil {
		var pe *policy.ParseError
		if errors.As(err, &pe) {
			return lambdaapi.ErrInvalidParameter("The policy is not valid: " + pe.Message)
		}
		return fmt.Errorf("lambda: parse a function policy: %w", err)
	}
	return nil
}

// permissionStatement is the statement AddPermission adds, with its
// elements in the order Lambda writes them (the AWS CLI Command Reference,
// add-permission and get-policy): Sid, Effect, Principal, Action,
// Resource, Condition.
//
//nolint:govet // fieldalignment: the field order is the JSON order Lambda writes
type permissionStatement struct {
	Sid       string                       `json:"Sid"`
	Effect    string                       `json:"Effect"`
	Principal any                          `json:"Principal"`
	Action    string                       `json:"Action"`
	Resource  string                       `json:"Resource"`
	Condition map[string]map[string]string `json:"Condition,omitempty"`
}

// principalOf is the Principal element of an AddPermission Principal: "*"
// as is; an account ID as its root ARN, {"AWS": "arn:aws:iam::<account>:root"}
// (the Developer Guide's add-permission output, "Granting function access
// to other accounts"); an ARN as {"AWS": <arn>}; and a domain-style service
// identifier, such as sns.amazonaws.com, as {"Service": <it>} ("Granting
// function access to AWS services"). Anything else is refused.
func principalOf(v string) (any, error) {
	var p any
	switch {
	case v == "*":
		return "*", nil
	case accountIDPattern.MatchString(v):
		p = map[string]string{"AWS": "arn:" + partition + ":iam::" + v + ":root"}
	case len(v) > 4 && v[:4] == "arn:":
		p = map[string]string{"AWS": v}
	case serviceDomainPattern.MatchString(v):
		return map[string]string{"Service": v}, nil
	default:
		return nil, errInvalidPrincipal
	}
	// An ARN must be one a resource-based policy can name.
	doc, err := marshal(policyDoc{Statement: []json.RawMessage{json.RawMessage(
		`{"Effect":"Allow","Principal":` + mustMarshal(p) + `,"Action":"lambda:GetPolicy",` +
			`"Resource":"*"}`)}})
	if err != nil {
		return nil, err
	}
	if _, err = policy.ParseResource([]byte(doc)); err != nil {
		return nil, errInvalidPrincipal
	}
	return p, nil
}

// mustMarshal is v, a map of strings, as JSON, which cannot fail.
func mustMarshal(v any) string {
	s, err := marshal(v)
	if err != nil {
		panic(err)
	}
	return s
}

// checkRequired refuses an AddPermission request without a StatementId,
// an Action or a Principal, and the members longer than the model allows.
func checkRequired(req *lambdaapi.AddPermissionRequest) error {
	switch {
	case req.StatementID == nil:
		return nullError("statementId")
	case req.Action == nil:
		return nullError("action")
	case req.Principal == nil:
		return nullError("principal")
	case len(*req.StatementID) < 1 || len(*req.StatementID) > maxStatementID:
		return constraint("statementId", "have length less than or equal to 100")
	case len(deref(req.EventSourceToken)) > maxEventSourceToken:
		return constraint("eventSourceToken", "have length less than or equal to 256")
	case req.PrincipalOrgID != nil && len(*req.PrincipalOrgID) < minOrgID:
		return constraint("principalOrgID", "have length greater than or equal to 12")
	}
	return nil
}

// checkAddPermission holds an AddPermission request to the model's
// constraints. Every member sent is checked, the empty string included,
// which no pattern of these members matches: a condition member sent
// empty is refused, never left out of the statement.
func checkAddPermission(req *lambdaapi.AddPermissionRequest) error {
	if err := checkRequired(req); err != nil {
		return err
	}
	for _, c := range []struct {
		value   *string
		pattern *regexp.Regexp
		member  string
	}{
		{req.StatementID, addStatementIDPattern, "statementId"},
		{req.Action, actionPattern, "action"},
		{req.Principal, principalPattern, "principal"},
		{req.EventSourceToken, eventSourceTokenPattern, "eventSourceToken"},
		{req.PrincipalOrgID, orgIDPattern, "principalOrgID"},
		{req.SourceAccount, sourceAccountPattern, "sourceAccount"},
		{req.SourceArn, sourceARNPattern, "sourceArn"},
	} {
		if c.value != nil && !c.pattern.MatchString(*c.value) {
			return patternError(c.member, *c.value, c.pattern.String())
		}
	}
	if t := deref(req.FunctionURLAuthType); req.FunctionURLAuthType != nil &&
		t != "NONE" && t != "AWS_IAM" {
		return lambdaapi.ErrValidation(fmt.Sprintf("1 validation error detected: Value '%s' "+
			"at 'functionUrlAuthType' failed to satisfy constraint: Member must satisfy enum "+
			"value set: [NONE, AWS_IAM]", t))
	}
	return nil
}

// statementOf is the statement AddPermission adds for req to the function
// at arn. The request's conditions become the statement's:
//   - SourceArn: ArnLike on AWS:SourceArn (the Developer Guide's
//     add-permission output, "Tutorial: Using AWS Lambda with Amazon
//     Simple Notification Service");
//   - SourceAccount: StringEquals on AWS:SourceAccount;
//   - PrincipalOrgID: StringEquals on aws:PrincipalOrgID ("Granting
//     function access to an organization");
//   - FunctionUrlAuthType: StringEquals on lambda:FunctionUrlAuthType, and
//     InvokedViaFunctionUrl: Bool true on lambda:InvokedViaFunctionUrl
//     ("Control access to Lambda function URLs");
//   - EventSourceToken: StringEquals on lambda:EventSourceToken.
func statementOf(req *lambdaapi.AddPermissionRequest, arn string) (*permissionStatement, error) {
	principal, err := principalOf(*req.Principal)
	if err != nil {
		return nil, err
	}
	s := &permissionStatement{
		Sid: *req.StatementID, Effect: "Allow", Principal: principal,
		Action: *req.Action, Resource: arn,
	}
	// InvokedViaFunctionUrl false asks for no restriction, so only true
	// becomes a condition.
	var invokedViaURL *string
	if req.InvokedViaFunctionURL != nil && *req.InvokedViaFunctionURL {
		invokedViaURL = new("true")
	}
	for _, c := range []struct {
		value   *string
		op, key string
	}{
		{req.SourceArn, "ArnLike", "AWS:SourceArn"},
		{req.SourceAccount, "StringEquals", "AWS:SourceAccount"},
		{req.PrincipalOrgID, "StringEquals", "aws:PrincipalOrgID"},
		{req.FunctionURLAuthType, "StringEquals", keyFunctionURLAuthType},
		{invokedViaURL, "Bool", "lambda:InvokedViaFunctionUrl"},
		{req.EventSourceToken, "StringEquals", "lambda:EventSourceToken"},
	} {
		// Every condition member sent is one; checkAddPermission refused
		// any that was empty.
		if c.value == nil {
			continue
		}
		if s.Condition == nil {
			s.Condition = map[string]map[string]string{}
		}
		if s.Condition[c.op] == nil {
			s.Condition[c.op] = map[string]string{}
		}
		s.Condition[c.op][c.key] = *c.value
	}
	return s, nil
}

// withStatement is the policy doc, empty for none, with the statement s,
// whose Sid is sid, added: a new policy is
// {"Version":"2012-10-17","Id":"default","Statement":[s]} (the AWS CLI
// Command Reference, get-policy). A statement ID already in the policy is
// refused.
func withStatement(doc, sid string, s json.RawMessage) (string, error) {
	p := policyDoc{Version: "2012-10-17", ID: "default"}
	if doc != "" {
		var err error
		if p, err = decodePolicy(doc); err != nil {
			return "", err
		}
	}
	for _, st := range p.Statement {
		if id, ok := statementID(st); ok && id == sid {
			return "", lambdaapi.ErrConflict("The statement id (" + sid + ") provided already " +
				"exists. Please provide a new statement id, or remove the existing statement.")
		}
	}
	p.Statement = append(p.Statement, s)
	return marshal(p)
}

// withoutStatement is the policy doc without the statement sid, empty when
// none is left.
func withoutStatement(doc, sid string) (string, error) {
	p, err := decodePolicy(doc)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(p.Statement, func(st json.RawMessage) bool {
		id, ok := statementID(st)
		return ok && id == sid
	})
	if i < 0 {
		return "", lambdaapi.ErrNotFound("Statement " + sid + " is not found in resource policy.")
	}
	p.Statement = slices.Delete(p.Statement, i, i+1)
	if len(p.Statement) == 0 {
		return "", nil
	}
	return marshal(p)
}

// policyFunction resolves the FunctionName and Qualifier of a function
// policy operation: the function's name, and whether it names $LATEST,
// the only version a function has.
func (m *Module) policyFunction(ctx gas.Context) (string, bool, error) {
	name, err := m.pathQualifiedFunction(ctx)
	if err != nil {
		return "", false, err
	}
	return name, m.qualifiedARN(ctx, name) != m.settings.FunctionARN(name), nil
}

// authorizeActions authorizes op on the function name at resource, and the
// further actions also on it, each with the function's tags and the keys
// k, and with the function's policy: its Deny statements on every action,
// its Allow statements on the actions it can grant.
func (m *Module) authorizeActions(
	ctx gas.Context,
	op, name, resource string,
	k keys,
	also ...string,
) error {
	return m.authorize(ctx, func() ([]authz.Request, error) {
		fn, err := m.storedFunction(ctx, name)
		if err != nil {
			return nil, err
		}
		tags, err := resourceTags(fn.tags)
		if err != nil {
			return nil, err
		}
		k = merge(tags, k)
		reqs := []authz.Request{withPolicy(request(op, resource, k), fn.policy)}
		for _, action := range also {
			reqs = append(reqs, withPolicy(
				authz.Request{Action: action, Resource: resource, Context: k}, fn.policy))
		}
		return reqs, nil
	})
}

// setPolicy changes the function name's policy with change, which returns
// the new policy, empty for none, after checking the function's policy
// revision against revision when it is set.
func (m *Module) setPolicy(
	ctx gas.Context,
	name string,
	revision *string,
	revisionOp string,
	change func(doc string) (string, error),
) (*contracts.Function, error) {
	fn, err := m.store.UpdateFunction(ctx, name, func(f *contracts.Function) error {
		if revision != nil && *revision != f.PolicyRevisionID {
			return revisionMismatch(revisionOp)
		}
		doc, cErr := change(f.Policy)
		if cErr != nil {
			return cErr
		}
		f.Policy, f.PolicyRevisionID = doc, ""
		if doc != "" {
			f.PolicyRevisionID = ids.UUID()
		}
		return nil
	})
	if errors.Is(err, contracts.ErrFunctionNotFound) {
		return nil, lambdaapi.ErrNotFound("Function not found: " + m.settings.FunctionARN(name))
	}
	return fn, err
}

// decodePermission decodes and checks an AddPermission request, once:
// its keys are authorized and its statement added from the same decoding.
// The keys are lambda:Principal and, when it is set,
// lambda:FunctionUrlAuthType.
func decodePermission(ctx gas.Context) (*lambdaapi.AddPermissionRequest, keys, error) {
	req, err := lambdaapi.Decode[lambdaapi.AddPermissionRequest](ctx)
	if err != nil {
		return nil, nil, err
	}
	if err = checkAddPermission(&req); err != nil {
		return nil, nil, err
	}
	k := keys{keyPrincipal: {*req.Principal}}
	if req.FunctionURLAuthType != nil {
		k[keyFunctionURLAuthType] = []string{*req.FunctionURLAuthType}
	}
	return &req, k, nil
}

func (m *Module) addPermission(ctx gas.Context) error {
	name, latest, err := m.policyFunction(ctx)
	if err != nil {
		return err
	}
	defer m.names.write(name)()
	req, k, err := decodePermission(ctx)
	if err != nil {
		return err
	}
	if err = m.authorizeActions(ctx, "AddPermission", name,
		m.qualifiedARN(ctx, name), k); err != nil {
		return err
	}
	// "Lambda does not support adding policies to version $LATEST." (the
	// AddPermission API reference).
	if latest {
		return errLatest
	}
	s, err := statementOf(req, m.settings.FunctionARN(name))
	if err != nil {
		return err
	}
	bound, err := m.bindStatement(ctx, s)
	if err != nil {
		return err
	}
	if _, err = m.setPolicy(ctx, name, req.RevisionID, "GetPolicy",
		func(doc string) (string, error) {
			out, wErr := withStatement(doc, s.Sid, bound)
			if wErr != nil {
				return "", wErr
			}
			return out, checkPolicy(out)
		}); err != nil {
		return err
	}
	// The statement as sent is the bound one shown: its principal, if a user
	// or role, has the ARN it was bound by.
	b, err := marshal(s)
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusCreated, lambdaapi.AddPermissionResponse{Statement: b})
}

// pathStatementID reads RemovePermission's StatementId path label.
func pathStatementID(ctx gas.Context) (string, error) {
	sid, err := lambdaapi.PathParam(ctx, "StatementId")
	if err != nil {
		return "", err
	}
	if len(sid) > maxStatementID {
		return "", constraint("statementId", "have length less than or equal to 100")
	}
	if !statementIDPattern.MatchString(sid) {
		return "", patternError("statementId", sid, statementIDPattern.String())
	}
	return sid, nil
}

// queryRevision is the RevisionId query parameter, nil when the request
// has none.
func queryRevision(ctx gas.Context) *string {
	q := ctx.Request().URL.Query()
	if !q.Has("RevisionId") {
		return nil
	}
	v := q.Get("RevisionId")
	return &v
}

func (m *Module) removePermission(ctx gas.Context) error {
	name, latest, err := m.policyFunction(ctx)
	if err != nil {
		return err
	}
	sid, err := pathStatementID(ctx)
	if err != nil {
		return err
	}
	defer m.names.write(name)()
	if err = m.authorizeActions(ctx, "RemovePermission", name,
		m.qualifiedARN(ctx, name), nil); err != nil {
		return err
	}
	revision := queryRevision(ctx)
	if _, err = m.getOrNotFound(ctx, name); err != nil {
		return err
	}
	// $LATEST has no policy of its own: one cannot be added to it.
	if latest {
		return errNoPolicy
	}
	if _, err = m.setPolicy(ctx, name, revision, "GetPolicy", func(doc string) (string, error) {
		if doc == "" {
			return "", errNoPolicy
		}
		return withoutStatement(doc, sid)
	}); err != nil {
		return err
	}
	return lambdaapi.NoContent(ctx)
}

func (m *Module) getPolicy(ctx gas.Context) error {
	name, latest, err := m.policyFunction(ctx)
	if err != nil {
		return err
	}
	fn, err := m.readPolicy(ctx, name, latest, func() error {
		return m.authorizeActions(ctx, "GetPolicy", name, m.qualifiedARN(ctx, name), nil)
	})
	if err != nil {
		return err
	}
	return m.writePolicy(ctx, fn)
}

// readPolicy authorizes the read with authorize and reads the function
// name, under the name's lock, not found when it has no policy or the
// request names $LATEST. The lock is released on return, before the policy
// is shown, so an identity slow to answer holds up only this read, not the
// operations on the function that wait for the lock.
func (m *Module) readPolicy(
	ctx gas.Context,
	name string,
	latest bool,
	authorize func() error,
) (*contracts.Function, error) {
	defer m.names.read(name)()
	if err := authorize(); err != nil {
		return nil, err
	}
	fn, err := m.getOrNotFound(ctx, name)
	if err != nil {
		return nil, err
	}
	if latest || fn.Policy == "" {
		return nil, errNoPolicy
	}
	return fn, nil
}

// writePolicy answers with fn's policy, shown, and its revision.
func (m *Module) writePolicy(ctx gas.Context, fn *contracts.Function) error {
	shown, err := m.show(ctx, fn.Policy)
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusOK,
		lambdaapi.PolicyResponse{Policy: shown, RevisionID: fn.PolicyRevisionID})
}

// resourceARN resolves the ResourceArn path label of the whole-policy
// operations, a complete function ARN, possibly qualified: the function's
// name, whether it names $LATEST, and the ARN it is evaluated on, rebuilt
// from the service's own partition, region and account.
func (m *Module) resourceARN(ctx gas.Context) (string, bool, string, error) {
	arn, err := lambdaapi.PathParam(ctx, "ResourceArn")
	if err != nil {
		return "", false, "", err
	}
	if len(arn) > maxResourceARN {
		return "", false, "", constraint("resourceArn",
			"have length less than or equal to 256")
	}
	if !resourceARNPattern.MatchString(arn) {
		return "", false, "", patternError("resourceArn", arn, resourceARNPattern.String())
	}
	name, err := m.resolveName(arn)
	if err != nil {
		return "", false, "", err
	}
	ref, _ := parseFunctionRef(arn)
	if ref.qualifier != "" {
		return name, true, m.settings.FunctionARN(name) + ":" + ref.qualifier, nil
	}
	return name, false, m.settings.FunctionARN(name), nil
}

// checkPolicyRevision holds a whole-policy operation's RevisionId to the
// model's: 36 characters, a UUID.
func checkPolicyRevision(v *string) error {
	if v == nil {
		return nil
	}
	if len(*v) != 36 {
		return constraint("revisionId", "have length greater than or equal to 36")
	}
	if !policyRevisionPattern.MatchString(*v) {
		return patternError("revisionId", *v, policyRevisionPattern.String())
	}
	return nil
}

// decodePutPolicy decodes and checks a PutResourcePolicy request against
// the model: a Policy of 1 to 20480 characters, and a UUID RevisionId.
func decodePutPolicy(ctx gas.Context) (*lambdaapi.PutResourcePolicyRequest, error) {
	req, err := lambdaapi.Decode[lambdaapi.PutResourcePolicyRequest](ctx)
	if err != nil {
		return nil, err
	}
	if req.Policy == nil {
		return nil, nullError("policy")
	}
	if n := utf8.RuneCountInString(*req.Policy); n < 1 || n > maxPolicySize {
		return nil, constraint("policy", "have length less than or equal to 20480")
	}
	return &req, checkPolicyRevision(req.RevisionID)
}

func (m *Module) putResourcePolicy(ctx gas.Context) error {
	name, latest, arn, err := m.resourceARN(ctx)
	if err != nil {
		return err
	}
	fn, err := m.storePolicy(ctx, name, latest, arn)
	if err != nil {
		return err
	}
	// The policy is shown once the name's lock is released, so an identity
	// slow to answer holds up only this call. A failure to show it fails the
	// call although the policy is stored.
	shown, err := m.show(ctx, fn.Policy)
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusOK,
		lambdaapi.PolicyResponse{Policy: shown, RevisionID: fn.PolicyRevisionID})
}

// storePolicy decodes, authorizes, binds and stores a PutResourcePolicy's
// policy on the function name at arn, under the name's lock, and returns
// the function as stored. The policy is bound between authorization and
// the write, so a failure to reach identity stores nothing, and the bound
// policy is held to the size limit too, as it is stored; an identity slow
// to answer holds the lock, and the operations on the function wait.
func (m *Module) storePolicy(
	ctx gas.Context,
	name string,
	latest bool,
	arn string,
) (*contracts.Function, error) {
	defer m.names.write(name)()
	req, err := decodePutPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if err = m.authorizeActions(ctx, "PutResourcePolicy", name, arn, nil,
		actionAddPermission, actionRemovePermission); err != nil {
		return nil, err
	}
	if latest {
		return nil, errLatest
	}
	if err = checkPolicy(*req.Policy); err != nil {
		return nil, err
	}
	bound, err := m.bind(ctx, *req.Policy, errInvalidPrincipal)
	if err != nil {
		return nil, err
	}
	if err = checkPolicy(bound); err != nil {
		return nil, err
	}
	return m.setPolicy(ctx, name, req.RevisionID, "GetResourcePolicy",
		func(string) (string, error) { return bound, nil })
}

func (m *Module) getResourcePolicy(ctx gas.Context) error {
	name, latest, arn, err := m.resourceARN(ctx)
	if err != nil {
		return err
	}
	fn, err := m.readPolicy(ctx, name, latest, func() error {
		return m.authorizeActions(ctx, "GetResourcePolicy", name, arn, nil, actionGetPolicy)
	})
	if err != nil {
		return err
	}
	return m.writePolicy(ctx, fn)
}

func (m *Module) deleteResourcePolicy(ctx gas.Context) error {
	name, latest, arn, err := m.resourceARN(ctx)
	if err != nil {
		return err
	}
	revision := queryRevision(ctx)
	if err = checkPolicyRevision(revision); err != nil {
		return err
	}
	defer m.names.write(name)()
	if err = m.authorizeActions(ctx, "DeleteResourcePolicy", name, arn, nil,
		actionRemovePermission); err != nil {
		return err
	}
	if _, err = m.getOrNotFound(ctx, name); err != nil {
		return err
	}
	if latest {
		return errNoPolicy
	}
	if _, err = m.setPolicy(ctx, name, revision, "GetResourcePolicy",
		func(doc string) (string, error) {
			if doc == "" {
				return "", errNoPolicy
			}
			return "", nil
		}); err != nil {
		return err
	}
	return lambdaapi.NoContent(ctx)
}
