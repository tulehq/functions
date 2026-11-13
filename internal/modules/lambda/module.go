// Package lambda serves the Lambda API: the restJson1 routes of the
// function, invocation, tagging and event source mapping operations in
// scope.
package lambda

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/engine"
	"tule.dev/functions/internal/lambdaapi"
)

const moduleName = "tule/modules/lambda"

// Module registers the Lambda routes and serves them.
type Module struct {
	router   *gas.Router
	store    contracts.Store
	engine   *engine.Engine
	authz    *authz.Authorizer
	settings *contracts.Settings
	names    *nameLocks
	// principals binds function policies on save and shows them on read,
	// nil when the service runs standalone.
	principals Principals
}

// NewModule returns the constructor gas builds the Module with. principals
// binds the function policies' principals, nil to run standalone, where
// policies are stored as sent.
func NewModule(settings *contracts.Settings, principals Principals) func(
	router *gas.Router, store contracts.Store, eng *engine.Engine, az *authz.Authorizer,
) *Module {
	return func(
		router *gas.Router, store contracts.Store, eng *engine.Engine, az *authz.Authorizer,
	) *Module {
		return &Module{
			router: router, store: store, engine: eng, authz: az, settings: settings,
			names: newNameLocks(), principals: principals,
		}
	}
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

type handler func(gas.Context) error

// route is a routed operation: its SDK name, which operations maps to its
// IAM action, its handler, and its method and path.
type route struct {
	h      handler
	op     string
	method string
	path   string
}

// routes are the operations, at the paths and methods of the SDK model.
func (m *Module) routes() []route {
	const (
		fns  = "/2015-03-31/functions"
		fn   = fns + "/{FunctionName}"
		esms = "/2015-03-31/event-source-mappings"
		tags = "/2017-03-31/tags/{Resource}"
		// The whole-policy operations' path, at their own API version.
		policies = "/2026-07-09/resource-policy/{ResourceArn}"
	)
	return []route{
		{m.createFunction, "CreateFunction", http.MethodPost, fns},
		{m.listFunctions, "ListFunctions", http.MethodGet, fns},
		{m.getFunction, "GetFunction", http.MethodGet, fn},
		{m.deleteFunction, "DeleteFunction", http.MethodDelete, fn},
		{
			m.getFunctionConfiguration,
			"GetFunctionConfiguration",
			http.MethodGet,
			fn + "/configuration",
		},
		{
			m.updateFunctionConfiguration,
			"UpdateFunctionConfiguration",
			http.MethodPut,
			fn + "/configuration",
		},
		{m.updateFunctionCode, "UpdateFunctionCode", http.MethodPut, fn + "/code"},
		{m.invoke, "Invoke", http.MethodPost, fn + "/invocations"},
		{m.tagResource, "TagResource", http.MethodPost, tags},
		{m.untagResource, "UntagResource", http.MethodDelete, tags},
		{m.listTags, "ListTags", http.MethodGet, tags},
		{m.addPermission, "AddPermission", http.MethodPost, fn + "/policy"},
		{m.getPolicy, "GetPolicy", http.MethodGet, fn + "/policy"},
		{
			m.removePermission,
			"RemovePermission",
			http.MethodDelete,
			fn + "/policy/{StatementId}",
		},
		{m.putResourcePolicy, "PutResourcePolicy", http.MethodPut, policies},
		{m.getResourcePolicy, "GetResourcePolicy", http.MethodGet, policies},
		{m.deleteResourcePolicy, "DeleteResourcePolicy", http.MethodDelete, policies},
		{m.createMapping, "CreateEventSourceMapping", http.MethodPost, esms},
		{m.listMappings, "ListEventSourceMappings", http.MethodGet, esms},
		{m.getMapping, "GetEventSourceMapping", http.MethodGet, esms + "/{UUID}"},
		{m.updateMapping, "UpdateEventSourceMapping", http.MethodPut, esms + "/{UUID}"},
		{m.deleteMapping, "DeleteEventSourceMapping", http.MethodDelete, esms + "/{UUID}"},
	}
}

// Init registers the routes.
func (m *Module) Init(context.Context) error {
	for _, r := range m.routes() {
		m.router.Handle(m, r.method, r.path, serve(r.h))
	}
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

func serve(h handler) func(gas.Context) error {
	return func(ctx gas.Context) error {
		if err := h(ctx); err != nil {
			return lambdaapi.WriteError(ctx, err)
		}
		return nil
	}
}

// functionNamePattern is a function's own name.
var functionNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// resolveName returns the function name a FunctionName names: a name, a
// partial ARN (account:function:name) or a full ARN, each optionally
// qualified. Only $LATEST exists, so any other qualifier names no function;
// so does an ARN of another partition, account or region.
func (m *Module) resolveName(value string) (string, error) {
	invalid := lambdaapi.ErrValidation(fmt.Sprintf("1 validation error detected: Value '%s' "+
		"at 'functionName' failed to satisfy constraint: Member must satisfy regular "+
		"expression pattern: (arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\\d{1}:)?"+
		"(\\d{12}:)?(function:)?([a-zA-Z0-9-_]+)(:(\\$LATEST|[a-zA-Z0-9-_]+))?", value))
	ref, ok := parseFunctionRef(value)
	if !ok {
		return "", invalid
	}
	if !functionNamePattern.MatchString(ref.name) {
		return "", invalid
	}
	if !m.isOurs(ref) {
		return "", lambdaapi.ErrNotFound("Function not found: " + value)
	}
	if ref.qualifier != "" && ref.qualifier != contracts.LatestVersion {
		return "", lambdaapi.ErrNotFound("Function not found: " +
			m.settings.FunctionARN(ref.name) + ":" + ref.qualifier)
	}
	return ref.name, nil
}

// isOurs reports whether ref is of this service's partition, account and
// region, where it gives them.
func (m *Module) isOurs(ref functionRef) bool {
	return (ref.partition == "" || ref.partition == partition) &&
		(ref.account == "" || ref.account == m.settings.AccountID) &&
		(ref.region == "" || ref.region == m.settings.Region)
}

// partition is the only partition this service's ARNs are in.
const partition = "aws"

// functionRef is what a FunctionName says: the name, and the partition,
// account, region and qualifier when it gives them.
type functionRef struct {
	partition, account, region, name, qualifier string
}

// parseFunctionRef splits a name (name[:qualifier]), a partial ARN
// (account:function:name[:qualifier]) or a full ARN
// (arn:aws:lambda:region:account:function:name[:qualifier]).
func parseFunctionRef(value string) (functionRef, bool) {
	parts := strings.Split(value, ":")
	var ref functionRef
	var rest []string
	switch {
	case len(parts) <= 2:
		ref.name, rest = parts[0], parts[1:]
	case len(parts) <= 4 && parts[1] == "function":
		ref.account, ref.name, rest = parts[0], parts[2], parts[3:]
	case len(parts) >= 7 && len(parts) <= 8 && parts[0] == "arn" && parts[2] == "lambda" &&
		parts[5] == "function":
		ref.partition, ref.region, ref.account = parts[1], parts[3], parts[4]
		ref.name, rest = parts[6], parts[7:]
	default:
		return ref, false
	}
	ref.qualifier = strings.Join(rest, "")
	return ref, true
}

// pathFunction resolves the FunctionName path label of an operation that
// takes no Qualifier parameter, such as UpdateFunctionCode; one in the query
// is not the operation's, and is ignored as unknown parameters are.
func (m *Module) pathFunction(ctx gas.Context) (string, error) {
	v, err := lambdaapi.PathParam(ctx, "FunctionName")
	if err != nil {
		return "", err
	}
	return m.resolveName(v)
}

// pathQualifiedFunction resolves the FunctionName path label and the
// Qualifier query parameter of an operation that takes one: GetFunction,
// GetFunctionConfiguration, DeleteFunction and Invoke.
func (m *Module) pathQualifiedFunction(ctx gas.Context) (string, error) {
	name, err := m.pathFunction(ctx)
	if err != nil {
		return "", err
	}
	if q := ctx.Query("Qualifier"); q != "" && q != contracts.LatestVersion {
		return "", lambdaapi.ErrNotFound("Function not found: " +
			m.settings.FunctionARN(name) + ":" + q)
	}
	return name, nil
}

// pageOf reads a list operation's Marker and MaxItems, from 1 to 10000,
// defaulting to def.
func pageOf(ctx gas.Context, def int) (contracts.PageInput, error) {
	page := contracts.PageInput{Token: ctx.Query("Marker"), Size: def}
	if v := ctx.Query("MaxItems"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10000 {
			return page, lambdaapi.ErrValidation(fmt.Sprintf("1 validation error detected: "+
				"Value '%s' at 'maxItems' failed to satisfy constraint: Member must have "+
				"value between 1 and 10000", v))
		}
		page.Size = n
	}
	return page, nil
}
