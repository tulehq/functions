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
	settings *contracts.Settings
}

// NewModule returns the constructor gas builds the Module with.
func NewModule(settings *contracts.Settings) func(
	router *gas.Router, store contracts.Store, eng *engine.Engine,
) *Module {
	return func(router *gas.Router, store contracts.Store, eng *engine.Engine) *Module {
		return &Module{router: router, store: store, engine: eng, settings: settings}
	}
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

type handler func(gas.Context) error

// Init registers the routes, at the paths and methods of the SDK model.
func (m *Module) Init(context.Context) error {
	const (
		fns  = "/2015-03-31/functions"
		fn   = fns + "/{FunctionName}"
		esms = "/2015-03-31/event-source-mappings"
		tags = "/2017-03-31/tags/{Resource}"
	)
	routes := []struct {
		h      handler
		method string
		path   string
	}{
		{m.createFunction, http.MethodPost, fns},
		{m.listFunctions, http.MethodGet, fns},
		{m.getFunction, http.MethodGet, fn},
		{m.deleteFunction, http.MethodDelete, fn},
		{m.getFunctionConfiguration, http.MethodGet, fn + "/configuration"},
		{m.updateFunctionConfiguration, http.MethodPut, fn + "/configuration"},
		{m.updateFunctionCode, http.MethodPut, fn + "/code"},
		{m.invoke, http.MethodPost, fn + "/invocations"},
		{m.tagResource, http.MethodPost, tags},
		{m.untagResource, http.MethodDelete, tags},
		{m.listTags, http.MethodGet, tags},
		{m.createMapping, http.MethodPost, esms},
		{m.listMappings, http.MethodGet, esms},
		{m.getMapping, http.MethodGet, esms + "/{UUID}"},
		{m.updateMapping, http.MethodPut, esms + "/{UUID}"},
		{m.deleteMapping, http.MethodDelete, esms + "/{UUID}"},
	}
	for _, r := range routes {
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
// so does an ARN of another account or region.
func (m *Module) resolveName(value string) (string, error) {
	invalid := lambdaapi.ErrValidation(fmt.Sprintf("1 validation error detected: Value '%s' "+
		"at 'functionName' failed to satisfy constraint: Member must satisfy regular "+
		"expression pattern: (arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\\d{1}:)?"+
		"(\\d{12}:)?(function:)?([a-zA-Z0-9-_]+)(:(\\$LATEST|[a-zA-Z0-9-_]+))?", value))
	ref, ok := parseFunctionRef(value)
	if !ok {
		return "", invalid
	}
	account, region, name, qualifier := ref.account, ref.region, ref.name, ref.qualifier
	if !functionNamePattern.MatchString(name) {
		return "", invalid
	}
	if (account != "" && account != m.settings.AccountID) ||
		(region != "" && region != m.settings.Region) {
		return "", lambdaapi.ErrNotFound("Function not found: " + value)
	}
	if qualifier != "" && qualifier != contracts.LatestVersion {
		return "", lambdaapi.ErrNotFound("Function not found: " +
			m.settings.FunctionARN(name) + ":" + qualifier)
	}
	return name, nil
}

// functionRef is what a FunctionName says: the name, and the account,
// region and qualifier when it gives them.
type functionRef struct {
	account, region, name, qualifier string
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
		ref.region, ref.account, ref.name, rest = parts[3], parts[4], parts[6], parts[7:]
	default:
		return ref, false
	}
	ref.qualifier = strings.Join(rest, "")
	return ref, true
}

// pathFunction resolves the FunctionName path label and the Qualifier
// query parameter.
func (m *Module) pathFunction(ctx gas.Context) (string, error) {
	v, err := lambdaapi.PathParam(ctx, "FunctionName")
	if err != nil {
		return "", err
	}
	name, err := m.resolveName(v)
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
