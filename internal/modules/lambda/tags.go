package lambda

import (
	"errors"
	"maps"
	"net/http"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/lambdaapi"
)

// tagged is the resource a tagging operation names: a function or an
// event source mapping, by ARN. update changes its tags in one transaction.
type tagged struct {
	update func(gas.Context, func(map[string]string) (map[string]string, error)) error
}

// resource resolves the Resource path label.
func (m *Module) resource(ctx gas.Context) (*tagged, error) {
	arn, err := lambdaapi.PathParam(ctx, "Resource")
	if err != nil {
		return nil, err
	}
	if uuid, ok := m.settings.MappingOfARN(arn); ok {
		return &tagged{update: func(
			ctx gas.Context, fn func(map[string]string) (map[string]string, error),
		) error {
			_, uErr := m.store.UpdateMapping(ctx, uuid, func(mp *contracts.Mapping) error {
				tags, tErr := fn(mp.Tags)
				mp.Tags = tags
				return tErr
			})
			if errors.Is(uErr, contracts.ErrMappingNotFound) {
				return lambdaapi.ErrNotFound("The resource you requested does not exist.")
			}
			return uErr
		}}, nil
	}
	if !strings.HasPrefix(arn, "arn:") {
		return nil, lambdaapi.ErrValidation("1 validation error detected: Value '" + arn +
			"' at 'resource' failed to satisfy constraint: Member must satisfy regular " +
			"expression pattern: arn:(aws[a-zA-Z-]*):lambda:...")
	}
	name, err := m.resolveName(arn)
	if err != nil {
		return nil, err
	}
	return &tagged{update: func(
		ctx gas.Context, fn func(map[string]string) (map[string]string, error),
	) error {
		_, uErr := m.store.UpdateFunction(ctx, name, func(f *contracts.Function) error {
			tags, tErr := fn(f.Tags)
			f.Tags = tags
			return tErr
		})
		if errors.Is(uErr, contracts.ErrFunctionNotFound) {
			return lambdaapi.ErrNotFound("Function not found: " + m.settings.FunctionARN(name))
		}
		return uErr
	}}, nil
}

func (m *Module) tagResource(ctx gas.Context) error {
	res, err := m.resource(ctx)
	if err != nil {
		return err
	}
	req, err := lambdaapi.Decode[lambdaapi.TagResourceRequest](ctx)
	if err != nil {
		return err
	}
	if err = res.update(ctx, func(tags map[string]string) (map[string]string, error) {
		out := map[string]string{}
		maps.Copy(out, tags)
		maps.Copy(out, req.Tags)
		return out, checkTags(out)
	}); err != nil {
		return err
	}
	return lambdaapi.NoContent(ctx)
}

func (m *Module) untagResource(ctx gas.Context) error {
	res, err := m.resource(ctx)
	if err != nil {
		return err
	}
	keys := ctx.Request().URL.Query()["tagKeys"]
	if err = res.update(ctx, func(tags map[string]string) (map[string]string, error) {
		out := map[string]string{}
		maps.Copy(out, tags)
		for _, k := range keys {
			delete(out, k)
		}
		return out, nil
	}); err != nil {
		return err
	}
	return lambdaapi.NoContent(ctx)
}

func (m *Module) listTags(ctx gas.Context) error {
	res, err := m.resource(ctx)
	if err != nil {
		return err
	}
	var got map[string]string
	// A read through update, which writes the tags back unchanged.
	if err = res.update(ctx, func(tags map[string]string) (map[string]string, error) {
		got = tags
		return tags, nil
	}); err != nil {
		return err
	}
	if got == nil {
		got = map[string]string{}
	}
	return lambdaapi.Write(ctx, http.StatusOK, lambdaapi.ListTagsResponse{Tags: got})
}
