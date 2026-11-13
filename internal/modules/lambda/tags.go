package lambda

import (
	"errors"
	"maps"
	"net/http"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/lambdaapi"
)

// tagged is the resource a tagging operation names: a function or an
// event source mapping, by ARN. update changes its tags in one transaction;
// stored returns its tags as they are, and its other condition keys.
//
// lock holds the resource from authorization until the operation has acted:
// a function's name lock, since a function can be created again under its
// name; nothing for a mapping, whose UUID is never reused.
type tagged struct {
	update func(gas.Context, func(map[string]string) (map[string]string, error)) error
	stored func(gas.Context) (map[string]string, keys, error)
	lock   func() func()
	arn    string
}

// authorize authorizes op on the resource, with the request's own keys k
// beside the resource's, and the tags set sets, if any. A key of set that
// differs only in case from another, or from a stored key, is refused as a
// duplicate: the policy library matches condition keys without regard to
// case.
func (t *tagged) authorize(
	ctx gas.Context,
	m *Module,
	op string,
	set map[string]string,
	k keys,
) error {
	return m.authorize(ctx, func() ([]authz.Request, error) {
		tags, extra, err := t.stored(ctx)
		if err != nil {
			return nil, err
		}
		own, err := resourceTags(tags)
		if err != nil {
			return nil, err
		}
		if key, ok := caseCollision(tags, set); ok {
			return nil, &lambdaapi.DuplicateTagError{Key: key}
		}
		setting, err := requestTags(set)
		if err != nil {
			return nil, err
		}
		return []authz.Request{request(op, t.arn, merge(own, extra, k, setting))}, nil
	})
}

// maxTaggableResource is the longest Resource of the tagging operations.
const maxTaggableResource = 256

// isMappingARN reports whether arn names an event source mapping, of any
// partition, account or region.
func isMappingARN(arn string) bool {
	parts := strings.SplitN(arn, ":", 7)
	return len(parts) == 7 && parts[0] == "arn" && parts[2] == "lambda" &&
		parts[5] == "event-source-mapping"
}

// resource resolves the Resource path label to the function or mapping it
// names, which is evaluated on its ARN rebuilt from the service's own
// partition, region and account, never on the client's string. An ARN of
// another partition, account or region names nothing here.
func (m *Module) resource(ctx gas.Context) (*tagged, error) {
	arn, err := lambdaapi.PathParam(ctx, "Resource")
	if err != nil {
		return nil, err
	}
	// The model's TaggableResource is at most 256 characters, so no longer
	// ARN is ever evaluated.
	if len(arn) > maxTaggableResource {
		return nil, constraint("resource", "have length less than or equal to 256")
	}
	if uuid, ok := m.settings.MappingOfARN(arn); ok {
		if !mappingUUIDPattern.MatchString(uuid) {
			return nil, constraint("resource", "satisfy regular expression pattern: "+
				"arn:(aws[a-zA-Z-]*):lambda:...:event-source-mapping:<UUID>")
		}
		return m.taggedMapping(uuid), nil
	}
	if !strings.HasPrefix(arn, "arn:") {
		return nil, lambdaapi.ErrValidation("1 validation error detected: Value '" + arn +
			"' at 'resource' failed to satisfy constraint: Member must satisfy regular " +
			"expression pattern: arn:(aws[a-zA-Z-]*):lambda:...")
	}
	if isMappingARN(arn) {
		// A mapping of another partition, account or region.
		return nil, lambdaapi.ErrNotFound("The resource you requested does not exist.")
	}
	name, err := m.resolveName(arn)
	if err != nil {
		return nil, err
	}
	return m.taggedFunction(name), nil
}

// taggedMapping is the mapping uuid as a tagged resource.
func (m *Module) taggedMapping(uuid string) *tagged {
	return &tagged{arn: m.settings.MappingARN(uuid), lock: func() func() {
		return func() {}
	}, stored: func(
		ctx gas.Context,
	) (map[string]string, keys, error) {
		return m.storedMapping(ctx, uuid)
	}, update: func(
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
	}}
}

// taggedFunction is the function name as a tagged resource. Tags apply at
// the function level, not to versions or aliases (the Lambda Developer
// Guide, "Using tags on Lambda functions"), so a qualified ARN is evaluated
// on the function it tags.
func (m *Module) taggedFunction(name string) *tagged {
	return &tagged{arn: m.settings.FunctionARN(name), lock: func() func() {
		return m.names.read(name)
	}, stored: func(
		ctx gas.Context,
	) (map[string]string, keys, error) {
		tags, err := m.storedFunctionTags(ctx, name)
		return tags, nil, err
	}, update: func(
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
	}}
}

func (m *Module) tagResource(ctx gas.Context) error {
	res, err := m.resource(ctx)
	if err != nil {
		return err
	}
	defer res.lock()()
	req, err := lambdaapi.Decode[lambdaapi.TagResourceRequest](ctx)
	if err != nil {
		return err
	}
	if err = checkTags(req.Tags); err != nil {
		return err
	}
	if err = res.authorize(ctx, m, "TagResource", req.Tags, nil); err != nil {
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
	defer res.lock()()
	tagKeys := ctx.Request().URL.Query()["tagKeys"]
	if err = checkTagKeys(tagKeys); err != nil {
		return err
	}
	var k keys
	if len(tagKeys) > 0 {
		k = keys{keyTagKeys: tagKeys}
	}
	if err = res.authorize(ctx, m, "UntagResource", nil, k); err != nil {
		return err
	}
	if err = res.update(ctx, func(tags map[string]string) (map[string]string, error) {
		out := map[string]string{}
		maps.Copy(out, tags)
		for _, key := range tagKeys {
			delete(out, key)
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
	defer res.lock()()
	if err = res.authorize(ctx, m, "ListTags", nil, nil); err != nil {
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
