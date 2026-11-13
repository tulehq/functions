package lambda

import (
	"errors"
	"maps"
	"net/http"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/lambdaapi"
)

// The defaults Lambda gives a function.
const (
	defaultTimeout    = 3
	defaultMemorySize = 128
	defaultArch       = "x86_64"
)

// configOf is the function's configuration as Lambda reports it.
func configOf(fn *contracts.Function) lambdaapi.FunctionConfiguration {
	c := lambdaapi.FunctionConfiguration{
		FunctionName:               fn.Name,
		FunctionArn:                fn.ARN,
		Role:                       fn.Role,
		Description:                fn.Description,
		LastModified:               fn.LastModified.UTC().Format(lambdaapi.LastModifiedFormat),
		CodeSha256:                 fn.Image.CodeSha256,
		Version:                    contracts.LatestVersion,
		RevisionID:                 fn.RevisionID,
		State:                      fn.State,
		StateReason:                fn.StateReason,
		StateReasonCode:            fn.StateReasonCode,
		LastUpdateStatus:           fn.LastUpdateStatus,
		LastUpdateStatusReason:     fn.LastUpdateStatusReason,
		LastUpdateStatusReasonCode: fn.LastUpdateStatusReasonCode,
		PackageType:                "Image",
		Architectures:              fn.Architectures,
		Timeout:                    fn.Timeout,
		MemorySize:                 fn.MemorySize,
	}
	if len(fn.Environment) > 0 {
		c.Environment = &lambdaapi.EnvironmentResponse{Variables: fn.Environment}
	}
	if fn.ImageConfig.Set {
		ic := lambdaapi.ImageConfig{
			EntryPoint: fn.ImageConfig.EntryPoint,
			Command:    fn.ImageConfig.Command,
		}
		if fn.ImageConfig.WorkingDirectory != "" {
			ic.WorkingDirectory = &fn.ImageConfig.WorkingDirectory
		}
		c.ImageConfigResponse = &lambdaapi.ImageConfigResponse{ImageConfig: ic}
	}
	return c
}

func (m *Module) createFunction(ctx gas.Context) error {
	req, err := lambdaapi.Decode[lambdaapi.CreateFunctionRequest](ctx)
	if err != nil {
		return err
	}
	fn, err := m.newFunction(&req)
	if err != nil {
		return err
	}
	defer m.names.write(fn.Name)()
	if err = m.authorize(ctx, createRequests(m.settings.FunctionARN(fn.Name), fn)); err != nil {
		return err
	}
	if err = m.engine.CheckRole(
		ctx,
		fn.Role,
		fn.Name,
		m.settings.FunctionARN(fn.Name),
	); err != nil {
		return err
	}
	if err = m.engine.CreateFunction(ctx, fn); err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusCreated, configOf(fn))
}

// createRequests are what CreateFunction of fn at arn needs allowed:
// lambda:CreateFunction, iam:PassRole on its role, and lambda:TagResource
// when it is created with tags.
func createRequests(arn string, fn *contracts.Function) func() ([]authz.Request, error) {
	return func() ([]authz.Request, error) {
		tags, err := requestTags(fn.Tags)
		if err != nil {
			return nil, err
		}
		reqs := []authz.Request{request("CreateFunction", arn, tags), passRole(fn.Role)}
		if len(fn.Tags) > 0 {
			reqs = append(
				reqs,
				authz.Request{Action: actionTagResource, Resource: arn, Context: tags},
			)
		}
		return reqs, nil
	}
}

// newFunction checks a CreateFunction request and builds the function it
// asks for.
func (m *Module) newFunction(req *lambdaapi.CreateFunctionRequest) (*contracts.Function, error) {
	if req.FunctionName == nil {
		return nil, lambdaapi.ErrValidation("1 validation error detected: Value null at " +
			"'functionName' failed to satisfy constraint: Member must not be null")
	}
	name, err := m.resolveName(*req.FunctionName)
	if err != nil {
		return nil, err
	}
	uri, err := checkCode(req)
	if err != nil {
		return nil, err
	}
	if err = m.checkRole(req.Role, true); err != nil {
		return nil, err
	}
	fn := &contracts.Function{
		Name:          name,
		Role:          deref(req.Role),
		Description:   deref(req.Description),
		Timeout:       defaultTimeout,
		MemorySize:    defaultMemorySize,
		Architectures: []string{defaultArch},
		Image:         contracts.Image{URI: uri},
		Environment:   map[string]string{},
		Tags:          map[string]string{},
	}
	if err = applyCommon(fn, req.Description, req.Timeout, req.MemorySize,
		req.Environment, req.ImageConfig); err != nil {
		return nil, err
	}
	if req.Architectures != nil {
		if err = checkArchitectures(req.Architectures); err != nil {
			return nil, err
		}
		fn.Architectures = req.Architectures
	}
	if err = checkTags(req.Tags); err != nil {
		return nil, err
	}
	maps.Copy(fn.Tags, req.Tags)
	return fn, nil
}

// applyCommon checks and applies the members CreateFunction and
// UpdateFunctionConfiguration share.
func applyCommon(
	fn *contracts.Function,
	description *string,
	timeout, memory *int,
	env *lambdaapi.Environment,
	imageConfig *lambdaapi.ImageConfig,
) error {
	if err := applyLimits(fn, description, timeout, memory); err != nil {
		return err
	}
	if env != nil {
		if err := checkEnvironment(env.Variables); err != nil {
			return err
		}
		fn.Environment = map[string]string{}
		maps.Copy(fn.Environment, env.Variables)
	}
	if imageConfig != nil {
		ic, err := imageConfigOf(imageConfig)
		if err != nil {
			return err
		}
		fn.ImageConfig = ic
	}
	return nil
}

// applyLimits checks and applies the description, timeout and memory size,
// within the model's bounds and the developer guide's 10240 MB.
func applyLimits(fn *contracts.Function, description *string, timeout, memory *int) error {
	if description != nil {
		if len(*description) > 256 {
			return constraint("description", "have length less than or equal to 256")
		}
		fn.Description = *description
	}
	if timeout != nil {
		if *timeout < 1 || *timeout > 900 {
			return constraint("timeout", "have value between 1 and 900")
		}
		fn.Timeout = *timeout
	}
	if memory != nil {
		if *memory < 128 || *memory > 10240 {
			return constraint("memorySize", "have value between 128 and 10240")
		}
		fn.MemorySize = *memory
	}
	return nil
}

func imageConfigOf(c *lambdaapi.ImageConfig) (contracts.ImageConfig, error) {
	if len(c.EntryPoint) > 1500 {
		return contracts.ImageConfig{}, constraint("imageConfig.entryPoint",
			"have length less than or equal to 1500")
	}
	if len(c.Command) > 1500 {
		return contracts.ImageConfig{}, constraint("imageConfig.command",
			"have length less than or equal to 1500")
	}
	wd := deref(c.WorkingDirectory)
	if len(wd) > 1000 {
		return contracts.ImageConfig{}, constraint("imageConfig.workingDirectory",
			"have length less than or equal to 1000")
	}
	return contracts.ImageConfig{
		EntryPoint:       c.EntryPoint,
		Command:          c.Command,
		WorkingDirectory: wd,
		Set:              len(c.EntryPoint) > 0 || len(c.Command) > 0 || wd != "",
	}, nil
}

func (m *Module) getFunction(ctx gas.Context) error {
	name, err := m.pathQualifiedFunction(ctx)
	if err != nil {
		return err
	}
	defer m.names.read(name)()
	if err = m.authorizeQualifiedFunction(ctx, "GetFunction", name); err != nil {
		return err
	}
	fn, err := m.getOrNotFound(ctx, name)
	if err != nil {
		return err
	}
	resp := lambdaapi.GetFunctionResponse{
		Configuration: configOf(fn),
		Code: lambdaapi.FunctionCodeLocation{
			RepositoryType:   "ECR",
			ImageURI:         fn.Image.URI,
			ResolvedImageURI: fn.Image.ResolvedURI,
		},
	}
	if len(fn.Tags) > 0 {
		show, lErr := m.mayListTags(ctx, fn)
		if lErr != nil {
			return lErr
		}
		if show {
			resp.Tags = fn.Tags
		}
	}
	return lambdaapi.Write(ctx, http.StatusOK, resp)
}

func (m *Module) getFunctionConfiguration(ctx gas.Context) error {
	name, err := m.pathQualifiedFunction(ctx)
	if err != nil {
		return err
	}
	defer m.names.read(name)()
	if err = m.authorizeQualifiedFunction(ctx, "GetFunctionConfiguration", name); err != nil {
		return err
	}
	fn, err := m.getOrNotFound(ctx, name)
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusOK, configOf(fn))
}

func (m *Module) getOrNotFound(ctx gas.Context, name string) (*contracts.Function, error) {
	fn, err := m.store.GetFunction(ctx, name)
	if errors.Is(err, contracts.ErrFunctionNotFound) {
		return nil, lambdaapi.ErrNotFound("Function not found: " + m.settings.FunctionARN(name))
	}
	return fn, err
}

func (m *Module) listFunctions(ctx gas.Context) error {
	page, err := pageOf(ctx, 50)
	if err != nil {
		return err
	}
	if err = m.authorize(ctx, one("ListFunctions", "*", nil)); err != nil {
		return err
	}
	out, err := m.store.ListFunctions(ctx, page)
	if err != nil {
		return err
	}
	resp := lambdaapi.ListFunctionsResponse{
		NextMarker: out.NextToken,
		Functions:  make([]lambdaapi.FunctionConfiguration, 0, len(out.Items)),
	}
	for i := range out.Items {
		resp.Functions = append(resp.Functions, configOf(&out.Items[i]))
	}
	return lambdaapi.Write(ctx, http.StatusOK, resp)
}

func (m *Module) updateFunctionCode(ctx gas.Context) error {
	name, err := m.pathFunction(ctx)
	if err != nil {
		return err
	}
	defer m.names.read(name)()
	if err = m.authorizeFunction(ctx, "UpdateFunctionCode", name); err != nil {
		return err
	}
	req, err := lambdaapi.Decode[lambdaapi.UpdateFunctionCodeRequest](ctx)
	if err != nil {
		return err
	}
	if err = checkCodeUpdate(&req); err != nil {
		return err
	}
	if req.DryRun {
		fn, gErr := m.getOrNotFound(ctx, name)
		if gErr != nil {
			return gErr
		}
		return lambdaapi.Write(ctx, http.StatusOK, configOf(fn))
	}
	fn, err := m.engine.UpdateCode(ctx, name, *req.ImageURI, req.RevisionID)
	if err != nil {
		return err
	}
	if req.Architectures != nil {
		if fn, err = m.store.UpdateFunction(ctx, name, func(f *contracts.Function) error {
			f.Architectures = req.Architectures
			return nil
		}); err != nil {
			return err
		}
	}
	return lambdaapi.Write(ctx, http.StatusOK, configOf(fn))
}

// checkCodeUpdate holds an UpdateFunctionCode request to an image, and its
// architectures to the model's.
func checkCodeUpdate(req *lambdaapi.UpdateFunctionCodeRequest) error {
	if req.ZipFile != nil || req.S3Bucket != nil {
		return lambdaapi.ErrInvalidParameter("Please don't provide code as a zip file or " +
			"from S3 when updating a function with packageType Image.")
	}
	if deref(req.ImageURI) == "" {
		return lambdaapi.ErrInvalidParameter("Please provide ImageUri when updating a " +
			"function with packageType Image.")
	}
	if err := checkImageURI(*req.ImageURI); err != nil {
		return err
	}
	if req.Architectures != nil {
		return checkArchitectures(req.Architectures)
	}
	return nil
}

func (m *Module) updateFunctionConfiguration(ctx gas.Context) error {
	name, err := m.pathFunction(ctx)
	if err != nil {
		return err
	}
	defer m.names.read(name)()
	req, err := lambdaapi.Decode[lambdaapi.UpdateFunctionConfigurationRequest](ctx)
	if err != nil {
		return err
	}
	if req.Runtime != nil || req.Handler != nil {
		return lambdaapi.ErrInvalidParameter(errRuntimeOrHandler)
	}
	if err = m.authorizeConfiguration(ctx, name, req.Role); err != nil {
		return err
	}
	fn, err := m.engine.UpdateConfiguration(ctx, name, req.RevisionID,
		func(fn *contracts.Function) error {
			if req.Role != nil {
				fn.Role = *req.Role
			}
			return applyCommon(fn, req.Description, req.Timeout, req.MemorySize,
				req.Environment, req.ImageConfig)
		})
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusOK, configOf(fn))
}

// authorizeConfiguration checks and authorizes an UpdateFunctionConfiguration
// of the function name that sets role, if it does: iam:PassRole on the role
// besides the update, and a role Lambda can assume.
func (m *Module) authorizeConfiguration(ctx gas.Context, name string, role *string) error {
	if role == nil {
		return m.authorizeFunction(ctx, "UpdateFunctionConfiguration", name)
	}
	if err := m.checkRole(role, false); err != nil {
		return err
	}
	err := m.authorizeFunction(ctx, "UpdateFunctionConfiguration", name, passRole(*role))
	if err != nil {
		return err
	}
	return m.engine.CheckRole(ctx, *role, name, m.settings.FunctionARN(name))
}

func (m *Module) deleteFunction(ctx gas.Context) error {
	name, err := m.pathQualifiedFunction(ctx)
	if err != nil {
		return err
	}
	defer m.names.write(name)()
	if err = m.authorizeQualifiedFunction(ctx, "DeleteFunction", name); err != nil {
		return err
	}
	if err = m.engine.DeleteFunction(ctx, name); err != nil {
		return err
	}
	return lambdaapi.NoContent(ctx)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
