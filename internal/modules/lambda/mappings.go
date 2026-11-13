package lambda

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/functions/internal/authz"
	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/engine"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/lambdaapi"
)

// The limits of an SQS mapping, from the SDK model and the developer
// guide's SQS parameters.
const (
	defaultBatchSize = 10
	maxBatchSize     = 10000
	maxFIFOBatchSize = 10
	maxBatchWindow   = 300
)

func mappingOf(mp *contracts.Mapping) lambdaapi.EventSourceMappingConfiguration {
	c := lambdaapi.EventSourceMappingConfiguration{
		UUID:                           mp.UUID,
		EventSourceArn:                 mp.EventSourceARN,
		FunctionArn:                    mp.FunctionARN,
		LastProcessingResult:           mp.LastProcessingResult,
		State:                          mp.State,
		StateTransitionReason:          mp.StateTransitionReason,
		EventSourceMappingArn:          mp.ARN,
		FunctionResponseTypes:          mp.FunctionResponseTypes,
		LastModified:                   lambdaapi.EpochSeconds(mp.LastModified),
		BatchSize:                      mp.BatchSize,
		MaximumBatchingWindowInSeconds: mp.BatchingWindow,
	}
	if c.FunctionResponseTypes == nil {
		c.FunctionResponseTypes = []string{}
	}
	if mp.MaximumConcurrency > 0 {
		n := mp.MaximumConcurrency
		c.ScalingConfig = &lambdaapi.ScalingConfig{MaximumConcurrency: &n}
	}
	return c
}

// mappingSettings are the members CreateEventSourceMapping and
// UpdateEventSourceMapping share.
type mappingSettings struct {
	scaling       *lambdaapi.ScalingConfig
	enabled       *bool
	batchSize     *int
	window        *int
	responseTypes []string
}

// apply checks s and applies it to mp, whose queue decides the batch size
// limit.
func (s *mappingSettings) apply(mp *contracts.Mapping) error {
	if s.enabled != nil {
		mp.Enabled = *s.enabled
	}
	if s.batchSize != nil {
		mp.BatchSize = *s.batchSize
	}
	if s.window != nil {
		if *s.window < 0 || *s.window > maxBatchWindow {
			return constraint("maximumBatchingWindowInSeconds", "have value between 0 and 300")
		}
		mp.BatchingWindow = *s.window
	}
	if err := s.applyResponseTypes(mp); err != nil {
		return err
	}
	if err := s.applyScaling(mp); err != nil {
		return err
	}
	return checkBatch(mp)
}

func (s *mappingSettings) applyResponseTypes(mp *contracts.Mapping) error {
	if s.responseTypes == nil {
		return nil
	}
	if len(s.responseTypes) > 1 ||
		(len(s.responseTypes) == 1 && s.responseTypes[0] != contracts.ReportBatchItemFailures) {
		return constraint("functionResponseTypes",
			"satisfy enum value set: [ReportBatchItemFailures]")
	}
	mp.FunctionResponseTypes = s.responseTypes
	return nil
}

func (s *mappingSettings) applyScaling(mp *contracts.Mapping) error {
	if s.scaling == nil {
		return nil
	}
	mp.MaximumConcurrency = 0
	if n := s.scaling.MaximumConcurrency; n != nil {
		if *n < 2 || *n > 1000 {
			return constraint("scalingConfig.maximumConcurrency", "have value between 2 and 1000")
		}
		mp.MaximumConcurrency = *n
	}
	return nil
}

// checkBatch holds the batch size to its queue's limit, 10 for a FIFO
// queue and 10000 for a standard one, and to the batching window it needs:
// over 10 messages, one of at least a second.
func checkBatch(mp *contracts.Mapping) error {
	limit := maxBatchSize
	if strings.HasSuffix(mp.EventSourceARN, ".fifo") {
		limit = maxFIFOBatchSize
	}
	if mp.BatchSize < 1 || mp.BatchSize > limit {
		return lambdaapi.ErrInvalidParameter(fmt.Sprintf(
			"BatchSize must be between 1 and %d for this queue.", limit))
	}
	if mp.BatchSize > defaultBatchSize && mp.BatchingWindow == 0 {
		return lambdaapi.ErrInvalidParameter("Maximum batch window in seconds must be " +
			"greater than 0 if maximum batch size is greater than 10")
	}
	return nil
}

func (m *Module) createMapping(ctx gas.Context) error {
	req, err := lambdaapi.Decode[lambdaapi.CreateEventSourceMappingRequest](ctx)
	if err != nil {
		return err
	}
	if err = m.checkCreate(&req); err != nil {
		return err
	}
	arn := *req.EventSourceArn
	if err = checkTags(req.Tags); err != nil {
		return err
	}
	uuid := ids.UUID()
	fn, err := m.authorizeCreate(ctx, &req, uuid)
	if err != nil {
		return err
	}
	if err = m.checkUnmapped(ctx, arn, fn); err != nil {
		return err
	}
	mp := &contracts.Mapping{
		UUID:           uuid,
		EventSourceARN: arn,
		FunctionName:   fn.Name,
		FunctionARN:    fn.ARN,
		BatchSize:      defaultBatchSize,
		Enabled:        true,
		Tags:           map[string]string{},
	}
	maps.Copy(mp.Tags, req.Tags)
	s := mappingSettings{
		scaling: req.ScalingConfig, enabled: req.Enabled, batchSize: req.BatchSize,
		window: req.MaximumBatchingWindowInSeconds, responseTypes: req.FunctionResponseTypes,
	}
	if err = s.apply(mp); err != nil {
		return err
	}
	if err = m.engine.CheckVisibilityTimeout(ctx, arn, fn); err != nil {
		return err
	}
	if err = m.engine.CreateMapping(ctx, mp); err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusAccepted, mappingOf(mp))
}

// authorizeCreate authorizes the CreateEventSourceMapping req, as the
// mapping uuid, and returns the function it maps.
func (m *Module) authorizeCreate(
	ctx gas.Context,
	req *lambdaapi.CreateEventSourceMappingRequest,
	uuid string,
) (*contracts.Function, error) {
	name, err := m.resolveName(*req.FunctionName)
	if err != nil {
		return nil, err
	}
	if err = m.authorize(ctx, m.createMappingRequests(name, uuid, req.Tags)); err != nil {
		return nil, err
	}
	return m.getOrNotFound(ctx, name)
}

// createMappingRequests are what CreateEventSourceMapping of the function
// name, as the mapping uuid, needs allowed: lambda:CreateEventSourceMapping,
// which acts on no resource type, with lambda:FunctionArn, and
// lambda:TagResource on the new mapping when it is created with tags.
func (m *Module) createMappingRequests(
	name, uuid string,
	tags map[string]string,
) func() ([]authz.Request, error) {
	return func() ([]authz.Request, error) {
		set, err := requestTags(tags)
		if err != nil {
			return nil, err
		}
		k := merge(set, keys{keyFunctionARN: {m.settings.FunctionARN(name)}})
		reqs := []authz.Request{request("CreateEventSourceMapping", "*", k)}
		if len(tags) > 0 {
			reqs = append(reqs, authz.Request{
				Action:   actionTagResource,
				Resource: m.settings.MappingARN(uuid),
				Context:  set,
			})
		}
		return reqs, nil
	}
}

// mappingUUIDPattern is the form of a mapping's UUID, as Lambda's ARNs of
// mappings have it (the TaggableResource pattern of the SDK model).
var mappingUUIDPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// pathMapping reads the UUID path label. One that is not a UUID names no
// mapping, and is answered as not found before anything is evaluated, so
// no request evaluates a resource name longer than a mapping's.
func pathMapping(ctx gas.Context) (string, error) {
	uuid, err := lambdaapi.PathParam(ctx, "UUID")
	if err != nil {
		return "", err
	}
	if !mappingUUIDPattern.MatchString(uuid) {
		return "", lambdaapi.ErrNotFound("The resource you requested does not exist.")
	}
	return uuid, nil
}

// authorizeMapping authorizes op on the mapping uuid. functions are further
// functions the request points the mapping at, each of which must be
// allowed as its lambda:FunctionArn too.
func (m *Module) authorizeMapping(ctx gas.Context, op, uuid string, functions ...string) error {
	return m.authorize(ctx, func() ([]authz.Request, error) {
		k, err := m.mappingKeys(ctx, uuid)
		if err != nil {
			return nil, err
		}
		arn := m.settings.MappingARN(uuid)
		reqs := []authz.Request{request(op, arn, k)}
		for _, fn := range functions {
			reqs = append(reqs, request(op, arn,
				merge(k, keys{keyFunctionARN: {m.settings.FunctionARN(fn)}})))
		}
		return reqs, nil
	})
}

// checkCreate checks what CreateEventSourceMapping needs before it looks at
// the function: an SQS queue ARN, a queues service to poll it at, no
// StartingPosition, which SQS mappings do not take, and a FunctionName.
func (m *Module) checkCreate(req *lambdaapi.CreateEventSourceMappingRequest) error {
	if _, ok := engine.ParseQueueARN(deref(req.EventSourceArn)); !ok {
		return lambdaapi.ErrInvalidParameter("Unrecognized event source, must be an SQS " +
			"queue ARN: this service maps SQS queues only.")
	}
	if m.settings.QueuesEndpoint == "" {
		return lambdaapi.ErrInvalidParameter("Event source mappings need a queues " +
			"service: set TULE_Functions_QueuesEndpoint.")
	}
	if req.StartingPosition != nil {
		return lambdaapi.ErrInvalidParameter("StartingPosition is not valid for SQS event sources.")
	}
	if req.FunctionName == nil {
		return lambdaapi.ErrValidation("1 validation error detected: Value null at " +
			"'functionName' failed to satisfy constraint: Member must not be null")
	}
	return nil
}

// checkUnmapped refuses a second mapping of the queue to the function.
func (m *Module) checkUnmapped(ctx gas.Context, arn string, fn *contracts.Function) error {
	existing, err := m.store.ListMappings(ctx,
		contracts.MappingFilter{FunctionName: fn.Name, EventSourceARN: arn},
		contracts.PageInput{Size: 1})
	if err != nil {
		return err
	}
	if len(existing.Items) > 0 {
		return lambdaapi.ErrConflict(fmt.Sprintf("An event source mapping with SQS arn "+
			"(\" %s \") and function (\" %s \") already exists. Please update or delete the "+
			"existing mapping with UUID %s", arn, fn.Name, existing.Items[0].UUID))
	}
	return nil
}

func (m *Module) getMapping(ctx gas.Context) error {
	uuid, err := pathMapping(ctx)
	if err != nil {
		return err
	}
	if err = m.authorizeMapping(ctx, "GetEventSourceMapping", uuid); err != nil {
		return err
	}
	mp, err := m.store.GetMapping(ctx, uuid)
	if errors.Is(err, contracts.ErrMappingNotFound) {
		return lambdaapi.ErrNotFound("The resource you requested does not exist.")
	}
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusOK, mappingOf(mp))
}

func (m *Module) listMappings(ctx gas.Context) error {
	page, err := pageOf(ctx, 100)
	if err != nil {
		return err
	}
	f := contracts.MappingFilter{EventSourceARN: ctx.Query("EventSourceArn")}
	if v := ctx.Query("FunctionName"); v != "" {
		if f.FunctionName, err = m.resolveName(v); err != nil {
			return err
		}
	}
	if err = m.authorize(ctx, one("ListEventSourceMappings", "*", nil)); err != nil {
		return err
	}
	out, err := m.store.ListMappings(ctx, f, page)
	if err != nil {
		return err
	}
	resp := lambdaapi.ListEventSourceMappingsResponse{
		NextMarker:          out.NextToken,
		EventSourceMappings: make([]lambdaapi.EventSourceMappingConfiguration, 0, len(out.Items)),
	}
	for i := range out.Items {
		resp.EventSourceMappings = append(resp.EventSourceMappings, mappingOf(&out.Items[i]))
	}
	return lambdaapi.Write(ctx, http.StatusOK, resp)
}

func (m *Module) updateMapping(ctx gas.Context) error {
	uuid, err := pathMapping(ctx)
	if err != nil {
		return err
	}
	req, err := lambdaapi.Decode[lambdaapi.UpdateEventSourceMappingRequest](ctx)
	if err != nil {
		return err
	}
	fn, err := m.authorizeUpdate(ctx, uuid, req.FunctionName)
	if err != nil {
		return err
	}
	s := mappingSettings{
		scaling: req.ScalingConfig, enabled: req.Enabled, batchSize: req.BatchSize,
		window: req.MaximumBatchingWindowInSeconds, responseTypes: req.FunctionResponseTypes,
	}
	if err = m.checkUpdatedVisibility(ctx, uuid, fn); err != nil {
		return err
	}
	mp, err := m.engine.UpdateMapping(ctx, uuid, func(mp *contracts.Mapping) error {
		if fn != nil {
			mp.FunctionName, mp.FunctionARN = fn.Name, fn.ARN
		}
		return s.apply(mp)
	})
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusAccepted, mappingOf(mp))
}

// authorizeUpdate authorizes the UpdateEventSourceMapping of the mapping
// uuid, and returns the function the update points it at, if it names one
// in functionName.
func (m *Module) authorizeUpdate(
	ctx gas.Context,
	uuid string,
	functionName *string,
) (*contracts.Function, error) {
	if functionName == nil {
		return nil, m.authorizeMapping(ctx, "UpdateEventSourceMapping", uuid)
	}
	name, err := m.resolveName(*functionName)
	if err != nil {
		return nil, err
	}
	if err = m.authorizeMapping(ctx, "UpdateEventSourceMapping", uuid, name); err != nil {
		return nil, err
	}
	return m.getOrNotFound(ctx, name)
}

func (m *Module) deleteMapping(ctx gas.Context) error {
	uuid, err := pathMapping(ctx)
	if err != nil {
		return err
	}
	if err = m.authorizeMapping(ctx, "DeleteEventSourceMapping", uuid); err != nil {
		return err
	}
	mp, err := m.engine.DeleteMapping(ctx, uuid)
	if err != nil {
		return err
	}
	return lambdaapi.Write(ctx, http.StatusAccepted, mappingOf(mp))
}

// checkUpdatedVisibility checks the queue's visibility timeout against the
// timeout of the function the updated mapping will invoke: fn when the
// update names one, else the mapping's own.
func (m *Module) checkUpdatedVisibility(
	ctx gas.Context,
	uuid string,
	fn *contracts.Function,
) error {
	mp, err := m.store.GetMapping(ctx, uuid)
	if errors.Is(err, contracts.ErrMappingNotFound) {
		return lambdaapi.ErrNotFound("The resource you requested does not exist.")
	}
	if err != nil {
		return err
	}
	if fn == nil {
		if fn, err = m.getOrNotFound(ctx, mp.FunctionName); err != nil {
			return err
		}
	}
	return m.engine.CheckVisibilityTimeout(ctx, mp.EventSourceARN, fn)
}
