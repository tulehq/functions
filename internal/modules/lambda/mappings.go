package lambda

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/gasmod/gas"

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
	fn, err := m.functionNamed(ctx, *req.FunctionName)
	if err != nil {
		return err
	}
	if err = m.checkUnmapped(ctx, arn, fn); err != nil {
		return err
	}
	if err = checkTags(req.Tags); err != nil {
		return err
	}
	mp := &contracts.Mapping{
		UUID:           ids.UUID(),
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

// functionNamed returns the function a FunctionName member names.
func (m *Module) functionNamed(ctx gas.Context, value string) (*contracts.Function, error) {
	name, err := m.resolveName(value)
	if err != nil {
		return nil, err
	}
	return m.getOrNotFound(ctx, name)
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
	uuid, err := lambdaapi.PathParam(ctx, "UUID")
	if err != nil {
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
	uuid, err := lambdaapi.PathParam(ctx, "UUID")
	if err != nil {
		return err
	}
	req, err := lambdaapi.Decode[lambdaapi.UpdateEventSourceMappingRequest](ctx)
	if err != nil {
		return err
	}
	var fn *contracts.Function
	if req.FunctionName != nil {
		if fn, err = m.functionNamed(ctx, *req.FunctionName); err != nil {
			return err
		}
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

func (m *Module) deleteMapping(ctx gas.Context) error {
	uuid, err := lambdaapi.PathParam(ctx, "UUID")
	if err != nil {
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
