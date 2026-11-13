package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/lambdaapi"
	"tule.dev/functions/internal/poller"
	"tule.dev/functions/internal/runner"
)

// defaultWorkers is how many batches a mapping without a ScalingConfig
// receives and invokes at once: the five Lambda starts an SQS mapping with.
const defaultWorkers = 5

// QueueARN is an SQS queue ARN's parts.
type QueueARN struct {
	Region  string
	Account string
	Name    string
}

// ParseQueueARN splits an SQS queue ARN, arn:aws:sqs:region:account:name.
func ParseQueueARN(arn string) (QueueARN, bool) {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || !strings.HasPrefix(parts[1], "aws") ||
		parts[2] != "sqs" || parts[3] == "" || parts[4] == "" || parts[5] == "" {
		return QueueARN{}, false
	}
	return QueueARN{Region: parts[3], Account: parts[4], Name: parts[5]}, true
}

// CreateMapping stores m as Creating and starts it in the background:
// Enabled with its poller running, or Disabled.
func (e *Engine) CreateMapping(ctx context.Context, m *contracts.Mapping) error {
	m.ARN = e.settings.MappingARN(m.UUID)
	m.State = contracts.MappingCreating
	m.StateTransitionReason = "USER_INITIATED"
	m.LastProcessingResult = "No records processed"
	m.LastModified = time.Now().UTC()
	if err := e.store.PutMapping(ctx, m); err != nil {
		return err
	}
	e.settle(m.UUID)
	return nil
}

// errMappingNotFound is Lambda's ResourceNotFoundException for a mapping.
func errMappingNotFound() error {
	return lambdaapi.ErrNotFound("The resource you requested does not exist.")
}

// UpdateMapping applies change to the mapping, reported Updating, and
// restarts its poller in the background with the new settings.
func (e *Engine) UpdateMapping(
	ctx context.Context,
	uuid string,
	change func(*contracts.Mapping) error,
) (*contracts.Mapping, error) {
	unlock := e.lockMapping(uuid)
	defer unlock()
	m, err := e.store.UpdateMapping(ctx, uuid, func(m *contracts.Mapping) error {
		if m.State == contracts.MappingCreating || m.State == contracts.MappingUpdating ||
			m.State == contracts.MappingDeleting {
			return lambdaapi.NewError(http.StatusBadRequest, lambdaapi.CodeResourceInUse,
				"Cannot update the event source mapping because it is in use.")
		}
		if cErr := change(m); cErr != nil {
			return cErr
		}
		m.State = contracts.MappingUpdating
		m.StateTransitionReason = "USER_INITIATED"
		m.LastModified = time.Now().UTC()
		return nil
	})
	if errors.Is(err, contracts.ErrMappingNotFound) {
		return nil, errMappingNotFound()
	}
	if err != nil {
		return nil, err
	}
	e.stopPoller(uuid)
	e.settle(uuid)
	return m, nil
}

// DeleteMapping stops the mapping's poller and deletes it in the
// background, answering with the mapping as Deleting.
func (e *Engine) DeleteMapping(ctx context.Context, uuid string) (*contracts.Mapping, error) {
	unlock := e.lockMapping(uuid)
	defer unlock()
	m, err := e.store.UpdateMapping(ctx, uuid, func(m *contracts.Mapping) error {
		if m.State == contracts.MappingDeleting {
			return lambdaapi.NewError(http.StatusBadRequest, lambdaapi.CodeResourceInUse,
				"Cannot delete the event source mapping because it is in use.")
		}
		m.State = contracts.MappingDeleting
		m.StateTransitionReason = "USER_INITIATED"
		m.LastModified = time.Now().UTC()
		return nil
	})
	if errors.Is(err, contracts.ErrMappingNotFound) {
		return nil, errMappingNotFound()
	}
	if err != nil {
		return nil, err
	}
	e.stopPoller(uuid)
	e.goBackground(func(ctx context.Context) {
		if dErr := e.store.DeleteMapping(ctx, uuid); dErr != nil &&
			!errors.Is(dErr, contracts.ErrMappingNotFound) {
			e.logger.Error("failed to delete an event source mapping").Str("mapping", uuid).
				Err("error", dErr).Send()
		}
	})
	return m, nil
}

// settle moves a Creating or Updating mapping to Enabled, starting its
// poller, or to Disabled. The state change and the poller's start are one
// step under the mapping's lock, which an update and a delete take too, so
// neither can land between them and leave a poller running.
func (e *Engine) settle(uuid string) {
	e.goBackground(func(ctx context.Context) {
		unlock := e.lockMapping(uuid)
		defer unlock()
		m, err := e.store.UpdateMapping(ctx, uuid, func(m *contracts.Mapping) error {
			if m.State != contracts.MappingCreating && m.State != contracts.MappingUpdating {
				return errSuperseded
			}
			m.State = contracts.MappingDisabled
			if m.Enabled {
				m.State = contracts.MappingEnabled
			}
			return nil
		})
		if errors.Is(err, errSuperseded) || errors.Is(err, contracts.ErrMappingNotFound) {
			return
		}
		if err != nil {
			e.logger.Error("failed to start an event source mapping").Str("mapping", uuid).
				Err("error", err).Send()
			return
		}
		if m.State == contracts.MappingEnabled {
			e.startPoller(ctx, m)
		}
	})
}

// resumeMappings starts the enabled mappings' pollers, and settles those an
// interrupted run left changing.
func (e *Engine) resumeMappings(ctx context.Context) error {
	all, err := e.store.AllMappings(ctx)
	if err != nil {
		return err
	}
	for i := range all {
		m := &all[i]
		switch m.State {
		case contracts.MappingEnabled:
			// The pollers outlive the start, so they run on the engine's own
			// context rather than the start's.
			e.startPoller(e.ctx, m) //nolint:contextcheck // as above
		case contracts.MappingCreating, contracts.MappingUpdating:
			e.settle(m.UUID)
		case contracts.MappingDeleting:
			if dErr := e.store.DeleteMapping(ctx, m.UUID); dErr != nil {
				return dErr
			}
		}
	}
	return nil
}

// sqsClient returns a client for the queues service in region for the
// mappings of the function name: signed with its execution role's session
// in role mode, as Lambda polls a queue with the function's execution role,
// else with the configured key.
func (e *Engine) sqsClient(region, function string) *sqs.Client {
	var creds aws.CredentialsProvider = credentials.NewStaticCredentialsProvider(
		e.accessKeyID, e.secretAccessKey, "")
	if e.settings.FunctionCredentials == contracts.CredentialsRole {
		creds = &roleProvider{e: e, name: function}
	}
	return sqs.New(sqs.Options{
		Region:       region,
		BaseEndpoint: aws.String(e.settings.QueuesEndpoint),
		Credentials:  creds,
	})
}

// startPoller runs the mapping's poller until stopPoller, or until ctx,
// which the engine's own context bounds, ends.
func (e *Engine) startPoller(ctx context.Context, m *contracts.Mapping) {
	q, ok := ParseQueueARN(m.EventSourceARN)
	if !ok || e.settings.QueuesEndpoint == "" {
		e.logger.Error("an event source mapping cannot poll").Str("mapping", m.UUID).Send()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	if old, running := e.pollers[m.UUID]; running {
		old()
	}
	e.pollers[m.UUID] = cancel
	e.mu.Unlock()

	workers := defaultWorkers
	if m.MaximumConcurrency > 0 {
		workers = m.MaximumConcurrency
	}
	uuid, function := m.UUID, m.FunctionName
	cfg := &poller.Config{
		Client:  e.sqsClient(q.Region, m.FunctionName),
		Logger:  e.logger,
		Mapping: *m,
		Region:  q.Region,
		Account: q.Account,
		Queue:   q.Name,
		Workers: workers,
		Invoke: func(ctx context.Context, payload []byte) (*poller.Outcome, error) {
			return e.invokeForMapping(ctx, function, payload)
		},
		Report: func(result string) { e.reportProcessing(uuid, result) },
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		poller.Run(ctx, cfg)
	}()
}

func (e *Engine) stopPoller(uuid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if cancel, ok := e.pollers[uuid]; ok {
		cancel()
		delete(e.pollers, uuid)
	}
}

// invokeForMapping runs a mapping's batch synchronously, waiting for a
// container, and records it.
func (e *Engine) invokeForMapping(
	ctx context.Context,
	function string,
	payload []byte,
) (*poller.Outcome, error) {
	fn, err := e.Invocable(ctx, function)
	if err != nil {
		return nil, err
	}
	res, err := e.runner.Invoke(ctx, specOf(fn), &runner.Request{
		RequestID: ids.UUID(), Payload: payload, Wait: true,
	})
	if err != nil {
		return nil, err
	}
	e.record(ctx, function, contracts.SourceMapping, payload, res, 1)
	return &poller.Outcome{
		Response:  res.Payload,
		Succeeded: res.Status == runner.StatusSucceeded,
	}, nil
}

// reportProcessing records the mapping's last processing result, when it
// changed.
func (e *Engine) reportProcessing(uuid, result string) {
	_, err := e.store.UpdateMapping(e.ctx, uuid, func(m *contracts.Mapping) error {
		if m.LastProcessingResult == result {
			return errSuperseded
		}
		m.LastProcessingResult = result
		return nil
	})
	if err != nil && !errors.Is(err, errSuperseded) &&
		!errors.Is(err, contracts.ErrMappingNotFound) && e.ctx.Err() == nil {
		e.logger.Warn("failed to record a mapping's processing result").Str("mapping", uuid).
			Err("error", err).Send()
	}
}

// CheckVisibilityTimeout fails with InvalidParameterValueException when the
// function's timeout exceeds the queue's visibility timeout, which the
// developer guide says Lambda checks when a mapping is created or updated.
// The queue is asked through the SQS API; a queue it cannot read fails the
// same way.
func (e *Engine) CheckVisibilityTimeout(
	ctx context.Context,
	queueARN string,
	fn *contracts.Function,
) error {
	q, ok := ParseQueueARN(queueARN)
	if !ok {
		return lambdaapi.ErrInvalidParameter("The event source ARN is not an SQS queue ARN.")
	}
	client := e.sqsClient(q.Region, fn.Name)
	url, err := client.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
		QueueName: aws.String(q.Name), QueueOwnerAWSAccountId: aws.String(q.Account),
	})
	if err != nil {
		return lambdaapi.ErrInvalidParameter("Lambda could not read the queue " + queueARN +
			": " + err.Error())
	}
	attrs, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       url.QueueUrl,
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameVisibilityTimeout},
	})
	if err != nil {
		return lambdaapi.ErrInvalidParameter("Lambda could not read the queue " + queueARN +
			": " + err.Error())
	}
	visibility, err := strconv.Atoi(
		attrs.Attributes[string(sqstypes.QueueAttributeNameVisibilityTimeout)],
	)
	if err != nil {
		return fmt.Errorf("engine: the queue %s reports no VisibilityTimeout: %w", queueARN, err)
	}
	if fn.Timeout > visibility {
		return lambdaapi.ErrInvalidParameter(fmt.Sprintf("Queue visibility timeout: %d seconds "+
			"is less than Function timeout: %d seconds", visibility, fn.Timeout))
	}
	return nil
}

// lockMapping takes the mapping's lock, and returns its release.
func (e *Engine) lockMapping(uuid string) func() {
	e.mu.Lock()
	l, ok := e.mappingLocks[uuid]
	if !ok {
		l = &sync.Mutex{}
		e.mappingLocks[uuid] = l
	}
	e.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// Polling reports whether the mapping's poller runs.
func (e *Engine) Polling(uuid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.pollers[uuid]
	return ok
}
