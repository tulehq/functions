package poller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/gasmod/gas"

	"tule.dev/functions/internal/contracts"
)

// SQS is the part of the SQS client a poller calls.
type SQS interface {
	GetQueueUrl(
		ctx context.Context, in *sqs.GetQueueUrlInput, optFns ...func(*sqs.Options),
	) (*sqs.GetQueueUrlOutput, error)
	ReceiveMessage(
		ctx context.Context, in *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options),
	) (*sqs.ReceiveMessageOutput, error)
	DeleteMessageBatch(
		ctx context.Context, in *sqs.DeleteMessageBatchInput, optFns ...func(*sqs.Options),
	) (*sqs.DeleteMessageBatchOutput, error)
}

// Outcome is how an invocation of a batch ended: Succeeded, and the
// function's response.
type Outcome struct {
	Response  []byte
	Succeeded bool
}

// Invoke invokes the mapping's function synchronously with an event,
// waiting for a container when the function is at its cap.
type Invoke func(ctx context.Context, payload []byte) (*Outcome, error)

// The results a mapping reports in LastProcessingResult.
const (
	ResultOK      = "OK"
	ResultProblem = "PROBLEM: Function call failed"
)

// Config is one mapping's poller.
type Config struct {
	Client SQS
	Logger gas.Logger
	Invoke Invoke
	// Report records the mapping's last processing result.
	Report func(result string)
	// Region and Account are the queue's, from its ARN.
	Region  string
	Account string
	Queue   string
	Mapping contracts.Mapping
	// Workers is how many batches are received and invoked at once.
	Workers int
}

// maxWait is SQS's longest long poll.
const maxWait = 20

// retryDelay is how long a worker waits after a failed call to the queue.
const retryDelay = time.Second

// Run polls the queue until ctx ends. A batch received is invoked, and its
// messages deleted, even when ctx ends meanwhile.
func Run(ctx context.Context, cfg *Config) {
	url := ""
	for url == "" {
		out, err := cfg.Client.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
			QueueName:              aws.String(cfg.Queue),
			QueueOwnerAWSAccountId: aws.String(cfg.Account),
		})
		if err == nil {
			url = aws.ToString(out.QueueUrl)
			break
		}
		cfg.Logger.Warn("event source mapping cannot find its queue").
			Str("mapping", cfg.Mapping.UUID).Err("error", err).Send()
		if !sleep(ctx, retryDelay) {
			return
		}
	}
	done := make(chan struct{})
	for range cfg.Workers {
		go func() {
			defer func() { done <- struct{}{} }()
			w := &worker{cfg: cfg, url: url}
			w.run(ctx)
		}()
	}
	for range cfg.Workers {
		<-done
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

type worker struct {
	cfg *Config
	url string
}

func (w *worker) run(ctx context.Context) {
	for ctx.Err() == nil {
		batch, err := w.receive(ctx)
		if len(batch) > 0 {
			for _, part := range Split(batch, w.cfg.Mapping.EventSourceARN, w.cfg.Region,
				MaxEventSize) {
				w.process(context.WithoutCancel(ctx), part)
			}
		}
		if err != nil && ctx.Err() == nil {
			w.cfg.Logger.Warn("event source mapping failed to receive").
				Str("mapping", w.cfg.Mapping.UUID).Err("error", err).Send()
			sleep(ctx, retryDelay)
		}
	}
}

// receive returns the next batch: up to BatchSize messages, gathered for
// up to the batching window after the first arrives. With no window, and
// from a FIFO queue, one receive's messages are the batch.
func (w *worker) receive(ctx context.Context) ([]types.Message, error) {
	m := &w.cfg.Mapping
	// The batching window applies to standard queues only, as the
	// developer guide says.
	window := m.BatchingWindow
	if strings.HasSuffix(w.cfg.Queue, ".fifo") {
		window = 0
	}
	var batch []types.Message
	var deadline time.Time
	for len(batch) < m.BatchSize {
		wait := int32(maxWait)
		if len(batch) > 0 {
			left := time.Until(deadline)
			if left <= 0 {
				break
			}
			secs := min(maxWait, int64((left+time.Second-1)/time.Second))
			wait = int32(secs) //nolint:gosec // at most maxWait
		}
		count := int32(min(10, m.BatchSize-len(batch))) //nolint:gosec // at most 10
		out, err := w.cfg.Client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:                    aws.String(w.url),
			MaxNumberOfMessages:         count,
			WaitTimeSeconds:             wait,
			MessageSystemAttributeNames: []types.MessageSystemAttributeName{"All"},
			MessageAttributeNames:       []string{"All"},
		})
		if err != nil {
			return batch, fmt.Errorf("receive from %s: %w", w.url, err)
		}
		if len(out.Messages) == 0 && len(batch) == 0 {
			continue
		}
		if len(batch) == 0 {
			deadline = time.Now().Add(time.Duration(window) * time.Second)
		}
		batch = append(batch, out.Messages...)
		if window == 0 {
			break
		}
	}
	return batch, nil
}

// process invokes the function with batch and deletes what it processed:
// every message when it succeeded, all but the failed ones when it reports
// them, none when it failed. What is not deleted becomes visible again
// after the queue's visibility timeout, and moves to the dead-letter queue
// once the queue's redrive policy says.
func (w *worker) process(ctx context.Context, batch []types.Message) {
	payload, err := json.Marshal(BuildEvent(batch, w.cfg.Mapping.EventSourceARN, w.cfg.Region))
	if err != nil {
		w.cfg.Logger.Error("failed to encode an SQS event").Err("error", err).Send()
		return
	}
	out, err := w.cfg.Invoke(ctx, payload)
	if err != nil {
		w.cfg.Logger.Warn("event source mapping could not invoke its function").
			Str("mapping", w.cfg.Mapping.UUID).Err("error", err).Send()
		w.cfg.Report(ResultProblem)
		return
	}
	if !out.Succeeded {
		w.cfg.Report(ResultProblem)
		return
	}
	w.cfg.Report(ResultOK)
	del := toDelete(&w.cfg.Mapping, batch, out.Response)
	if err = w.delete(ctx, del); err != nil {
		w.cfg.Logger.Warn("event source mapping failed to delete messages").
			Str("mapping", w.cfg.Mapping.UUID).Err("error", err).Send()
	}
}

// MaxEventSize is the largest event a batch invokes the function with:
// Lambda's 6 MB synchronous invocation payload limit, 6291456 bytes, which
// a batch's records and the metadata Lambda adds to them must fit in.
const MaxEventSize = 6 * 1024 * 1024

// Split cuts a received batch into the batches whose events fit in limit,
// keeping the messages' order: Lambda passes a batch's records in one call
// only while they fit in the payload limit, and fewer when they do not. A
// message too large to fit alone is a batch of its own.
func Split(batch []types.Message, arn, region string, limit int) [][]types.Message {
	const envelope = len(`{"Records":[]}`)
	var parts [][]types.Message
	cur := make([]types.Message, 0, len(batch))
	size := envelope
	for i := range batch {
		rec, _ := json.Marshal(BuildEvent(batch[i:i+1], arn, region).Records[0])
		n := len(rec)
		if len(cur) > 0 {
			n++ // the comma between records
		}
		if len(cur) > 0 && size+n > limit {
			parts = append(parts, cur)
			cur, size, n = make([]types.Message, 0, len(batch)-i), envelope, len(rec)
		}
		cur = append(cur, batch[i])
		size += n
	}
	if len(cur) > 0 {
		parts = append(parts, cur)
	}
	return parts
}

// toDelete returns the messages of a batch the function processed: all of
// them, or with ReportBatchItemFailures all but those its response names,
// and none when that response is not valid.
func toDelete(m *contracts.Mapping, batch []types.Message, response []byte) []types.Message {
	keep := map[string]bool{}
	if reportsFailures(m) {
		ids := make(map[string]bool, len(batch))
		for _, msg := range batch {
			ids[aws.ToString(msg.MessageId)] = true
		}
		failed, ok := Failed(response, ids)
		if !ok {
			return nil
		}
		for _, id := range failed {
			keep[id] = true
		}
	}
	del := make([]types.Message, 0, len(batch))
	for _, msg := range batch {
		if !keep[aws.ToString(msg.MessageId)] {
			del = append(del, msg)
		}
	}
	return del
}

func reportsFailures(m *contracts.Mapping) bool {
	for _, t := range m.FunctionResponseTypes {
		if t == contracts.ReportBatchItemFailures {
			return true
		}
	}
	return false
}

// delete deletes msgs, ten to a batch.
func (w *worker) delete(ctx context.Context, msgs []types.Message) error {
	var errs []error
	for start := 0; start < len(msgs); start += 10 {
		chunk := msgs[start:min(start+10, len(msgs))]
		entries := make([]types.DeleteMessageBatchRequestEntry, 0, len(chunk))
		for i, m := range chunk {
			entries = append(entries, types.DeleteMessageBatchRequestEntry{
				Id: aws.String(strconv.Itoa(i)), ReceiptHandle: m.ReceiptHandle,
			})
		}
		out, err := w.cfg.Client.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{
			QueueUrl: aws.String(w.url), Entries: entries,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("delete from %s: %w", w.url, err))
			continue
		}
		for _, f := range out.Failed {
			errs = append(errs, fmt.Errorf("delete from %s: %s %s", w.url,
				aws.ToString(f.Code), aws.ToString(f.Message)))
		}
	}
	return errors.Join(errs...)
}
