//go:build e2e

package e2e

import (
	"crypto/md5" //nolint:gosec // G501: SQS's body digest is MD5
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // G401: SQS's body digest is MD5
	return hex.EncodeToString(sum[:])
}

func TestMappingDeliversTheSQSEvent(t *testing.T) {
	// The event and its fields as "Example Amazon SQS message event
	// (standard queue)" shows them (Using Lambda with Amazon SQS); the
	// batch is deleted once the function succeeds ("When your function
	// successfully processes a batch, Lambda deletes its messages").
	s := startMappingStack(t)
	createFunction(t, s.lambda, "consumer", "sqs", nil)
	q := s.createQueue(t, "orders", map[string]string{"VisibilityTimeout": "30"})
	s.mapping(t, q, "consumer", nil)

	id := s.send(t, q, &sqs.SendMessageInput{
		MessageBody: aws.String("Test message."),
		MessageAttributes: map[string]sqstypes.MessageAttributeValue{
			"myAttribute": {DataType: aws.String("String"), StringValue: aws.String("myValue")},
		},
	})
	s.waitDelivered(t, "consumer", id)

	b := s.batches(t, "consumer")[0]
	requireEqual(t, b.detail.Status, "succeeded", "invocation status")
	requireEventKeys(t, b.raw)
	requireEqual(t, len(b.records), 1, "records")
	r := b.records[0]
	requireEqual(t, r.MessageID, id, "messageId")
	requireEqual(t, r.Body, "Test message.", "body")
	requireEqual(t, r.MD5OfBody, md5Hex("Test message."), "md5OfBody")
	requireEqual(t, r.EventSource, "aws:sqs", "eventSource")
	requireEqual(t, r.EventSourceARN, q.ARN, "eventSourceARN")
	requireEqual(t, r.AWSRegion, region, "awsRegion")
	if r.ReceiptHandle == "" {
		t.Fatal("no receiptHandle")
	}
	requireEqual(t, r.Attributes["ApproximateReceiveCount"], "1", "ApproximateReceiveCount")
	for _, k := range []string{"SentTimestamp", "ApproximateFirstReceiveTimestamp"} {
		if _, err := strconv.ParseInt(r.Attributes[k], 10, 64); err != nil {
			t.Fatalf("attribute %s is %q, want epoch milliseconds", k, r.Attributes[k])
		}
	}
	if r.Attributes["SenderId"] == "" {
		t.Fatal("no SenderId attribute")
	}
	requireJSONEqual(t, r.MessageAttributes["myAttribute"],
		`{"stringValue":"myValue","stringListValues":[],"binaryListValues":[],"dataType":"String"}`,
		"messageAttributes.myAttribute")

	eventually(t, deliveryTimeout, "the delivered message deleted", func() bool {
		return s.messagesIn(t, q) == 0
	})
}

// requireEventKeys fails unless the event is {"Records": [...]} and each
// record carries every field of the documented example.
func requireEventKeys(t *testing.T, raw []byte) {
	t.Helper()
	var e map[string][]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("the event is not {\"Records\": [...]}: %v: %s", err, raw)
	}
	for _, rec := range e["Records"] {
		for _, k := range []string{
			"messageId", "receiptHandle", "body", "attributes", "messageAttributes",
			"md5OfBody", "eventSource", "eventSourceARN", "awsRegion",
		} {
			if _, ok := rec[k]; !ok {
				t.Fatalf("record without %s: %s", k, raw)
			}
		}
	}
}

// oneSecond gives a function a 1s timeout, so a queue with a short
// visibility timeout can feed it: "Your function's timeout must be less
// than or equal to the queue's visibility timeout. Lambda validates this
// requirement when you create or update an event source mapping"
// (Creating and configuring an Amazon SQS event source mapping). The
// visibility timeout also covers the batching window, as the same page
// recommends.
func oneSecond(in *lambda.CreateFunctionInput) { in.Timeout = aws.Int32(1) }

// withDLQ creates a dead-letter queue and a source queue redriving to it
// after maxReceiveCount receives, with the visibility timeout vis seconds.
func (s *mappingStack) withDLQ(
	t *testing.T,
	name string,
	maxReceiveCount, vis int,
) (src, dlq queue) {
	t.Helper()
	dlq = s.createQueue(t, name+"-dlq", nil)
	policy, err := json.Marshal(map[string]string{
		"deadLetterTargetArn": dlq.ARN,
		"maxReceiveCount":     strconv.Itoa(maxReceiveCount),
	})
	requireNoErr(t, err, "redrive policy")
	src = s.createQueue(t, name, map[string]string{
		"VisibilityTimeout": strconv.Itoa(vis),
		"RedrivePolicy":     string(policy),
	})
	return src, dlq
}

func TestMappingReportBatchItemFailures(t *testing.T) {
	// "To make messages id2 and id4 visible again in your queue, your
	// function should return" them in batchItemFailures (Handling errors for
	// an SQS event source): only the failed record comes back.
	s := startMappingStack(t)
	createFunction(t, s.lambda, "partial", "sqs", oneSecond)
	q, _ := s.withDLQ(t, "partial", 3, 2)
	ok1, failed, ok3 := s.sendBody(
		t,
		q,
		"ok-1",
	), s.sendBody(
		t,
		q,
		"fail-2",
	), s.sendBody(
		t,
		q,
		"ok-3",
	)
	s.mapping(t, q, "partial", func(in *lambda.CreateEventSourceMappingInput) {
		in.FunctionResponseTypes = []types.FunctionResponseType{
			types.FunctionResponseTypeReportBatchItemFailures,
		}
		in.MaximumBatchingWindowInSeconds = aws.Int32(1)
	})

	eventually(t, deliveryTimeout, "the failed record redelivered", func() bool {
		return s.deliveriesOf(t, "partial", failed) >= 2
	})
	requireEqual(t, s.deliveriesOf(t, "partial", ok1), 1, "deliveries of ok-1")
	requireEqual(t, s.deliveriesOf(t, "partial", ok3), 1, "deliveries of ok-3")
	for _, r := range s.deliveries(t, "partial") {
		if r.Attributes["ApproximateReceiveCount"] != "1" && r.MessageID != failed {
			t.Fatalf("message %s (%s) came back though it succeeded", r.MessageID, r.Body)
		}
	}

	first := s.batches(t, "partial")[0]
	var res struct {
		BatchItemFailures []struct {
			ItemIdentifier string `json:"itemIdentifier"`
		} `json:"batchItemFailures"`
	}
	unmarshal(t, first.detail.resultJSON(t), &res)
	if len(res.BatchItemFailures) != 1 || res.BatchItemFailures[0].ItemIdentifier != failed {
		t.Fatalf("first result %s, want the one failure %s", first.detail.resultJSON(t), failed)
	}
}

func TestMappingUnknownItemIdentifierFailsTheBatch(t *testing.T) {
	// "Lambda treats a batch as a complete failure if your function returns
	// ... An itemIdentifier value with a message ID that doesn't exist"
	// (Success and failure conditions): every record comes back.
	s := startMappingStack(t)
	createFunction(t, s.lambda, "badids", "sqs", oneSecond)
	q, _ := s.withDLQ(t, "badids", 2, 3)
	bad, ok := s.sendBody(t, q, "badid-1"), s.sendBody(t, q, "ok-2")
	s.mapping(t, q, "badids", func(in *lambda.CreateEventSourceMappingInput) {
		in.FunctionResponseTypes = []types.FunctionResponseType{
			types.FunctionResponseTypeReportBatchItemFailures,
		}
		in.MaximumBatchingWindowInSeconds = aws.Int32(2)
	})

	eventually(t, deliveryTimeout, "the batch redelivered", func() bool {
		return s.deliveriesOf(t, "badids", ok) >= 2
	})
	first := s.batches(t, "badids")[0]
	got := make([]string, 0, len(first.records))
	for _, r := range first.records {
		got = append(got, r.MessageID)
	}
	// Both were sent before the mapping, and the batching window gathers
	// them; otherwise the redelivery of ok-2 would prove nothing.
	requireSameSet(t, got, []string{bad, ok}, "the first batch")
}

func TestMappingRedrivesToTheDLQ(t *testing.T) {
	// "By default, if your function encounters an error while processing a
	// batch, all messages in that batch become visible in the queue again
	// after the visibility timeout expires" (Using Lambda with Amazon SQS);
	// the queue's redrive policy moves it after maxReceiveCount receives.
	s := startMappingStack(t)
	createFunction(t, s.lambda, "crashy", "sqs", oneSecond)
	src, dlq := s.withDLQ(t, "crashy", 2, 1)
	s.mapping(t, src, "crashy", nil)
	id := s.sendBody(t, src, "error-1")

	eventually(t, 2*deliveryTimeout, "the message in the DLQ", func() bool {
		return s.messagesIn(t, dlq) == 1
	})
	requireEqual(t, s.messagesIn(t, src), 0, "messages left in the source queue")
	requireEqual(t, s.deliveriesOf(t, "crashy", id), 2, "deliveries before the redrive")
	for _, b := range s.batches(t, "crashy") {
		requireEqual(t, b.detail.Status, "failed", "status of a failed batch")
	}

	out, err := s.sqs.ReceiveMessage(
		t.Context(),
		&sqs.ReceiveMessageInput{QueueUrl: aws.String(dlq.URL)},
	)
	requireNoErr(t, err, "receive from the DLQ")
	requireEqual(t, len(out.Messages), 1, "messages received from the DLQ")
	requireEqual(t, aws.ToString(out.Messages[0].MessageId), id, "the redriven message")
}

func TestMappingFIFOKeepsOrderPerGroup(t *testing.T) {
	// The design: FIFO queues are processed per message group in order. The
	// records carry the FIFO attributes of "Example Amazon SQS message event
	// (FIFO queue)".
	s := startMappingStack(t)
	createFunction(t, s.lambda, "ordered", "sqs", nil)
	q := s.createQueue(t, "jobs.fifo", map[string]string{
		"FifoQueue": "true", "ContentBasedDeduplication": "true", "VisibilityTimeout": "30",
	})
	sent := map[string][]string{}
	var all []string
	for i := 1; i <= 4; i++ {
		for _, g := range []string{"a", "b"} {
			body := g + strconv.Itoa(i)
			id := s.send(t, q, &sqs.SendMessageInput{
				MessageBody: aws.String(body), MessageGroupId: aws.String(g),
			})
			sent[g] = append(sent[g], body)
			all = append(all, id)
		}
	}
	s.mapping(t, q, "ordered", func(in *lambda.CreateEventSourceMappingInput) {
		in.BatchSize = aws.Int32(2)
	})
	s.waitDelivered(t, "ordered", all...)

	got := map[string][]string{}
	for _, r := range s.deliveries(t, "ordered") {
		for _, k := range []string{"MessageGroupId", "SequenceNumber", "MessageDeduplicationId"} {
			if r.Attributes[k] == "" {
				t.Fatalf("FIFO record %s without %s: %v", r.MessageID, k, r.Attributes)
			}
		}
		g := r.Attributes["MessageGroupId"]
		got[g] = append(got[g], r.Body)
	}
	for _, g := range []string{"a", "b"} {
		requireSlice(t, got[g], sent[g], "group "+g+" in delivery order")
	}
	eventually(t, deliveryTimeout, "the FIFO queue emptied", func() bool {
		return s.messagesIn(t, q) == 0
	})
}

func TestMappingDisableStopsDelivery(t *testing.T) {
	s := startMappingStack(t)
	createFunction(t, s.lambda, "pausable", "sqs", nil)
	q := s.createQueue(t, "pausable", nil)
	id := s.mapping(t, q, "pausable", nil)
	s.waitDelivered(t, "pausable", s.sendBody(t, q, "m1"))

	out, err := s.lambda.UpdateEventSourceMapping(
		t.Context(),
		&lambda.UpdateEventSourceMappingInput{
			UUID: aws.String(id), Enabled: aws.Bool(false),
		},
	)
	requireNoErr(t, err, "disable the mapping")
	requireOneOf(t, aws.ToString(out.State), []string{"Updating", "Disabling", "Disabled"},
		"State after disabling")
	s.waitState(t, id, "Disabled")

	m2 := s.sendBody(t, q, "m2")
	time.Sleep(5 * time.Second)
	requireEqual(t, s.deliveriesOf(t, "pausable", m2), 0, "deliveries while disabled")
	requireEqual(t, s.messagesIn(t, q), 1, "messages waiting while disabled")

	_, err = s.lambda.UpdateEventSourceMapping(t.Context(), &lambda.UpdateEventSourceMappingInput{
		UUID: aws.String(id), Enabled: aws.Bool(true),
	})
	requireNoErr(t, err, "enable the mapping")
	s.waitState(t, id, "Enabled")
	s.waitDelivered(t, "pausable", m2)
}

func TestMappingStates(t *testing.T) {
	// The states the SDK model lists: Creating, Enabling, Enabled,
	// Disabling, Disabled, Updating, Deleting.
	s := startMappingStack(t)
	createFunction(t, s.lambda, "stateful", "sqs", nil)
	q := s.createQueue(t, "stateful", nil)

	out, err := s.lambda.CreateEventSourceMapping(
		t.Context(),
		&lambda.CreateEventSourceMappingInput{
			EventSourceArn:                 aws.String(q.ARN),
			FunctionName:                   aws.String("stateful"),
			BatchSize:                      aws.Int32(7),
			MaximumBatchingWindowInSeconds: aws.Int32(1),
			FunctionResponseTypes: []types.FunctionResponseType{
				types.FunctionResponseTypeReportBatchItemFailures,
			},
			ScalingConfig: &types.ScalingConfig{MaximumConcurrency: aws.Int32(2)},
		},
	)
	requireNoErr(t, err, "create event source mapping")
	id := aws.ToString(out.UUID)
	requireOneOf(t, aws.ToString(out.State), []string{"Creating", "Enabled"}, "State after create")
	requireEqual(t, aws.ToString(out.EventSourceArn), q.ARN, "EventSourceArn")
	requireEqual(t, aws.ToString(out.FunctionArn), functionARN("stateful"), "FunctionArn")
	requireEqual(t, aws.ToInt32(out.BatchSize), int32(7), "BatchSize")

	got := s.waitState(t, id, "Enabled")
	requireEqual(t, aws.ToInt32(got.MaximumBatchingWindowInSeconds), int32(1), "batching window")
	requireEqual(
		t,
		aws.ToInt32(got.ScalingConfig.MaximumConcurrency),
		int32(2),
		"MaximumConcurrency",
	)
	if !slices.Equal(got.FunctionResponseTypes, []types.FunctionResponseType{
		types.FunctionResponseTypeReportBatchItemFailures,
	}) {
		t.Fatalf("FunctionResponseTypes %v", got.FunctionResponseTypes)
	}
	s.requireListed(t, id, q)

	s.updateThenDelete(t, id)
}

// updateThenDelete updates the enabled mapping id, then deletes it and a
// disabled one.
func (s *mappingStack) updateThenDelete(t *testing.T, id string) {
	t.Helper()
	up, err := s.lambda.UpdateEventSourceMapping(t.Context(), &lambda.UpdateEventSourceMappingInput{
		UUID: aws.String(id), BatchSize: aws.Int32(5),
	})
	requireNoErr(t, err, "update the mapping")
	requireOneOf(t, aws.ToString(up.State), []string{"Updating", "Enabled"}, "State after update")
	requireEqual(
		t,
		aws.ToInt32(s.waitState(t, id, "Enabled").BatchSize),
		int32(5),
		"updated BatchSize",
	)

	off := s.mapping(t, s.createQueue(t, "stateful-off", nil), "stateful",
		func(in *lambda.CreateEventSourceMappingInput) { in.Enabled = aws.Bool(false) })

	del, err := s.lambda.DeleteEventSourceMapping(t.Context(),
		&lambda.DeleteEventSourceMappingInput{UUID: aws.String(id)})
	requireNoErr(t, err, "delete the mapping")
	requireEqual(t, aws.ToString(del.State), "Deleting", "State after delete")
	s.waitGone(t, id)
	_, err = s.lambda.DeleteEventSourceMapping(t.Context(),
		&lambda.DeleteEventSourceMappingInput{UUID: aws.String(off)})
	requireNoErr(t, err, "delete the disabled mapping")
	s.waitGone(t, off)
}

func (s *mappingStack) requireListed(t *testing.T, id string, q queue) {
	t.Helper()
	for what, in := range map[string]*lambda.ListEventSourceMappingsInput{
		"all":             {},
		"by function":     {FunctionName: aws.String("stateful")},
		"by event source": {EventSourceArn: aws.String(q.ARN)},
	} {
		out, err := s.lambda.ListEventSourceMappings(t.Context(), in)
		requireNoErr(t, err, "list mappings "+what)
		if len(out.EventSourceMappings) != 1 ||
			aws.ToString(out.EventSourceMappings[0].UUID) != id {
			t.Fatalf(
				"list mappings %s: %d mappings, want only %s",
				what,
				len(out.EventSourceMappings),
				id,
			)
		}
	}
}

func (s *mappingStack) waitGone(t *testing.T, id string) {
	t.Helper()
	var err error
	eventually(t, deliveryTimeout, "mapping "+id+" deleted", func() bool {
		_, err = s.lambda.GetEventSourceMapping(t.Context(),
			&lambda.GetEventSourceMappingInput{UUID: aws.String(id)})
		return err != nil
	})
	requireModeled[*types.ResourceNotFoundException](t, err)
}

func TestMappingRefusesAVisibilityTimeoutBelowTheFunctionTimeout(t *testing.T) {
	// "Lambda validates this requirement when you create or update an event
	// source mapping and returns an error if the function timeout exceeds
	// the queue's visibility timeout" (Creating and configuring an Amazon
	// SQS event source mapping). Assumption: the error is
	// InvalidParameterValueException; the page names none.
	s := startMappingStack(t)
	createFunction(t, s.lambda, "patient", "sqs", func(in *lambda.CreateFunctionInput) {
		in.Timeout = aws.Int32(10)
	})
	q := s.createQueue(t, "hasty", map[string]string{"VisibilityTimeout": "5"})
	err := errOf(
		s.lambda.CreateEventSourceMapping(t.Context(), &lambda.CreateEventSourceMappingInput{
			EventSourceArn: aws.String(q.ARN), FunctionName: aws.String("patient"),
		}),
	)
	requireModeled[*types.InvalidParameterValueException](t, err)
}

func TestMappingErrors(t *testing.T) {
	// ResourceNotFoundException (404) for a function or a mapping that does
	// not exist.
	s := startMappingStack(t)
	q := s.createQueue(t, "orphan", nil)
	err := errOf(
		s.lambda.CreateEventSourceMapping(t.Context(), &lambda.CreateEventSourceMappingInput{
			EventSourceArn: aws.String(q.ARN), FunctionName: aws.String("nobody"),
		}),
	)
	requireModeled[*types.ResourceNotFoundException](t, err)
	err = errOf(s.lambda.GetEventSourceMapping(t.Context(), &lambda.GetEventSourceMappingInput{
		UUID: aws.String("00000000-0000-0000-0000-000000000000"),
	}))
	requireModeled[*types.ResourceNotFoundException](t, err)
}

func requireOneOf(t *testing.T, got string, want []string, what string) {
	t.Helper()
	if !slices.Contains(want, got) {
		t.Fatalf("%s: %q, want one of %s", what, got, strings.Join(want, ", "))
	}
}
