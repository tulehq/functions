package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/gasmod/gas"

	"tule.dev/functions/internal/contracts"
)

func TestBuildEventShapesRecordsAsLambdaDoes(t *testing.T) {
	ev := BuildEvent([]types.Message{{
		MessageId:     aws.String("m1"),
		ReceiptHandle: aws.String("rh"),
		Body:          aws.String("hello"),
		MD5OfBody:     aws.String("5d41402abc4b2a76b9719d911017c592"),
		Attributes:    map[string]string{"ApproximateReceiveCount": "1"},
		MessageAttributes: map[string]types.MessageAttributeValue{
			"s": {DataType: aws.String("String"), StringValue: aws.String("v")},
			"b": {DataType: aws.String("Binary"), BinaryValue: []byte{1, 2}},
		},
	}}, "arn:aws:sqs:us-east-1:000000000000:q", "us-east-1")
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Records []map[string]json.RawMessage `json:"Records"`
	}
	if err = json.Unmarshal(b, &got); err != nil || len(got.Records) != 1 {
		t.Fatalf("event %s: %v", b, err)
	}
	r := got.Records[0]
	for k, want := range map[string]string{
		"messageId": `"m1"`, "receiptHandle": `"rh"`, "body": `"hello"`,
		"md5OfBody": `"5d41402abc4b2a76b9719d911017c592"`, "eventSource": `"aws:sqs"`,
		"eventSourceARN": `"arn:aws:sqs:us-east-1:000000000000:q"`, "awsRegion": `"us-east-1"`,
		"attributes": `{"ApproximateReceiveCount":"1"}`,
	} {
		if string(r[k]) != want {
			t.Errorf("%s = %s, want %s", k, r[k], want)
		}
	}
	var attrs map[string]map[string]any
	_ = json.Unmarshal(r["messageAttributes"], &attrs)
	if attrs["s"]["stringValue"] != "v" || attrs["s"]["dataType"] != "String" ||
		attrs["b"]["binaryValue"] != "AQI=" || attrs["s"]["stringListValues"] == nil {
		t.Errorf("messageAttributes = %s", r["messageAttributes"])
	}
}

func TestFailedFollowsTheDeveloperGuidesRules(t *testing.T) {
	batch := map[string]bool{"a": true, "b": true}
	tests := []struct {
		response string
		failed   int
		ok       bool
	}{
		{``, 0, true},
		{`null`, 0, true},
		{`{}`, 0, true},
		{`{"batchItemFailures":null}`, 0, true},
		{`{"batchItemFailures":[]}`, 0, true},
		{`{"batchItemFailures":[{"itemIdentifier":"a"}]}`, 1, true},
		{`not json`, 0, false},
		{`"a string"`, 0, false},
		{`{"batchItemFailures":[{"itemIdentifier":""}]}`, 0, false},
		{`{"batchItemFailures":[{"itemIdentifier":null}]}`, 0, false},
		{`{"batchItemFailures":[{"id":"a"}]}`, 0, false},
		{`{"batchItemFailures":[{"itemIdentifier":"zzz"}]}`, 0, false},
	}
	for _, tt := range tests {
		failed, ok := Failed([]byte(tt.response), batch)
		if ok != tt.ok || len(failed) != tt.failed {
			t.Errorf("Failed(%s) = %v %v, want %d %v", tt.response, failed, ok, tt.failed, tt.ok)
		}
	}
}

// fakeSQS hands out its messages once, and records the deletes.
type fakeSQS struct {
	msgs    []types.Message
	deleted []string
	mu      sync.Mutex
}

func (f *fakeSQS) GetQueueUrl( //nolint:revive // the SDK's method name
	context.Context, *sqs.GetQueueUrlInput, ...func(*sqs.Options),
) (*sqs.GetQueueUrlOutput, error) {
	return &sqs.GetQueueUrlOutput{QueueUrl: aws.String("http://q/000000000000/q")}, nil
}

func (f *fakeSQS) ReceiveMessage(
	ctx context.Context, in *sqs.ReceiveMessageInput, _ ...func(*sqs.Options),
) (*sqs.ReceiveMessageOutput, error) {
	f.mu.Lock()
	n := min(int(in.MaxNumberOfMessages), len(f.msgs))
	out := f.msgs[:n]
	f.msgs = f.msgs[n:]
	f.mu.Unlock()
	if n == 0 {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("receive: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	return &sqs.ReceiveMessageOutput{Messages: out}, nil
}

func (f *fakeSQS) DeleteMessageBatch(
	_ context.Context, in *sqs.DeleteMessageBatchInput, _ ...func(*sqs.Options),
) (*sqs.DeleteMessageBatchOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range in.Entries {
		f.deleted = append(f.deleted, aws.ToString(e.ReceiptHandle))
	}
	return &sqs.DeleteMessageBatchOutput{}, nil
}

func messages(n int) []types.Message {
	out := make([]types.Message, 0, n)
	for i := range n {
		id := "m" + strconv.Itoa(i)
		out = append(out, types.Message{
			MessageId: aws.String(id), ReceiptHandle: aws.String("rh-" + id),
			Body: aws.String("body"),
		})
	}
	return out
}

// runPoller polls fake until want invocations ran, and returns what each
// was invoked with.
func runPoller(t *testing.T, fake *fakeSQS, m contracts.Mapping, outcome func(Event) *Outcome,
	want int,
) []Event {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var (
		mu     sync.Mutex
		events []Event
	)
	done := make(chan struct{})
	cfg := &Config{
		Client: fake, Logger: &gas.NopLogger{}, Mapping: m, Region: "us-east-1",
		Account: "000000000000", Queue: "q", Workers: 1,
		Report: func(string) {},
		Invoke: func(_ context.Context, payload []byte) (*Outcome, error) {
			var ev Event
			if err := json.Unmarshal(payload, &ev); err != nil {
				t.Errorf("decode the event: %v", err)
			}
			mu.Lock()
			events = append(events, ev)
			if len(events) == want {
				close(done)
			}
			mu.Unlock()
			return outcome(ev), nil
		},
	}
	go Run(ctx, cfg)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d invocations ran, want %d", len(events), want)
	}
	time.Sleep(50 * time.Millisecond) // let the last batch's deletes land
	mu.Lock()
	defer mu.Unlock()
	return events
}

func TestAPollerDeletesASucceededBatch(t *testing.T) {
	fake := &fakeSQS{msgs: messages(3)}
	events := runPoller(t, fake, contracts.Mapping{BatchSize: 10},
		func(Event) *Outcome { return &Outcome{Succeeded: true} }, 1)
	if len(events[0].Records) != 3 {
		t.Fatalf("batch of %d, want 3", len(events[0].Records))
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.deleted) != 3 {
		t.Fatalf("deleted %v, want all 3", fake.deleted)
	}
}

func TestAPollerKeepsAFailedBatch(t *testing.T) {
	fake := &fakeSQS{msgs: messages(2)}
	runPoller(t, fake, contracts.Mapping{BatchSize: 10},
		func(Event) *Outcome { return &Outcome{} }, 1)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.deleted) != 0 {
		t.Fatalf("deleted %v after a failure, want none", fake.deleted)
	}
}

func TestAPollerDeletesAllButTheReportedFailures(t *testing.T) {
	fake := &fakeSQS{msgs: messages(3)}
	runPoller(t, fake, contracts.Mapping{
		BatchSize: 10, FunctionResponseTypes: []string{contracts.ReportBatchItemFailures},
	}, func(Event) *Outcome {
		return &Outcome{
			Succeeded: true,
			Response:  []byte(`{"batchItemFailures":[{"itemIdentifier":"m1"}]}`),
		}
	}, 1)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.deleted) != 2 || fake.deleted[0] != "rh-m0" || fake.deleted[1] != "rh-m2" {
		t.Fatalf("deleted %v, want m0 and m2", fake.deleted)
	}
}

func TestAPollerSplitsByBatchSize(t *testing.T) {
	fake := &fakeSQS{msgs: messages(5)}
	events := runPoller(t, fake, contracts.Mapping{BatchSize: 2},
		func(Event) *Outcome { return &Outcome{Succeeded: true} }, 3)
	if len(events[0].Records) != 2 || len(events[2].Records) != 1 {
		t.Fatalf("batches %d, %d, %d", len(events[0].Records), len(events[1].Records),
			len(events[2].Records))
	}
}

func TestSplitKeepsEachEventWithinTheLimit(t *testing.T) {
	big := strings.Repeat("x", 400)
	msgs := messages(10)
	for i := range msgs {
		msgs[i].Body = aws.String(big)
	}
	one, _ := json.Marshal(BuildEvent(msgs[:1], "arn", "r"))
	limit := 3*len(one) + 10
	parts := Split(msgs, "arn", "r", limit)
	total := 0
	for _, p := range parts {
		ev, _ := json.Marshal(BuildEvent(p, "arn", "r"))
		if len(ev) > limit {
			t.Fatalf("an event of %d bytes, past %d", len(ev), limit)
		}
		total += len(p)
	}
	if len(parts) != 4 || total != 10 || aws.ToString(parts[3][0].MessageId) != "m9" {
		t.Fatalf("split into %d parts of %d messages", len(parts), total)
	}
	if got := Split(msgs[:1], "arn", "r", 10); len(got) != 1 {
		t.Fatalf("a message past the limit alone = %d parts, want 1", len(got))
	}
}
