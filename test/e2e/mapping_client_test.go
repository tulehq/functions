//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// The event source mapping tests run functions against a real queues
// service: queues is built from its checkout and run as a process with the
// same test/test key, and functions polls it through
// TULE_Functions_QueuesEndpoint.

// queuesDirEnv names the queues checkout to build, for a layout where it is
// not functions' sibling.
const queuesDirEnv = "TULE_E2E_QUEUES_DIR"

// deliveryTimeout bounds how long a sent message may take to reach the
// function: a long poll answers as soon as a message is visible.
const deliveryTimeout = 30 * time.Second

type mappingStack struct {
	srv    *server
	lambda *lambda.Client
	sqs    *sqs.Client
	h      *history
}

func startMappingStack(t *testing.T) *mappingStack {
	t.Helper()
	queues := startService(t, "queues", queuesDirEnv, "test", "test")
	srv := startServer(t, map[string]string{"TULE_Functions_QueuesEndpoint": queues.URL})
	return &mappingStack{
		srv:    srv,
		lambda: clientFor(srv),
		h:      historyFor(srv),
		sqs: sqs.New(sqs.Options{
			Region:           region,
			BaseEndpoint:     aws.String(queues.URL),
			Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
			HTTPClient:       &http.Client{Timeout: clientTimeout},
			RetryMaxAttempts: 1,
		}),
	}
}

// queue is a queue on the queues service.
type queue struct {
	URL, ARN string
}

func (s *mappingStack) createQueue(t *testing.T, name string, attrs map[string]string) queue {
	t.Helper()
	out, err := s.sqs.CreateQueue(t.Context(), &sqs.CreateQueueInput{
		QueueName: aws.String(name), Attributes: attrs,
	})
	requireNoErr(t, err, "create queue "+name)
	q := queue{URL: aws.ToString(out.QueueUrl)}
	q.ARN = s.queueAttrs(t, q, "QueueArn")["QueueArn"]
	if q.ARN == "" {
		t.Fatalf("queue %s has no QueueArn", name)
	}
	return q
}

func (s *mappingStack) queueAttrs(t *testing.T, q queue, names ...string) map[string]string {
	t.Helper()
	an := make([]sqstypes.QueueAttributeName, 0, len(names))
	for _, n := range names {
		an = append(an, sqstypes.QueueAttributeName(n))
	}
	out, err := s.sqs.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{
		QueueUrl: aws.String(q.URL), AttributeNames: an,
	})
	requireNoErr(t, err, "get queue attributes")
	return out.Attributes
}

// messagesIn is the queue's visible plus in-flight plus delayed count.
func (s *mappingStack) messagesIn(t *testing.T, q queue) int {
	t.Helper()
	a := s.queueAttrs(t, q, "ApproximateNumberOfMessages",
		"ApproximateNumberOfMessagesNotVisible", "ApproximateNumberOfMessagesDelayed")
	n := 0
	for _, v := range a {
		i, err := strconv.Atoi(v)
		requireNoErr(t, err, "queue count "+v)
		n += i
	}
	return n
}

func (s *mappingStack) send(t *testing.T, q queue, in *sqs.SendMessageInput) string {
	t.Helper()
	in.QueueUrl = aws.String(q.URL)
	out, err := s.sqs.SendMessage(t.Context(), in)
	requireNoErr(t, err, "send "+aws.ToString(in.MessageBody))
	return aws.ToString(out.MessageId)
}

func (s *mappingStack) sendBody(t *testing.T, q queue, body string) string {
	t.Helper()
	return s.send(t, q, &sqs.SendMessageInput{MessageBody: aws.String(body)})
}

// mapping creates an enabled mapping from q to function and waits until it
// is Enabled.
func (s *mappingStack) mapping(
	t *testing.T,
	q queue,
	function string,
	mutate func(*lambda.CreateEventSourceMappingInput),
) string {
	t.Helper()
	in := &lambda.CreateEventSourceMappingInput{
		EventSourceArn: aws.String(q.ARN),
		FunctionName:   aws.String(function),
		BatchSize:      aws.Int32(10),
		Enabled:        aws.Bool(true),
	}
	if mutate != nil {
		mutate(in)
	}
	out, err := s.lambda.CreateEventSourceMapping(t.Context(), in)
	requireNoErr(t, err, "create event source mapping")
	id := aws.ToString(out.UUID)
	if id == "" {
		t.Fatal("the mapping has no UUID")
	}
	want := "Enabled"
	if !aws.ToBool(in.Enabled) {
		want = "Disabled"
	}
	s.waitState(t, id, want)
	return id
}

// waitState waits for the mapping's State.
func (s *mappingStack) waitState(
	t *testing.T,
	id, want string,
) *lambda.GetEventSourceMappingOutput {
	t.Helper()
	var got *lambda.GetEventSourceMappingOutput
	eventually(t, deliveryTimeout, "mapping "+id+" "+want, func() bool {
		out, err := s.lambda.GetEventSourceMapping(t.Context(),
			&lambda.GetEventSourceMappingInput{UUID: aws.String(id)})
		requireNoErr(t, err, "get event source mapping")
		got = out
		return aws.ToString(out.State) == want
	})
	return got
}

// sqsRecord is one record of the SQS event (Using Lambda with Amazon SQS).
type sqsRecord struct {
	Attributes        map[string]string          `json:"attributes"`
	MessageAttributes map[string]json.RawMessage `json:"messageAttributes"`
	MessageID         string                     `json:"messageId"`
	ReceiptHandle     string                     `json:"receiptHandle"`
	Body              string                     `json:"body"`
	MD5OfBody         string                     `json:"md5OfBody"`
	EventSource       string                     `json:"eventSource"`
	EventSourceARN    string                     `json:"eventSourceARN"`
	AWSRegion         string                     `json:"awsRegion"`
}

// batch is one invocation of a mapping and the records it carried.
type batch struct {
	records []sqsRecord
	raw     []byte
	detail  invocationDetail
}

// batches returns the function's invocations through a mapping, oldest
// first, with the records of each.
func (s *mappingStack) batches(t *testing.T, function string) []batch {
	t.Helper()
	items := s.h.all(t, url.Values{"function": {function}, "source": {"eventSourceMapping"}})
	slices.Reverse(items)
	out := make([]batch, 0, len(items))
	for _, it := range items {
		d := s.h.get(t, it.RequestID)
		raw := d.payloadJSON(t)
		var e struct {
			Records []sqsRecord `json:"Records"`
		}
		unmarshal(t, raw, &e)
		out = append(out, batch{detail: d, records: e.Records, raw: raw})
	}
	return out
}

// deliveries returns every record delivered to function, oldest batch
// first.
func (s *mappingStack) deliveries(t *testing.T, function string) []sqsRecord {
	t.Helper()
	var out []sqsRecord
	for _, b := range s.batches(t, function) {
		out = append(out, b.records...)
	}
	return out
}

// deliveriesOf counts the deliveries of message id to function.
func (s *mappingStack) deliveriesOf(t *testing.T, function, id string) int {
	t.Helper()
	n := 0
	for _, r := range s.deliveries(t, function) {
		if r.MessageID == id {
			n++
		}
	}
	return n
}

// waitDelivered waits until each of ids has reached function at least once.
func (s *mappingStack) waitDelivered(t *testing.T, function string, ids ...string) {
	t.Helper()
	eventually(t, deliveryTimeout, "delivery to "+function, func() bool {
		seen := map[string]bool{}
		for _, r := range s.deliveries(t, function) {
			seen[r.MessageID] = true
		}
		for _, id := range ids {
			if !seen[id] {
				return false
			}
		}
		return true
	})
}
