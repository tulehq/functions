// Package poller runs an SQS event source mapping: it long polls the queue
// through the SQS API, builds the event Lambda builds from each batch,
// invokes the function synchronously, and deletes what the function
// processed, as Lambda does.
package poller

import (
	"encoding/base64"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// Event is the event an SQS batch invokes a function with, as the Lambda
// developer guide's examples give it.
type Event struct {
	Records []Record `json:"Records"`
}

// Record is one message of the batch.
type Record struct {
	Attributes             map[string]string           `json:"attributes"`
	MessageAttributes      map[string]MessageAttribute `json:"messageAttributes"`
	MessageID              string                      `json:"messageId"`
	ReceiptHandle          string                      `json:"receiptHandle"`
	Body                   string                      `json:"body"`
	MD5OfBody              string                      `json:"md5OfBody"`
	MD5OfMessageAttributes string                      `json:"md5OfMessageAttributes,omitempty"`
	EventSource            string                      `json:"eventSource"`
	EventSourceARN         string                      `json:"eventSourceARN"`
	AWSRegion              string                      `json:"awsRegion"`
}

// MessageAttribute is a message attribute as the event carries it: the
// list members are always present, empty, and a binary value is base64.
type MessageAttribute struct {
	StringValue      *string  `json:"stringValue,omitempty"`
	BinaryValue      *string  `json:"binaryValue,omitempty"`
	DataType         string   `json:"dataType"`
	StringListValues []string `json:"stringListValues"`
	BinaryListValues []string `json:"binaryListValues"`
}

// BuildEvent builds the event of a batch received from the queue arn in
// region.
func BuildEvent(msgs []types.Message, arn, region string) Event {
	ev := Event{Records: make([]Record, 0, len(msgs))}
	for i := range msgs {
		m := &msgs[i]
		rec := Record{
			MessageID:              aws.ToString(m.MessageId),
			ReceiptHandle:          aws.ToString(m.ReceiptHandle),
			Body:                   aws.ToString(m.Body),
			Attributes:             map[string]string{},
			MessageAttributes:      map[string]MessageAttribute{},
			MD5OfBody:              aws.ToString(m.MD5OfBody),
			MD5OfMessageAttributes: aws.ToString(m.MD5OfMessageAttributes),
			EventSource:            "aws:sqs",
			EventSourceARN:         arn,
			AWSRegion:              region,
		}
		for k, v := range m.Attributes {
			rec.Attributes[k] = v
		}
		for name, a := range m.MessageAttributes {
			attr := MessageAttribute{
				DataType:         aws.ToString(a.DataType),
				StringValue:      a.StringValue,
				StringListValues: append([]string{}, a.StringListValues...),
				BinaryListValues: make([]string, 0, len(a.BinaryListValues)),
			}
			if a.BinaryValue != nil {
				v := base64.StdEncoding.EncodeToString(a.BinaryValue)
				attr.BinaryValue = &v
			}
			for _, b := range a.BinaryListValues {
				attr.BinaryListValues = append(attr.BinaryListValues,
					base64.StdEncoding.EncodeToString(b))
			}
			rec.MessageAttributes[name] = attr
		}
		ev.Records = append(ev.Records, rec)
	}
	return ev
}

// Failed returns the message IDs a ReportBatchItemFailures response names,
// and whether the response is valid. The developer guide's rules: an empty
// or null response, or an empty or null batchItemFailures, fails nothing;
// a response that is not a JSON object, an item without an itemIdentifier
// or with an empty or null one, and an itemIdentifier of no message in the
// batch, fail the whole batch.
func Failed(response []byte, batch map[string]bool) ([]string, bool) {
	if len(response) == 0 || string(response) == "null" {
		return nil, true
	}
	var body struct {
		Failures []map[string]json.RawMessage `json:"batchItemFailures"`
	}
	if json.Unmarshal(response, &body) != nil {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(response, &obj) != nil {
		return nil, false
	}
	failed := make([]string, 0, len(body.Failures))
	for _, item := range body.Failures {
		raw, ok := item["itemIdentifier"]
		if !ok {
			return nil, false
		}
		var id string
		if json.Unmarshal(raw, &id) != nil || id == "" || !batch[id] {
			return nil, false
		}
		failed = append(failed, id)
	}
	return failed, true
}
