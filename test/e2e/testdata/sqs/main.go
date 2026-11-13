// Command sqs is a test function for SQS event source mappings. For each
// record, by body:
//   - "error..." fails the whole invocation with an error;
//   - "fail..." reports the record's messageId in batchItemFailures;
//   - "badid..." reports an itemIdentifier that is no message of the batch;
//   - anything else succeeds.
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func handler(_ context.Context, e events.SQSEvent) (events.SQSEventResponse, error) {
	resp := events.SQSEventResponse{BatchItemFailures: []events.SQSBatchItemFailure{}}
	for _, r := range e.Records {
		fmt.Printf("sqs: %s %s\n", r.MessageId, r.Body)
		switch {
		case strings.HasPrefix(r.Body, "error"):
			return resp, errors.New("batch failed on " + r.MessageId)
		case strings.HasPrefix(r.Body, "fail"):
			resp.BatchItemFailures = append(resp.BatchItemFailures,
				events.SQSBatchItemFailure{ItemIdentifier: r.MessageId})
		case strings.HasPrefix(r.Body, "badid"):
			resp.BatchItemFailures = append(resp.BatchItemFailures,
				events.SQSBatchItemFailure{ItemIdentifier: "no-such-message-id"})
		}
	}
	return resp, nil
}

func main() {
	lambda.Start(handler)
}
