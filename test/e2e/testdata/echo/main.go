// Command echo is a test function: it prints the event it receives and
// returns it unchanged.
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
)

func handler(_ context.Context, event json.RawMessage) (json.RawMessage, error) {
	fmt.Printf("echo: %s\n", event)
	return event, nil
}

func main() {
	lambda.Start(handler)
}
