// Command errors is a test function: it returns a handled error whose
// message carries the event's "message" field.
package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
)

type event struct {
	Message string `json:"message"`
}

func handler(_ context.Context, e event) (string, error) {
	fmt.Println("errors: failing with", e.Message)
	return "", errors.New("handled failure: " + e.Message)
}

func main() {
	lambda.Start(handler)
}
