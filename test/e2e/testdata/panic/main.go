// Command panic is a test function: it panics with the event's "message"
// field, unless "ok" is set, when it answers "survived".
package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
)

type event struct {
	Message string `json:"message"`
	OK      bool   `json:"ok"`
}

func handler(_ context.Context, e event) (string, error) {
	if e.OK {
		return "survived", nil
	}
	fmt.Println("panic: about to panic")
	panic(e.Message)
}

func main() {
	lambda.Start(handler)
}
