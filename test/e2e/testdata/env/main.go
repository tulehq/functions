// Command env is a test function: it returns its environment and what the
// Runtime API told it about the invocation.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
)

type result struct {
	Env                map[string]string `json:"env"`
	ClientCustom       map[string]string `json:"clientCustom"`
	RequestID          string            `json:"requestId"`
	InvokedFunctionArn string            `json:"invokedFunctionArn"`
	DeadlineMs         int64             `json:"deadlineMs"`
}

func handler(ctx context.Context) (result, error) {
	r := result{Env: map[string]string{}}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		r.Env[k] = v
	}
	if lc, ok := lambdacontext.FromContext(ctx); ok {
		r.RequestID = lc.AwsRequestID
		r.InvokedFunctionArn = lc.InvokedFunctionArn
		r.ClientCustom = lc.ClientContext.Custom
	}
	if d, ok := ctx.Deadline(); ok {
		r.DeadlineMs = d.UnixMilli()
	}
	fmt.Println("env: reported", len(r.Env), "variables")
	return r, nil
}

func main() {
	lambda.Start(handler)
}
