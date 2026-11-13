// Command sleep is a test function: it sleeps for the event's "ms"
// milliseconds and returns how long it slept and the container's hostname,
// which tells containers apart.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
)

type event struct {
	Ms int `json:"ms"`
}

type result struct {
	Host  string `json:"host"`
	Slept int    `json:"slept"`
}

func handler(_ context.Context, e event) (result, error) {
	fmt.Println("sleep: sleeping", e.Ms, "ms")
	time.Sleep(time.Duration(e.Ms) * time.Millisecond)
	host, err := os.Hostname()
	if err != nil {
		return result{}, err
	}
	fmt.Println("sleep: woke up")
	return result{Host: host, Slept: e.Ms}, nil
}

func main() {
	lambda.Start(handler)
}
