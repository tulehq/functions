// Command fn is the function the tests run in a container: an aws-lambda-go
// handler that does what its event asks.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
)

// event says what to do: echo the event back with the function's view of
// its context (the default), fail with an error, panic, or sleep first.
type event struct {
	Action  string          `json:"action"`
	Print   string          `json:"print"`
	Env     []string        `json:"env"`
	Records json.RawMessage `json:"Records"`
	Reply   json.RawMessage `json:"reply"`
	Bytes   int             `json:"bytes"`
	SleepMS int             `json:"sleepMs"`
}

type reply struct {
	Env           map[string]string `json:"env"`
	ClientContext map[string]string `json:"clientContext"`
	RequestID     string            `json:"requestId"`
	FunctionARN   string            `json:"functionArn"`
	Hostname      string            `json:"hostname"`
	Records       json.RawMessage   `json:"records,omitempty"`
	DeadlineMS    int64             `json:"deadlineMs"`
}

var (
	counting sync.Once
	ticks    atomic.Int64
)

func handle(ctx context.Context, ev event) (any, error) {
	if ev.Print != "" {
		fmt.Println(ev.Print)
	}
	if ev.SleepMS > 0 {
		time.Sleep(time.Duration(ev.SleepMS) * time.Millisecond)
	}
	switch ev.Action {
	case "error":
		return nil, errors.New("the handler failed")
	case "panic":
		panic("the handler panicked")
	case "exit":
		os.Exit(3)
	case "reply":
		return ev.Reply, nil
	case "count", "flood", "spam":
		return background(ev), nil
	}
	lc, _ := lambdacontext.FromContext(ctx)
	deadline, _ := ctx.Deadline()
	host, _ := os.Hostname()
	r := reply{
		Env:         map[string]string{},
		RequestID:   lc.AwsRequestID,
		FunctionARN: lc.InvokedFunctionArn,
		Records:     ev.Records,
		Hostname:    host,
		DeadlineMS:  deadline.UnixMilli(),
	}
	r.ClientContext = lc.ClientContext.Custom
	for _, k := range ev.Env {
		r.Env[k] = os.Getenv(k)
	}
	return r, nil
}

// background does the actions that leave the process doing something.
func background(ev event) any {
	switch ev.Action {
	case "count":
		// A goroutine that counts milliseconds for as long as the process
		// runs: frozen between invocations, it stops counting.
		counting.Do(func() {
			go func() {
				for {
					time.Sleep(time.Millisecond)
					ticks.Add(1)
				}
			}()
		})
		return ticks.Load()
	case "flood":
		fmt.Print(strings.Repeat("f", ev.Bytes))
		return "flooded"
	default:
		go func() {
			for {
				fmt.Println(strings.Repeat("s", 100))
			}
		}()
		return "spamming"
	}
}

func main() {
	fmt.Println("initializing")
	lambda.Start(handle)
}
