//go:build e2e

package e2e

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

// The design: all containers are removed on shutdown and on DeleteFunction
// and UpdateFunctionCode. Each test runs its function from an image no
// other test uses, and asks Docker for every container created from it.

// removalWindow is how long a removal may take after the call that causes
// it returns. Assumption: the design does not say whether DeleteFunction
// and UpdateFunctionCode remove containers before they answer, so a short
// window is allowed.
const removalWindow = 10 * time.Second

func requireContainers(t *testing.T, img, what string) {
	t.Helper()
	if len(containersOf(t, img)) == 0 {
		t.Fatalf("%s: no container from %s, so the check that follows proves nothing", what, img)
	}
}

func requireNoContainers(t *testing.T, img, what string, window time.Duration) {
	t.Helper()
	var left []string
	deadline := time.Now().Add(window)
	for {
		if left = containersOf(t, img); len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d container(s) from %s remain: %v", what, len(left), img, left)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestDeleteFunctionRemovesContainers(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "doomed", "cleanup-delete", nil)
	warmTwo(t, c, "doomed")
	requireContainers(t, "cleanup-delete", "after invoking")

	deleteFunction(t, c, "doomed")
	requireNoContainers(t, "cleanup-delete", "after DeleteFunction", removalWindow)
}

func TestUpdateFunctionCodeRemovesContainers(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "moving", "cleanup-update", nil)
	invokeOK(t, c, "moving", map[string]string{}, nil)
	requireContainers(t, "cleanup-update", "after invoking")

	_, err := c.UpdateFunctionCode(t.Context(), &lambda.UpdateFunctionCodeInput{
		FunctionName: aws.String("moving"),
		ImageUri:     aws.String(image("env")),
	})
	requireNoErr(t, err, "update code")
	waitUpdated(t, c, "moving")
	requireNoContainers(t, "cleanup-update", "after UpdateFunctionCode", removalWindow)
}

func TestShutdownRemovesContainers(t *testing.T) {
	// Assumption: the containers are gone when the app's Stop returns, since
	// nothing of the app is left to remove them afterwards.
	c, srv := newClient(t)
	createFunction(t, c, "left", "cleanup-stop", nil)
	warmTwo(t, c, "left")
	requireContainers(t, "cleanup-stop", "after invoking")

	srv.Stop(t)
	requireNoContainers(t, "cleanup-stop", "after the app stopped", 0)
}

// warmTwo leaves warm containers behind: two concurrent invocations, so
// more than one container may be running.
func warmTwo(t *testing.T, c *lambda.Client, name string) {
	t.Helper()
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := c.Invoke(t.Context(), &lambda.InvokeInput{
				FunctionName: aws.String(name),
				Payload:      []byte(`{}`),
			})
			errs <- err
		}()
	}
	for range 2 {
		requireNoErr(t, <-errs, "invoke "+name)
	}
}
