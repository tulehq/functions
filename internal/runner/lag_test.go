package runner

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"tule.dev/functions/internal/testfn"
)

// TestOutputWrittenJustBeforeTheResponseIsKept runs a function that prints a
// line and returns at once, hundreds of times: the line must be in each
// invocation's log, never in the next one's.
func TestOutputWrittenJustBeforeTheResponseIsKept(t *testing.T) {
	image := testfn.Image(t)
	r := newRunner(t, 1)
	spec := specFor(image, 5*time.Second)
	for i := range 300 {
		marker := "marker-" + strconv.Itoa(i)
		res := invoke(t, r, spec, `{"action":"reply","reply":1,"print":"`+marker+`"}`)
		if !strings.Contains(res.Log, marker+"\n") {
			t.Fatalf("invocation %d lost its output:\n%s", i, res.Log)
		}
		if i > 0 && strings.Contains(res.Log, "marker-"+strconv.Itoa(i-1)+"\n") {
			t.Fatalf("invocation %d holds the previous one's output:\n%s", i, res.Log)
		}
	}
}
