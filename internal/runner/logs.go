package runner

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// MaxLogCapture bounds the output an invocation's log keeps: its first
// 1 MiB. What is dropped is counted, and the log says how much where the
// output was cut.
const MaxLogCapture = 1 << 20

// logBuffer collects a container's output as the attach stream delivers it.
// An invocation takes what arrived since the last take.
type logBuffer struct {
	last    time.Time
	buf     []byte
	dropped int
	mu      sync.Mutex
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := min(len(p), MaxLogCapture-len(b.buf))
	b.buf = append(b.buf, p[:keep]...)
	b.dropped += len(p) - keep
	b.last = time.Now()
	return len(p), nil
}

// take returns the output since the last take, led by a line saying how
// much was dropped when there was more than MaxLogCapture.
func (b *logBuffer) take() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := string(b.buf)
	if b.dropped > 0 {
		s = withNewline(s) + fmt.Sprintf("[tule: %d more bytes of output dropped]\n", b.dropped)
	}
	b.buf = nil
	b.dropped = 0
	return s
}

// lastWrite returns when output last arrived.
func (b *logBuffer) lastWrite() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

// settle waits for the output written before since to arrive. Nothing in
// Docker's stdio path orders a container's output against its requests to
// the Runtime API: the container writes to a pipe, and the daemon copies it
// to the attach stream on its own schedule, so output written just before
// a response can arrive just after it. settle bounds that lag: it returns
// once no output has arrived for quiet since the later of since and the
// last arrival, and by limit at the latest.
func (b *logBuffer) settle(since time.Time, quiet, limit time.Duration) {
	deadline := since.Add(limit)
	for {
		last := b.lastWrite()
		if last.Before(since) {
			last = since
		}
		wait := time.Until(last.Add(quiet))
		if wait <= 0 {
			return
		}
		if left := time.Until(deadline); left < wait {
			if left > 0 {
				time.Sleep(left)
			}
			return
		}
		time.Sleep(wait)
	}
}

// capOutput holds an invocation's output, before its START line and
// during it, to MaxLogCapture together, the output during it first.
func capOutput(before, during string) (string, string) {
	room := max(0, MaxLogCapture-len(during))
	if len(before) > room {
		before = withNewline(before[:room]) +
			fmt.Sprintf("[tule: %d more bytes of output dropped]\n", len(before)-room)
	}
	return before, during
}

// report is what the REPORT line of an invocation says.
type report struct {
	requestID  string
	duration   time.Duration
	init       time.Duration
	memorySize int
	timedOut   bool
}

// ms is d in milliseconds, as the log lines give durations.
func ms(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// invocationLog is an invocation's log as Lambda writes it in its plain
// text format: the output before the invocation started (a cold start's
// initialization), the START line, the invocation's output, then the END
// and REPORT lines. A timed-out invocation's output ends with the timeout
// line, and its REPORT with "Status: timeout".
func invocationLog(before, during string, r *report) string {
	var sb strings.Builder
	sb.WriteString(withNewline(before))
	fmt.Fprintf(&sb, "START RequestId: %s Version: $LATEST\n", r.requestID)
	sb.WriteString(withNewline(during))
	if r.timedOut {
		fmt.Fprintf(&sb, "%s %s Task timed out after %.2f seconds\n",
			time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), r.requestID,
			r.duration.Seconds())
	}
	fmt.Fprintf(&sb, "END RequestId: %s\n", r.requestID)
	fmt.Fprintf(&sb, "REPORT RequestId: %s\tDuration: %.2f ms\tBilled Duration: %d ms\t"+
		"Memory Size: %d MB\t", r.requestID, ms(r.duration), billed(r.duration), r.memorySize)
	if r.init > 0 {
		fmt.Fprintf(&sb, "Init Duration: %.2f ms\t", ms(r.init))
	}
	if r.timedOut {
		sb.WriteString("Status: timeout\t")
	}
	sb.WriteString("\n")
	return sb.String()
}

// billed rounds d up to the millisecond, as Lambda bills.
func billed(d time.Duration) int64 {
	return int64((d + time.Millisecond - 1) / time.Millisecond)
}

func withNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
