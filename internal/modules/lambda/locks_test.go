package lambda

import (
	"testing"
	"time"
)

// TestANameIsNotReplacedWhileHeld checks that a function cannot be deleted
// or created again under a name an operation holds between its
// authorization and its act: the write waits for the read to be released.
func TestANameIsNotReplacedWhileHeld(t *testing.T) {
	l := newNameLocks()
	release := l.read("fn")
	other := l.read("other")
	written := make(chan struct{})
	go func() {
		l.write("fn")()
		close(written)
	}()
	select {
	case <-written:
		t.Fatal("the name was written while it was held")
	case <-time.After(100 * time.Millisecond):
	}
	other()
	release()
	select {
	case <-written:
	case <-time.After(5 * time.Second):
		t.Fatal("the write never got the name")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.locks) != 0 {
		t.Fatalf("%d locks kept after release", len(l.locks))
	}
}
