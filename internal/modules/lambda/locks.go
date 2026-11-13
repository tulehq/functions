package lambda

import "sync"

// nameLocks are a lock per function name. A function's name is its whole
// identity in its ARN, so a function deleted and created again under the
// same name between a request's authorization and its operation would be
// acted on although another function, with other tags, was evaluated. An
// operation that evaluates a function holds its name's lock for reading
// from authorization until it has acted, and CreateFunction and
// DeleteFunction hold it for writing, so a function cannot be replaced in
// between. The operations that change the function's policy hold it for
// writing too, so the policy an operation is evaluated with is the one in
// effect until it has acted. Tags changed in between are not held back: a
// tag value read at authorization may be stale when the operation acts, as
// on Lambda.
type nameLocks struct {
	locks map[string]*nameLock
	mu    sync.Mutex
}

type nameLock struct {
	rw   sync.RWMutex
	refs int
}

func newNameLocks() *nameLocks {
	return &nameLocks{locks: map[string]*nameLock{}}
}

// read takes name's lock for reading, and returns its release.
func (l *nameLocks) read(name string) func() {
	nl := l.acquire(name)
	nl.rw.RLock()
	return func() {
		nl.rw.RUnlock()
		l.release(name)
	}
}

// write takes name's lock for writing, and returns its release.
func (l *nameLocks) write(name string) func() {
	nl := l.acquire(name)
	nl.rw.Lock()
	return func() {
		nl.rw.Unlock()
		l.release(name)
	}
}

func (l *nameLocks) acquire(name string) *nameLock {
	l.mu.Lock()
	defer l.mu.Unlock()
	nl, ok := l.locks[name]
	if !ok {
		nl = &nameLock{}
		l.locks[name] = nl
	}
	nl.refs++
	return nl
}

func (l *nameLocks) release(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	nl := l.locks[name]
	if nl.refs--; nl.refs == 0 {
		delete(l.locks, name)
	}
}
