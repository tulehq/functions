//go:build e2e

package e2e

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A process is a sibling service built from its checkout and run beside the
// app under test: queues for the event source mappings, identity for the
// cross-service test.
type process struct {
	cmd     *exec.Cmd
	exited  chan error
	out     *processOutput
	name    string
	URL     string
	stopped bool
}

// processOutput collects the process's output, safe to write from the
// process's copying goroutines and read from the test.
type processOutput struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *processOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never fails
}

func (b *processOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// built caches each service binary for the run: building it once is enough.
var built = struct {
	bins map[string]string
	mu   sync.Mutex
}{bins: map[string]string{}}

// buildService builds the service name from its checkout. The test runs in
// functions/test/e2e; by default the checkout is functions' sibling, and
// dirEnv names another. CI sets it. A missing checkout fails the test, so a
// cross-service test is never silently left out.
func buildService(t *testing.T, name, dirEnv string) string {
	t.Helper()
	built.mu.Lock()
	defer built.mu.Unlock()
	if bin, ok := built.bins[name]; ok {
		return bin
	}

	src, from := os.Getenv(dirEnv), dirEnv
	if src == "" {
		src, from = filepath.Join("..", "..", "..", name), "the default sibling path"
	}
	src, err := filepath.Abs(src)
	requireNoErr(t, err, name+" directory")
	//nolint:gosec // G703: the checkout the test is told to build
	if _, err = os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Fatalf("no %s checkout at %s (from %s); set %s to a %s checkout: %v",
			name, src, from, dirEnv, name, err)
	}

	bin := filepath.Join(workDir, "services", "tule-"+name)
	//nolint:gosec // G204: go build of the checkout into this run's directory
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, out)
	}
	built.bins[name] = bin
	return bin
}

// startService builds name from its checkout and runs it on a free port
// with a fresh store, TULE_GasEnv=testing, the key keyID/secret and extra
// environment, and waits for it to be ready. It is stopped when the test
// ends.
func startService(t *testing.T, name, dirEnv, keyID, secret string, extra ...string) *process {
	t.Helper()
	bin := buildService(t, name, dirEnv)
	dir := t.TempDir()
	port := freePort(t)

	cmd := exec.Command(bin) //nolint:gosec // G204: the binary this suite just built
	cmd.Dir = dir
	cmd.Env = append(envWithoutTule(),
		"TULE_GasEnv=testing",
		"TULE_Server_Port="+strconv.Itoa(port),
		"TULE_Store_Path="+filepath.Join(dir, name+".db"),
		"TULE_Auth_AccessKeyID="+keyID,
		"TULE_Auth_SecretAccessKey="+secret,
	)
	cmd.Env = append(cmd.Env, extra...)
	p := &process{
		name:   name,
		cmd:    cmd,
		exited: make(chan error, 1),
		out:    &processOutput{},
		URL:    "http://127.0.0.1:" + strconv.Itoa(port),
	}
	cmd.Stdout = p.out
	cmd.Stderr = p.out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	go func() { p.exited <- cmd.Wait() }()
	t.Cleanup(func() { p.Stop(t) })

	p.waitReady(t)
	return p
}

// envWithoutTule is this process's environment minus the TULE_ variables
// the tests set for functions, so a sibling gets only its own.
func envWithoutTule() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TULE_") {
			env = append(env, kv)
		}
	}
	return env
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoErr(t, err, "find a free port")
	port := l.Addr().(*net.TCPAddr).Port
	requireNoErr(t, l.Close(), "release the free port")
	return port
}

// waitReady polls the readiness probe until it answers 200.
func (p *process) waitReady(t *testing.T) {
	t.Helper()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(clientTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.exited:
			t.Fatalf("%s exited before it was ready: %v\n%s", p.name, err, p.out.String())
		default:
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, p.URL+"/_ready", nil)
		requireNoErr(t, err, "build readiness request")
		if res, err := client.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s was not ready within %v\n%s", p.name, clientTimeout, p.out.String())
}

// Stop interrupts the process and kills it if it does not exit in time. It
// is idempotent.
func (p *process) Stop(t *testing.T) {
	t.Helper()

	if p.stopped {
		return
	}
	p.stopped = true

	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-p.exited:
		if err != nil {
			t.Logf("%s exited: %v", p.name, err)
		}
	case <-time.After(clientTimeout):
		_ = p.cmd.Process.Kill()
		err := <-p.exited
		t.Errorf("%s did not stop on interrupt (%v)\n%s", p.name, err, p.out.String())
	}
}
