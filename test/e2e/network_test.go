//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/runner"
)

// TestFunctionsRunOnTheServicesNetwork runs the service the way a compose
// file does with TULE_Functions_ContainerNetwork: in a container on a
// user-defined network, reachable there as functions, its Lambda API
// published on 127.0.0.1 only and its Runtime API not published at all. A
// function invoked through the SDK must run, which it can only do by
// reaching the Runtime API at functions:9061 on that network, and its
// container must be on that network alone, with no host-gateway mapping.
//
// The service runs in a container, not in-process as the other tests run
// it, because only then is functions a name the function containers
// resolve, and only then does nothing reach the Runtime API through the
// Docker host. Its image is built FROM scratch around a static build of
// the service, so nothing is pulled.
func TestFunctionsRunOnTheServicesNetwork(t *testing.T) {
	suffix := runID + "-" + ids.Hex(4)
	network := "tule-functions-e2e-" + suffix
	_, err := docker(t.Context(), "network", "create",
		"--label", "dev.tule.e2e.run="+runID, network)
	requireNoErr(t, err, "create network")
	t.Cleanup(func() {
		ctx := context.Background()
		// A function container the service did not remove would keep the
		// network from being removed.
		attached, _ := docker(ctx, "ps", "-a", "-q", "--filter", "network="+network,
			"--filter", "label="+runner.LabelInstance)
		if f := strings.Fields(attached); len(f) > 0 {
			t.Errorf("function containers left on the network: %v", f)
			_, _ = docker(ctx, append([]string{"rm", "-f"}, f...)...)
		}
		if _, rmErr := docker(ctx, "network", "rm", network); rmErr != nil {
			t.Errorf("remove network: %v", rmErr)
		}
	})

	svc := startServiceContainer(t, network, suffix)
	c := lambda.New(lambda.Options{
		Region:           region,
		BaseEndpoint:     aws.String(svc.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})

	name := "net-" + ids.Hex(4)
	createFunction(t, c, name, "env", nil)
	var got struct {
		Env map[string]string `json:"env"`
	}
	invokeOK(t, c, name, map[string]string{}, &got)
	requireContains(t, got.Env["AWS_LAMBDA_RUNTIME_API"], "functions:9061/",
		"the Runtime API the function was given")

	requireOnNetworkAlone(t, name, network)

	// Shut down as `docker stop` does, the service removes the function's
	// containers by label as it does elsewhere.
	svc.Stop(t)
	left, err := docker(t.Context(), "ps", "-a", "-q",
		"--filter", "label="+runner.LabelFunction+"="+name)
	requireNoErr(t, err, "list the function's containers after shutdown")
	if f := strings.Fields(left); len(f) > 0 {
		t.Errorf("containers left after shutdown: %v", f)
		_, _ = docker(context.Background(), append([]string{"rm", "-f"}, f...)...)
	}
}

// requireOnNetworkAlone fails unless the function has one live container,
// attached to network and no other, with no extra hosts.
func requireOnNetworkAlone(t *testing.T, function, network string) {
	t.Helper()
	listed, err := docker(t.Context(), "ps", "-q", "--no-trunc",
		"--filter", "label="+runner.LabelFunction+"="+function)
	requireNoErr(t, err, "list the function's containers")
	containers := strings.Fields(listed)
	requireEqual(t, len(containers), 1, "the function's warm containers")
	out, err := docker(t.Context(), "inspect", "--format",
		"{{json .NetworkSettings.Networks}} {{json .HostConfig.ExtraHosts}}", containers[0])
	requireNoErr(t, err, "inspect the function's container")
	networksJSON, extraHosts, _ := strings.Cut(strings.TrimSpace(out), " ")
	var networks map[string]json.RawMessage
	unmarshal(t, []byte(networksJSON), &networks)
	attached := make([]string, 0, len(networks))
	for n := range networks {
		attached = append(attached, n)
	}
	requireSlice(t, attached, []string{network}, "the function container's networks")
	if extraHosts != "null" && extraHosts != "[]" {
		t.Errorf("the function container has extra hosts %s, want none", extraHosts)
	}
}

// serviceContainer is the service under test run as a container.
type serviceContainer struct {
	name    string
	URL     string
	stopped bool
}

// serviceSocket is the daemon's socket as a container mounts it: the one
// the docker CLI talks to on Linux, and the one inside Docker Desktop's VM.
const serviceSocket = "/var/run/docker.sock"

// startServiceContainer builds the service's image and runs it on network,
// aliased functions, with the settings the network mode needs, and waits
// for it to be ready. It is removed, with its image, when the test ends.
func startServiceContainer(t *testing.T, network, suffix string) *serviceContainer {
	t.Helper()
	img := buildServiceImage(t, suffix)
	s := &serviceContainer{name: "tule-functions-e2e-svc-" + suffix}
	_, err := docker(t.Context(), "run", "-d", "--name", s.name,
		"--label", "dev.tule.e2e.run="+runID,
		"--network", network, "--network-alias", "functions",
		"-p", "127.0.0.1::9060",
		"-v", serviceSocket+":"+serviceSocket,
		"-e", "TULE_GasEnv=development",
		"-e", "TULE_Auth_AccessKeyID=test",
		"-e", "TULE_Auth_SecretAccessKey=test",
		"-e", "TULE_Store_Path=/work/data/functions.db",
		"-e", "TULE_Functions_ContainerNetwork="+network,
		"-e", "TULE_Functions_RuntimeAPIHost=functions",
		"-e", "TULE_Functions_RuntimeAPIBind=0.0.0.0",
		img)
	requireNoErr(t, err, "run the service")
	t.Cleanup(func() {
		ctx := context.Background()
		s.Stop(t)
		if t.Failed() {
			logs, _ := exec.CommandContext(ctx, //nolint:gosec // G204: this test's container
				"docker", "logs", s.name).CombinedOutput()
			t.Logf("service logs:\n%s", logs)
		}
		if _, rmErr := docker(ctx, "rm", "-f", s.name); rmErr != nil {
			t.Errorf("remove the service container: %v", rmErr)
		}
	})

	addr, err := docker(t.Context(), "port", s.name, "9060/tcp")
	requireNoErr(t, err, "find the Lambda API's published port")
	s.URL = "http://" + strings.TrimSpace(strings.Split(addr, "\n")[0])
	s.waitReady(t)
	return s
}

// buildServiceImage builds the service as a static linux binary for the
// host's architecture and an image FROM scratch around it, never pulling,
// and removes the image when the test ends. The service runs as root in
// it, which reaches the mounted socket whatever its group.
func buildServiceImage(t *testing.T, suffix string) string {
	t.Helper()
	dir := filepath.Join(workDir, "service-image-"+suffix)
	requireNoErr(t, os.MkdirAll(dir, 0o750), "make the service's image directory")
	bin := filepath.Join(dir, "tule-functions")
	//nolint:gosec // G204: go build of this module into this run's directory
	build := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", bin, "./cmd")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the service: %v\n%s", err, out)
	}
	// gas/config refuses to read .env from /, so the service starts in
	// /work.
	dockerfile := "FROM scratch\nCOPY tule-functions /tule-functions\nWORKDIR /work\n" +
		"ENTRYPOINT [\"/tule-functions\"]\n"
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600),
		"write the service's Dockerfile")
	img := "tule-functions-e2e/service:" + suffix
	_, err := docker(t.Context(), "build", "--pull=false", "-q",
		"--label", "dev.tule.e2e.run="+runID, "-t", img, dir)
	requireNoErr(t, err, "build the service image")
	t.Cleanup(func() {
		if _, rmErr := docker(context.Background(), "rmi", "-f", img); rmErr != nil {
			t.Errorf("remove the service image: %v", rmErr)
		}
	})
	return img
}

// waitReady polls the readiness probe until it answers 200, and fails at
// once if the container stops.
func (s *serviceContainer) waitReady(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(clientTimeout)
	for time.Now().Before(deadline) {
		state, err := docker(t.Context(), "inspect", "--format", "{{.State.Status}}", s.name)
		requireNoErr(t, err, "inspect the service container")
		if st := strings.TrimSpace(state); st != "running" {
			t.Fatalf("the service container is %s before it was ready", st)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.URL+"/_ready", nil)
		requireNoErr(t, err, "build readiness request")
		if res, err := client.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the service was not ready within %v", clientTimeout)
}

// Stop stops the container as `docker stop` does, SIGTERM and then, past
// the service's shutdown timeout, SIGKILL, and fails the test unless the
// service exited of itself with 0. It is idempotent.
func (s *serviceContainer) Stop(t *testing.T) {
	t.Helper()
	if s.stopped {
		return
	}
	s.stopped = true
	ctx := context.Background()
	_, err := docker(ctx, "stop", "-t", "15", s.name)
	requireNoErr(t, err, "stop the service")
	code, err := docker(ctx, "inspect", "--format", "{{.State.ExitCode}}", s.name)
	requireNoErr(t, err, "inspect the stopped service")
	if c := strings.TrimSpace(code); c != "0" {
		t.Errorf("the service exited with %s, want 0", c)
	}
}
