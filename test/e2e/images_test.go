//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test functions are the Go handlers under testdata, built for linux on
// the host's architecture and each wrapped in an image built FROM scratch:
// no image is ever pulled. Every image is tagged for this run and removed,
// with any container left from it, when the run ends.

// workDir is this run's scratch directory: handler binaries, image build
// contexts and the sibling services' binaries.
var workDir string

// runID tells this run's images apart from any other run's.
var runID = strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.Itoa(os.Getpid())

// imageSources maps each image the tests use to the testdata handler in it.
// The cleanup images hold the echo handler under labels of their own, so
// each has its own image ID and Docker's ancestor filter finds only the
// containers made for the test that uses it.
var imageSources = map[string]string{
	"echo":           "echo",
	"env":            "env",
	"errors":         "errors",
	"panic":          "panic",
	"sleep":          "sleep",
	"sqs":            "sqs",
	"s3put":          "s3put",
	"cleanup-delete": "echo",
	"cleanup-stop":   "echo",
	"cleanup-update": "echo",
}

// image returns the reference of the test image name.
func image(name string) string {
	if _, ok := imageSources[name]; !ok {
		panic("no test image " + name)
	}
	return "tule-functions-e2e/" + name + ":" + runID
}

// hostArch is the architecture the images are built for and the functions
// are created with, in Lambda's names (Architectures: x86_64 or arm64).
func hostArch() string {
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}

func TestMain(m *testing.M) {
	work, err := os.MkdirTemp("", "tule-functions-e2e-")
	workDir = work
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: temp dir:", err)
		os.Exit(1)
	}
	if err = buildImages(work); err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		removeImages()
		_ = os.RemoveAll(work)
		os.Exit(1)
	}
	code := m.Run()
	removeImages()
	_ = os.RemoveAll(work)
	os.Exit(code)
}

// buildImages builds each handler once and each image from it.
func buildImages(work string) error {
	bins := map[string]string{}
	for _, src := range imageSources {
		if _, done := bins[src]; done {
			continue
		}
		bin, err := buildHandler(work, src)
		if err != nil {
			return err
		}
		bins[src] = bin
	}
	for name, src := range imageSources {
		if err := buildImage(work, name, bins[src]); err != nil {
			return err
		}
	}
	return nil
}

// buildHandler builds testdata/<src> as a static linux binary for the host
// architecture, with lambda.norpc since the functions use only the Runtime
// API. The handlers are a module of their own, so aws-lambda-go is theirs
// and not a requirement of functions.
func buildHandler(work, src string) (string, error) {
	out := filepath.Join(work, "bin", src, "bootstrap")
	//nolint:gosec // G204: go build of this suite's own testdata
	cmd := exec.Command("go", "build", "-tags", "lambda.norpc", "-trimpath", "-o", out, "./"+src)
	cmd.Dir = "testdata"
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build handler %s: %w\n%s", src, err, b)
	}
	return out, nil
}

// buildImage builds image name FROM scratch around bin, never pulling.
func buildImage(work, name, bin string) error {
	dir := filepath.Join(work, "images", name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("image dir %s: %w", name, err)
	}
	b, err := os.ReadFile(bin) //nolint:gosec // G304: the binary just built
	if err != nil {
		return fmt.Errorf("read %s: %w", bin, err)
	}
	//nolint:gosec // G306: the image's entrypoint must be executable
	if err = os.WriteFile(filepath.Join(dir, "bootstrap"), b, 0o755); err != nil {
		return fmt.Errorf("copy %s: %w", bin, err)
	}
	dockerfile := "FROM scratch\nCOPY bootstrap /bootstrap\nENTRYPOINT [\"/bootstrap\"]\n"
	if err = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		return fmt.Errorf("Dockerfile %s: %w", name, err)
	}
	_, err = docker(context.Background(), "build", "--pull=false", "-q",
		"--label", "dev.tule.e2e.run="+runID, "--label", "dev.tule.e2e.image="+name,
		"-t", image(name), dir)
	return err
}

// removeImages removes this run's containers and images. A container left
// here is a leak the cleanup tests report; this only keeps Docker tidy.
func removeImages() {
	ctx := context.Background()
	for name := range imageSources {
		ids, _ := docker(ctx, "ps", "-a", "-q", "--filter", "ancestor="+image(name))
		if f := strings.Fields(ids); len(f) > 0 {
			fmt.Fprintf(
				os.Stderr,
				"e2e: removing %d containers left from %s\n",
				len(f),
				image(name),
			)
			_, _ = docker(ctx, append([]string{"rm", "-f"}, f...)...)
		}
		_, _ = docker(ctx, "rmi", "-f", image(name))
	}
}

// docker runs the docker CLI against the local daemon and returns its
// standard output.
func docker(ctx context.Context, args ...string) (string, error) {
	//nolint:gosec // G204: the docker CLI, with this suite's own arguments
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

// containersOf returns the IDs of every container, running or not, created
// from the test image name.
func containersOf(t *testing.T, name string) []string {
	t.Helper()
	out, err := docker(
		t.Context(),
		"ps",
		"-a",
		"-q",
		"--no-trunc",
		"--filter",
		"ancestor="+image(name),
	)
	requireNoErr(t, err, "list containers of "+name)
	return strings.Fields(out)
}
