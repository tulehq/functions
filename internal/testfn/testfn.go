// Package testfn builds the function image the tests run: the aws-lambda-go
// program in ./fn, compiled for Linux on the host's architecture and copied
// into an image FROM scratch. Building FROM scratch pulls nothing.
package testfn

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"tule.dev/functions/internal/ids"
)

// sourceDir is the directory of ./fn, found from this file's own path.
func sourceDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "fn")
}

// Image builds a fresh image of the test function, tagged uniquely, and
// removes it when the test ends. It skips the test when docker is not on
// PATH.
func Image(t testing.TB) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "fn")
	// The arguments are this package's own: a temporary directory and a
	// tag it made.
	build := exec.Command("go", "build", "-o", bin, ".") //nolint:gosec // see above
	build.Dir = sourceDir()
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the test function: %v\n%s", err, out)
	}
	dockerfile := "FROM scratch\nCOPY fn /fn\nENTRYPOINT [\"/fn\"]\n"
	if err := os.WriteFile(
		filepath.Join(dir, "Dockerfile"),
		[]byte(dockerfile),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	tag := "tule-functions-test:" + ids.Hex(6)
	cmd := exec.Command("docker", "build", "-q", "-t", tag, dir) //nolint:gosec // see above
	if out, bErr := cmd.CombinedOutput(); bErr != nil {
		t.Fatalf("docker build: %v\n%s", bErr, out)
	}
	t.Cleanup(func() {
		rmi := exec.Command("docker", "rmi", "-f", tag) //nolint:gosec // see above
		out, rErr := rmi.CombinedOutput()
		if rErr != nil {
			t.Errorf("docker rmi %s: %v\n%s", tag, rErr, out)
		}
	})
	return tag
}
