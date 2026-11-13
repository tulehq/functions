//go:build e2e

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// baseImageEnv gates the one test that builds on an AWS base image. Building
// it pulls public.ecr.aws/lambda/provided:al2023, so only CI sets it.
const baseImageEnv = "TULE_E2E_AWS_BASE_IMAGE"

// awsBaseImage is the OS-only base image the Go guide deploys on (Deploy Go
// Lambda functions with container images).
const awsBaseImage = "public.ecr.aws/lambda/provided:al2023"

// The two layouts, both on the base image, which sets
// LAMBDA_RUNTIME_DIR=/var/runtime, WORKDIR /var/task and ENTRYPOINT
// /lambda-entrypoint.sh (Dockerfile.provided.al2023):
//   - runtime dir: the bootstrap in ${LAMBDA_RUNTIME_DIR}, run by the base
//     image's own entrypoint script with the handler name as CMD;
//   - Go guide: the binary as ./main and ENTRYPOINT ["./main"], the
//     Dockerfile the Go guide shows.
var baseImageLayouts = map[string]string{
	"runtime dir": "FROM " + awsBaseImage + "\n" +
		"COPY bootstrap ${LAMBDA_RUNTIME_DIR}/bootstrap\n" +
		"CMD [\"bootstrap\"]\n",
	"go guide": "FROM " + awsBaseImage + "\n" +
		"COPY bootstrap ./main\n" +
		"ENTRYPOINT [\"./main\"]\n",
}

// requireBaseImageGate skips the test unless CI asked for the base-image
// tests, which pull base.
func requireBaseImageGate(t *testing.T, base string) {
	t.Helper()
	if os.Getenv(baseImageEnv) != "1" {
		t.Skipf("set %s=1 to build on %s; it pulls that image, so only CI runs it",
			baseImageEnv, base)
	}
}

func TestAWSBaseImage(t *testing.T) {
	// The design's CI-only check: an image on AWS's own base image, with its
	// entrypoint and Amazon Linux userland, runs through the Runtime API,
	// whose address carries a path after host:port.
	requireBaseImageGate(t, awsBaseImage)

	bin, err := buildHandler(t.TempDir(), "echo")
	requireNoErr(t, err, "build the echo handler")
	handler, err := os.ReadFile(bin) //nolint:gosec // G304: the binary just built
	requireNoErr(t, err, "read the echo handler")
	c, _ := newClient(t)
	for layout, dockerfile := range baseImageLayouts {
		name := "base-" + strings.ReplaceAll(layout, " ", "-")
		t.Run(layout, func(t *testing.T) {
			ref := buildBaseImage(t, layout, map[string][]byte{
				"Dockerfile": []byte(dockerfile), "bootstrap": handler,
			})
			createFunction(t, c, name, "echo", func(in *lambda.CreateFunctionInput) {
				in.Code.ImageUri = aws.String(ref)
			})
			requireBaseImageInvocation(t, c, name, "echo: ")
		})
	}
}

// buildBaseImage builds an image from the files (a Dockerfile among them)
// for the host architecture and removes it, with any container left from
// it, when the test ends. Unlike the scratch images, it may pull its base
// image.
func buildBaseImage(t *testing.T, what string, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		mode := os.FileMode(0o644)
		if name == "bootstrap" {
			mode = 0o755
		}
		//nolint:gosec // G306: the image's files must be readable, the bootstrap executable
		requireNoErr(t, os.WriteFile(filepath.Join(dir, name), b, mode), "write "+name)
	}

	ref := "tule-functions-e2e/base-image:" + runID + "-" + filepath.Base(dir)
	_, err := docker(t.Context(), "build", "-q", "--platform", "linux/"+runtime.GOARCH,
		"--label", "dev.tule.e2e.run="+runID, "-t", ref, dir)
	requireNoErr(t, err, "build the "+what+" image")
	t.Cleanup(func() {
		ctx := context.Background()
		ids, _ := docker(ctx, "ps", "-a", "-q", "--filter", "ancestor="+ref)
		if f := strings.Fields(ids); len(f) > 0 {
			_, _ = docker(ctx, append([]string{"rm", "-f"}, f...)...)
		}
		_, _ = docker(ctx, "rmi", "-f", ref)
	})
	return ref
}

// requireBaseImageInvocation invokes name with LogType Tail and checks the
// echoed payload and the log lines, as TestInvokeTailLog does.
func requireBaseImageInvocation(t *testing.T, c *lambda.Client, name, output string) {
	t.Helper()
	payload := `{"from":"base image"}`
	out := invokeWith(t, c, &lambda.InvokeInput{
		FunctionName: aws.String(name),
		LogType:      types.LogTypeTail,
		Payload:      []byte(payload),
	})
	if out.FunctionError != nil {
		t.Fatalf("function error %q: %s", *out.FunctionError, out.Payload)
	}
	requireJSONEqual(t, out.Payload, payload, "echoed payload")
	log := decodeLog(t, out)
	requireContains(t, log, "START RequestId: ", "START line")
	requireContains(t, log, output, "the function's own output")
	requireContains(t, log, "END RequestId: ", "END line")
	if !reportLine.MatchString(log) {
		t.Fatalf("no REPORT line in the log:\n%s", log)
	}
}

// awsPythonImage is the AWS base image for Python 3.13 (Deploy Python
// Lambda functions with container images). Its runtime interface client is
// awslambdaric, AWS's own and independent of aws-lambda-go.
const awsPythonImage = "public.ecr.aws/lambda/python:3.13"

// pythonHandler echoes its event and prints a line first.
const pythonHandler = `import json


def handler(event, context):
    print("python: " + json.dumps(event), flush=True)
    return event
`

// pythonDockerfile follows the Python guide: the code copied to
// ${LAMBDA_TASK_ROOT} and CMD naming the handler as file.function.
const pythonDockerfile = "FROM " + awsPythonImage + "\n" +
	"COPY lambda_function.py ${LAMBDA_TASK_ROOT}\n" +
	"CMD [ \"lambda_function.handler\" ]\n"

func TestAWSPythonBaseImage(t *testing.T) {
	// An independent runtime interface client, awslambdaric, reaches the
	// Runtime API through the AWS_LAMBDA_RUNTIME_API functions gives it,
	// path after host:port included. If the client cannot use that address,
	// the invocation fails here.
	requireBaseImageGate(t, awsPythonImage)

	ref := buildBaseImage(t, "python", map[string][]byte{
		"Dockerfile":         []byte(pythonDockerfile),
		"lambda_function.py": []byte(pythonHandler),
	})
	c, _ := newClient(t)
	createFunction(t, c, "python", "echo", func(in *lambda.CreateFunctionInput) {
		in.Code.ImageUri = aws.String(ref)
		in.Timeout = aws.Int32(30)
	})
	requireBaseImageInvocation(t, c, "python", `python: {"from": "base image"}`)
}
