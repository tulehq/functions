//go:build e2e

package e2e

import (
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func TestCreateFunction(t *testing.T) {
	c, _ := newClient(t)

	in := createInput("hello", "echo")
	in.Description = aws.String("says hello")
	in.Timeout = aws.Int32(10)
	in.MemorySize = aws.Int32(256)
	in.Environment = &types.Environment{Variables: map[string]string{"GREETING": "hi"}}
	in.Tags = map[string]string{"team": "core"}
	out, err := c.CreateFunction(t.Context(), in)
	requireNoErr(t, err, "create function")

	requireEqual(t, aws.ToString(out.FunctionName), "hello", "FunctionName")
	requireEqual(t, aws.ToString(out.FunctionArn), functionARN("hello"), "FunctionArn")
	requireEqual(t, out.PackageType, types.PackageTypeImage, "PackageType")
	requireEqual(t, aws.ToString(out.Version), "$LATEST", "Version")
	requireEqual(t, aws.ToString(out.Role), role, "Role")
	requireEqual(t, aws.ToString(out.Description), "says hello", "Description")
	requireEqual(t, aws.ToInt32(out.Timeout), int32(10), "Timeout")
	requireEqual(t, aws.ToInt32(out.MemorySize), int32(256), "MemorySize")
	requireSlice(t, archNames(out.Architectures), []string{hostArch()}, "Architectures")
	// Function states: Pending while the image is checked, then Active.
	if out.State != types.StatePending && out.State != types.StateActive {
		t.Fatalf("State after create: %q, want Pending or Active", out.State)
	}

	got := waitActive(t, c, "hello")
	cfg := got.Configuration
	requireEqual(t, cfg.State, types.StateActive, "State")
	requireEqual(t, cfg.LastUpdateStatus, types.LastUpdateStatusSuccessful, "LastUpdateStatus")
	requireEqual(t, aws.ToString(cfg.FunctionArn), functionARN("hello"), "GetFunction FunctionArn")
	requireEqual(t, cfg.Environment.Variables["GREETING"], "hi", "Environment")
	requireEqual(t, aws.ToString(got.Code.ImageUri), image("echo"), "Code.ImageUri")
	requireEqual(t, got.Tags["team"], "core", "GetFunction Tags")

	gc := getConfig(t, c, "hello")
	requireEqual(
		t,
		aws.ToString(gc.FunctionArn),
		functionARN("hello"),
		"GetConfiguration FunctionArn",
	)
	requireEqual(t, aws.ToInt32(gc.MemorySize), int32(256), "GetConfiguration MemorySize")
	requireEqual(t, gc.State, types.StateActive, "GetConfiguration State")

	// "Name formats": the function ARN names the function as well.
	_, err = c.GetFunction(t.Context(), &lambda.GetFunctionInput{
		FunctionName: aws.String(functionARN("hello")),
	})
	requireNoErr(t, err, "get function by ARN")
}

func TestCreateFunctionDefaults(t *testing.T) {
	// CreateFunction (API reference): Timeout "The default is 3 seconds",
	// MemorySize "The default value is 128 MB".
	c, _ := newClient(t)
	createFunction(t, c, "plain", "echo", nil)
	cfg := getConfig(t, c, "plain")
	requireEqual(t, aws.ToInt32(cfg.Timeout), int32(3), "default Timeout")
	requireEqual(t, aws.ToInt32(cfg.MemorySize), int32(128), "default MemorySize")
}

func TestCreateFunctionConflict(t *testing.T) {
	// ResourceConflictException: "The resource already exists" (409).
	c, _ := newClient(t)
	createFunction(t, c, "twice", "echo", nil)
	err := errOf(c.CreateFunction(t.Context(), createInput("twice", "env")))
	requireModeled[*types.ResourceConflictException](t, err)
	got := waitActive(t, c, "twice")
	requireEqual(
		t,
		aws.ToString(got.Code.ImageUri),
		image("echo"),
		"image after the refused create",
	)
}

func TestMissingFunction(t *testing.T) {
	// ResourceNotFoundException: "The resource specified in the request does
	// not exist" (404), on every operation that names a function.
	c, _ := newClient(t)
	name := aws.String("nobody")
	ctx := t.Context()
	for op, err := range map[string]error{
		"GetFunction": errOf(c.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: name})),
		"GetFunctionConfiguration": errOf(c.GetFunctionConfiguration(ctx,
			&lambda.GetFunctionConfigurationInput{FunctionName: name})),
		"DeleteFunction": errOf(c.DeleteFunction(ctx,
			&lambda.DeleteFunctionInput{FunctionName: name})),
		"Invoke": errOf(c.Invoke(ctx, &lambda.InvokeInput{FunctionName: name})),
		"UpdateFunctionConfiguration": errOf(c.UpdateFunctionConfiguration(ctx,
			&lambda.UpdateFunctionConfigurationInput{FunctionName: name, Timeout: aws.Int32(5)})),
		"UpdateFunctionCode": errOf(c.UpdateFunctionCode(ctx, &lambda.UpdateFunctionCodeInput{
			FunctionName: name, ImageUri: aws.String(image("echo")),
		})),
	} {
		t.Run(op, func(t *testing.T) {
			requireModeled[*types.ResourceNotFoundException](t, err)
		})
	}
}

func TestListFunctionsPagination(t *testing.T) {
	// ListFunctions pages with Marker and MaxItems; the last page has no
	// NextMarker.
	c, _ := newClient(t)
	names := []string{"alpha", "bravo", "charlie"}
	for _, n := range names {
		createFunction(t, c, n, "echo", nil)
	}

	p := lambda.NewListFunctionsPaginator(c, &lambda.ListFunctionsInput{MaxItems: aws.Int32(2)})
	var listed []string
	var sizes []int
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list functions")
		sizes = append(sizes, len(page.Functions))
		for _, f := range page.Functions {
			listed = append(listed, aws.ToString(f.FunctionName))
			requireEqual(t, aws.ToString(f.FunctionArn), functionARN(aws.ToString(f.FunctionName)),
				"listed FunctionArn")
			requireEqual(t, f.PackageType, types.PackageTypeImage, "listed PackageType")
		}
		if len(sizes) > 10 {
			t.Fatal("the marker did not end after 10 pages")
		}
	}
	if !slices.Equal(sizes, []int{2, 1}) {
		t.Fatalf("page sizes %v, want [2 1]", sizes)
	}
	requireSameSet(t, listed, names, "listed functions")
}

func TestUpdateFunctionConfiguration(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "conf", "env", func(in *lambda.CreateFunctionInput) {
		in.Environment = &types.Environment{Variables: map[string]string{"OLD": "1", "KEEP": "a"}}
	})

	out, err := c.UpdateFunctionConfiguration(t.Context(), &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String("conf"),
		Description:  aws.String("updated"),
		Timeout:      aws.Int32(7),
		MemorySize:   aws.Int32(512),
		Environment: &types.Environment{
			Variables: map[string]string{"KEEP": "b", "NEW": "2"},
		},
	})
	requireNoErr(t, err, "update configuration")
	if s := out.LastUpdateStatus; s != types.LastUpdateStatusInProgress &&
		s != types.LastUpdateStatusSuccessful {
		t.Fatalf("LastUpdateStatus after update: %q, want InProgress or Successful", s)
	}

	cfg := waitUpdated(t, c, "conf").Configuration
	requireEqual(t, aws.ToString(cfg.Description), "updated", "Description")
	requireEqual(t, aws.ToInt32(cfg.Timeout), int32(7), "Timeout")
	requireEqual(t, aws.ToInt32(cfg.MemorySize), int32(512), "MemorySize")

	// "the entire contents of the Variables structure is replaced"
	// (Working with Lambda environment variables).
	var r envResult
	invokeOK(t, c, "conf", map[string]any{}, &r)
	requireEqual(t, r.Env["KEEP"], "b", "KEEP after the update")
	requireEqual(t, r.Env["NEW"], "2", "NEW after the update")
	if v, ok := r.Env["OLD"]; ok {
		t.Fatalf("OLD=%q survived the update that replaced the variables", v)
	}
	requireEqual(
		t,
		r.Env["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"],
		"512",
		"memory size the function sees",
	)
}

func TestUpdateFunctionCode(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "swap", "echo", nil)
	invokeOK(t, c, "swap", map[string]string{"v": "1"}, nil)

	out, err := c.UpdateFunctionCode(t.Context(), &lambda.UpdateFunctionCodeInput{
		FunctionName: aws.String("swap"),
		ImageUri:     aws.String(image("env")),
	})
	requireNoErr(t, err, "update code")
	requireEqual(t, aws.ToString(out.FunctionName), "swap", "FunctionName")

	got := waitUpdated(t, c, "swap")
	requireEqual(t, aws.ToString(got.Code.ImageUri), image("env"), "Code.ImageUri")

	// The new image answers: env returns its environment, echo would have
	// returned the payload.
	var r envResult
	invokeOK(t, c, "swap", map[string]string{"v": "1"}, &r)
	requireEqual(t, r.Env["AWS_LAMBDA_FUNCTION_NAME"], "swap", "the new image's answer")
}

func TestTags(t *testing.T) {
	// TagResource, ListTags and UntagResource on the function ARN.
	c, _ := newClient(t)
	createFunction(t, c, "tagged", "echo", func(in *lambda.CreateFunctionInput) {
		in.Tags = map[string]string{"a": "1"}
	})
	arn := aws.String(functionARN("tagged"))

	_, err := c.TagResource(t.Context(), &lambda.TagResourceInput{
		Resource: arn, Tags: map[string]string{"b": "2", "c": "3"},
	})
	requireNoErr(t, err, "tag")
	requireTags(t, c, arn, map[string]string{"a": "1", "b": "2", "c": "3"})

	_, err = c.UntagResource(t.Context(), &lambda.UntagResourceInput{
		Resource: arn, TagKeys: []string{"a", "c"},
	})
	requireNoErr(t, err, "untag")
	requireTags(t, c, arn, map[string]string{"b": "2"})

	err = errOf(c.ListTags(t.Context(), &lambda.ListTagsInput{
		Resource: aws.String(functionARN("nobody")),
	}))
	requireModeled[*types.ResourceNotFoundException](t, err)
}

func requireTags(t *testing.T, c *lambda.Client, arn *string, want map[string]string) {
	t.Helper()
	out, err := c.ListTags(t.Context(), &lambda.ListTagsInput{Resource: arn})
	requireNoErr(t, err, "list tags")
	if len(out.Tags) != len(want) {
		t.Fatalf("tags %v, want %v", out.Tags, want)
	}
	for k, v := range want {
		requireEqual(t, out.Tags[k], v, "tag "+k)
	}
}

func TestDeleteFunction(t *testing.T) {
	c, _ := newClient(t)
	createFunction(t, c, "gone", "echo", nil)
	invokeOK(t, c, "gone", map[string]string{}, nil)
	deleteFunction(t, c, "gone")

	err := errOf(
		c.GetFunction(t.Context(), &lambda.GetFunctionInput{FunctionName: aws.String("gone")}),
	)
	requireModeled[*types.ResourceNotFoundException](t, err)
	out, err := c.ListFunctions(t.Context(), &lambda.ListFunctionsInput{})
	requireNoErr(t, err, "list functions")
	requireEqual(t, len(out.Functions), 0, "functions after the delete")
}

func TestMissingImageFailsTheFunction(t *testing.T) {
	// The design's states: Failed with a reason when the image cannot be
	// used, which the FunctionActiveV2 waiter reports as a failure. The
	// image names a registry on a closed local port, so no pull could ever
	// fetch anything.
	c, _ := newClient(t)
	in := createInput("broken", "echo")
	in.Code.ImageUri = aws.String("127.0.0.1:1/tule-functions-e2e/missing:" + runID)
	_, err := c.CreateFunction(t.Context(), in)
	requireNoErr(t, err, "create function with a missing image")

	w := lambda.NewFunctionActiveV2Waiter(c, func(o *lambda.FunctionActiveV2WaiterOptions) {
		o.MinDelay, o.MaxDelay = 100*time.Millisecond, time.Second
	})
	err = w.Wait(
		t.Context(),
		&lambda.GetFunctionInput{FunctionName: aws.String("broken")},
		waitTimeout,
	)
	if err == nil {
		t.Fatal("FunctionActiveV2 succeeded for a function whose image is missing")
	}
	requireContains(t, err.Error(), "transitioned to Failure", "waiter error")

	cfg := getConfig(t, c, "broken")
	requireEqual(t, cfg.State, types.StateFailed, "State")
	if aws.ToString(cfg.StateReason) == "" {
		t.Fatal("a Failed function has no StateReason")
	}
	// Assumption: the code is one the model lists; which one is not settled.
	if !slices.Contains(cfg.StateReasonCode.Values(), cfg.StateReasonCode) {
		t.Fatalf("StateReasonCode %q is not in the model's enum", cfg.StateReasonCode)
	}
}

func TestZipPackageIsRefused(t *testing.T) {
	// The design: Zip "answers as AWS does for an unsupported value", which
	// is InvalidParameterValueException, "One of the parameters in the
	// request is not valid" (400). Nothing is created.
	c, _ := newClient(t)
	_, err := c.CreateFunction(t.Context(), &lambda.CreateFunctionInput{
		FunctionName: aws.String("zipped"),
		PackageType:  types.PackageTypeZip,
		Runtime:      types.RuntimeProvidedal2023,
		Handler:      aws.String("bootstrap"),
		Code:         &types.FunctionCode{ZipFile: []byte("PK\x05\x06" + string(make([]byte, 18)))},
		Role:         aws.String(role),
	})
	requireModeled[*types.InvalidParameterValueException](t, err)
	err = errOf(
		c.GetFunction(t.Context(), &lambda.GetFunctionInput{FunctionName: aws.String("zipped")}),
	)
	requireModeled[*types.ResourceNotFoundException](t, err)
}

func TestReservedEnvironmentKeyIsRefused(t *testing.T) {
	// "The keys for these environment variables are reserved and cannot be
	// set in your function configuration" (defined runtime environment
	// variables). Assumption: refused as InvalidParameterValueException,
	// the error for a parameter that is not valid; the page names no code.
	c, _ := newClient(t)
	in := createInput("reserved", "env")
	in.Environment = &types.Environment{Variables: map[string]string{"AWS_REGION": "eu-west-1"}}
	requireModeled[*types.InvalidParameterValueException](
		t,
		errOf(c.CreateFunction(t.Context(), in)),
	)
}

func archNames(as []types.Architecture) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, string(a))
	}
	return out
}
