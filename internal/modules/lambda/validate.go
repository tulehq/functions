package lambda

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/lambdaapi"
)

// constraint is the ValidationException Lambda answers a member outside
// the model's constraints with.
func constraint(member, rule string) error {
	return lambdaapi.ErrValidation(fmt.Sprintf(
		"1 validation error detected: Value at '%s' failed to satisfy constraint: Member must %s",
		member, rule))
}

const errRuntimeOrHandler = "Please don't provide Handler or Runtime or Layer when the " +
	"intended function PackageType is Image."

// checkCode checks a CreateFunction request's package type and code, and
// returns its image URI. Only container images are served: a Zip function,
// which is what a request without a PackageType asks for, is refused as an
// unsupported value.
func checkCode(req *lambdaapi.CreateFunctionRequest) (string, error) {
	if err := checkPackageType(req.PackageType); err != nil {
		return "", err
	}
	if req.Runtime != nil || req.Handler != nil {
		return "", lambdaapi.ErrInvalidParameter(errRuntimeOrHandler)
	}
	if req.Code == nil || deref(req.Code.ImageURI) == "" {
		return "", lambdaapi.ErrInvalidParameter("Please provide ImageUri when creating a " +
			"function with packageType Image.")
	}
	if req.Code.ZipFile != nil || req.Code.S3Bucket != nil || req.Code.S3Key != nil {
		return "", lambdaapi.ErrInvalidParameter("Please don't provide code as a zip file or " +
			"from S3 when creating a function with packageType Image.")
	}
	return *req.Code.ImageURI, checkImageURI(*req.Code.ImageURI)
}

// checkImageURI holds an image URI to Docker's reference grammar,
// name[:tag][@digest].
func checkImageURI(uri string) error {
	if _, err := docker.ParseReference(uri); err != nil {
		return lambdaapi.ErrInvalidParameter("Source image " + uri + " is not valid. " +
			"Provide a valid image reference, name[:tag][@digest].")
	}
	return nil
}

func checkPackageType(packageType *string) error {
	switch deref(packageType) {
	case "Image":
		return nil
	case "", "Zip":
		return lambdaapi.ErrInvalidParameter("The PackageType Zip is not supported: " +
			"this service runs container images only. Create the function with PackageType " +
			"Image and Code.ImageUri.")
	default:
		return lambdaapi.ErrValidation(fmt.Sprintf("1 validation error detected: Value '%s' "+
			"at 'packageType' failed to satisfy constraint: Member must satisfy enum value "+
			"set: [Zip, Image]", deref(packageType)))
	}
}

var rolePattern = regexp.MustCompile(
	`^arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/?[a-zA-Z_0-9+=,.@\-_/]+$`,
)

// checkRole holds a role, recorded and never assumed, to the model's
// pattern.
func checkRole(role *string, required bool) error {
	if role == nil {
		if required {
			return lambdaapi.ErrValidation("1 validation error detected: Value null at 'role' " +
				"failed to satisfy constraint: Member must not be null")
		}
		return nil
	}
	if !rolePattern.MatchString(*role) {
		return constraint("role", "satisfy regular expression pattern: "+rolePattern.String())
	}
	return nil
}

func checkArchitectures(archs []string) error {
	if len(archs) != 1 {
		return constraint("architectures", "have length equal to 1")
	}
	if archs[0] != "x86_64" && archs[0] != "arm64" {
		return constraint("architectures", "satisfy enum value set: [x86_64, arm64]")
	}
	return nil
}

var (
	envNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]+$`)
	tagPattern     = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`)
)

// reservedEnv are the variables Lambda defines, which a function cannot
// set: the developer guide's reserved environment variables.
var reservedEnv = []string{
	"_HANDLER", "_X_AMZN_TRACE_ID", "AWS_DEFAULT_REGION", "AWS_REGION", "AWS_EXECUTION_ENV",
	"AWS_LAMBDA_FUNCTION_NAME", "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
	"AWS_LAMBDA_FUNCTION_VERSION", "AWS_LAMBDA_INITIALIZATION_TYPE",
	"AWS_LAMBDA_LOG_GROUP_NAME", "AWS_LAMBDA_LOG_STREAM_NAME", "AWS_ACCESS_KEY",
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
	"AWS_LAMBDA_RUNTIME_API", "LAMBDA_TASK_ROOT", "LAMBDA_RUNTIME_DIR",
	"AWS_LAMBDA_MAX_CONCURRENCY", "AWS_LAMBDA_METADATA_API", "AWS_LAMBDA_METADATA_TOKEN",
}

// maxEnvSize is the 4 KB the environment variables may take, measured as
// their JSON.
const maxEnvSize = 4096

// checkEnvironment holds the variables to the developer guide's rules: a
// key starts with a letter, is at least two characters of letters, digits
// and underscores, and is not reserved, and all of them take at most 4 KB.
func checkEnvironment(vars map[string]string) error {
	var reserved []string
	for k := range vars {
		if !envNamePattern.MatchString(k) {
			return constraint("environment.variables",
				"satisfy regular expression pattern: [a-zA-Z]([a-zA-Z0-9_])+")
		}
		if slices.Contains(reservedEnv, k) {
			reserved = append(reserved, k)
		}
	}
	if len(reserved) > 0 {
		sort.Strings(reserved)
		return lambdaapi.ErrInvalidParameter("Lambda was unable to configure your environment " +
			"variables because the environment variables you have provided contains reserved " +
			"keys that are currently not supported for modification. Reserved keys used in " +
			"this request: " + strings.Join(reserved, ", "))
	}
	b, err := json.Marshal(vars)
	if err != nil {
		return fmt.Errorf("encode the environment: %w", err)
	}
	if len(b) > maxEnvSize {
		return lambdaapi.ErrInvalidParameter(fmt.Sprintf("Lambda was unable to configure your "+
			"environment variables because the environment variables you have provided "+
			"exceeded the 4KB limit. String measured: %s", b))
	}
	return nil
}

// maxTags is how many tags a resource may have.
const maxTags = 50

// checkTags holds tags to the model's key and value constraints.
func checkTags(tags map[string]string) error {
	if len(tags) > maxTags {
		return lambdaapi.ErrInvalidParameter(fmt.Sprintf(
			"A resource can have at most %d tags.", maxTags))
	}
	for k, v := range tags {
		if n := utf8.RuneCountInString(k); n < 1 || n > 128 || !tagPattern.MatchString(k) {
			return constraint("tags.key", "have length between 1 and 128 and satisfy "+
				"regular expression pattern: ([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)")
		}
		if utf8.RuneCountInString(v) > 256 || !tagPattern.MatchString(v) {
			return constraint("tags.value", "have length less than or equal to 256 and "+
				"satisfy regular expression pattern: ([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)")
		}
	}
	return nil
}
