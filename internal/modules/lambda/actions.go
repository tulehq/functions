package lambda

// The IAM authorization of every routed operation: its action and the
// resource type it is evaluated on, from the Service Authorization
// Reference for AWS Lambda
// (https://servicereference.us-east-1.amazonaws.com/v1/lambda/lambda.json,
// and https://docs.aws.amazon.com/service-authorization/latest/reference/list_awslambda.html).
// The action is the operation's name with the lambda: prefix, but for
// Invoke, which is lambda:InvokeFunction (the Lambda Developer Guide,
// "Fine-tuning the Resources and Conditions sections of policies").
//
// Some operations need further actions, which the reference lists among
// the operation's authorized actions:
//   - CreateFunction and UpdateFunctionConfiguration with a Role need
//     iam:PassRole on that role, with iam:PassedToService
//     lambda.amazonaws.com.
//   - CreateFunction and CreateEventSourceMapping with Tags need
//     lambda:TagResource on the new resource.
//
// The condition keys each operation supplies are the ones the reference
// lists for it that the service has: aws:ResourceTag/<key> from the tags of
// the function or mapping acted on, aws:RequestTag/<key> and aws:TagKeys
// from the request's tags, and lambda:FunctionArn for the event source
// mapping operations.

// resourceType is what an operation is evaluated on.
type resourceType int

const (
	// onAll is "*": the reference lists no resource type for the action.
	onAll resourceType = iota + 1
	// onFunction is the function's ARN,
	// arn:aws:lambda:<region>:<account>:function:<name>, with the
	// qualifier the request gives, if any.
	onFunction
	// onMapping is the event source mapping's ARN,
	// arn:aws:lambda:<region>:<account>:event-source-mapping:<UUID>.
	onMapping
	// onTagged is the function or mapping ARN the tagging request names.
	onTagged
)

// operation is how a routed operation is authorized.
type operation struct {
	action   string
	resource resourceType
}

// operations maps every routed operation, by its SDK name, to its action.
var operations = map[string]operation{
	"CreateFunction":              {"lambda:CreateFunction", onFunction},
	"ListFunctions":               {"lambda:ListFunctions", onAll},
	"GetFunction":                 {"lambda:GetFunction", onFunction},
	"DeleteFunction":              {"lambda:DeleteFunction", onFunction},
	"GetFunctionConfiguration":    {"lambda:GetFunctionConfiguration", onFunction},
	"UpdateFunctionConfiguration": {"lambda:UpdateFunctionConfiguration", onFunction},
	"UpdateFunctionCode":          {"lambda:UpdateFunctionCode", onFunction},
	"Invoke":                      {"lambda:InvokeFunction", onFunction},
	"TagResource":                 {"lambda:TagResource", onTagged},
	"UntagResource":               {"lambda:UntagResource", onTagged},
	"ListTags":                    {"lambda:ListTags", onTagged},
	"CreateEventSourceMapping":    {"lambda:CreateEventSourceMapping", onAll},
	"ListEventSourceMappings":     {"lambda:ListEventSourceMappings", onAll},
	"GetEventSourceMapping":       {"lambda:GetEventSourceMapping", onMapping},
	"UpdateEventSourceMapping":    {"lambda:UpdateEventSourceMapping", onMapping},
	"DeleteEventSourceMapping":    {"lambda:DeleteEventSourceMapping", onMapping},
}

// The further actions some operations need.
const (
	actionPassRole    = "iam:PassRole"
	actionTagResource = "lambda:TagResource"
)

// The service principal iam:PassRole passes a role to, as
// iam:PassedToService.
const lambdaServicePrincipal = "lambda.amazonaws.com"

// The condition keys the service supplies beside the global ones.
const (
	keyFunctionARN     = "lambda:FunctionArn"
	keyTagKeys         = "aws:TagKeys"
	keyPassedToService = "iam:PassedToService"
	prefixRequestTag   = "aws:RequestTag/"
	prefixResourceTag  = "aws:ResourceTag/"
)
