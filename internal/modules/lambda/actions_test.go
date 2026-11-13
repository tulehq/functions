package lambda

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"tule.dev/functions/internal/contracts"
)

// reference is the part of the Service Authorization Reference for AWS
// Lambda the mapping is checked against: every action with its resource
// types and condition keys, the function and event source mapping resource
// types, and the authorized actions of each routed operation. It is
// testdata/lambda-reference.json, cut from the JSON its Source names.
type reference struct {
	Actions map[string]struct {
		Resources     []string
		ConditionKeys []string
	}
	Resources map[string]struct {
		ARNFormats    []string
		ConditionKeys []string
	}
	Operations map[string][]authorizedAction
	Source     string
	Version    string
}

// authorizedAction is an action the reference says an operation is
// authorized as, with the context it is authorized with.
type authorizedAction struct {
	Context map[string][]string
	Name    string
	Service string
}

func loadReference(t *testing.T) *reference {
	t.Helper()
	b, err := os.ReadFile("testdata/lambda-reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var ref reference
	if err = json.Unmarshal(b, &ref); err != nil {
		t.Fatal(err)
	}
	return &ref
}

func TestEveryRoutedOperationIsMapped(t *testing.T) {
	routed := map[string]bool{}
	for _, r := range (&Module{}).routes() {
		if _, ok := operations[r.op]; !ok {
			t.Errorf("%s (%s %s) has no IAM action", r.op, r.method, r.path)
		}
		routed[r.op] = true
	}
	for op := range operations {
		if !routed[op] {
			t.Errorf("%s is mapped but not routed", op)
		}
	}
}

func TestEveryMappedActionIsTheReferences(t *testing.T) {
	ref := loadReference(t)
	for op, o := range operations {
		name, ok := strings.CutPrefix(o.action, "lambda:")
		if !ok {
			t.Errorf("%s: %s is not a lambda action", op, o.action)
			continue
		}
		action, ok := ref.Actions[name]
		if !ok {
			t.Errorf("%s: %s is not in the reference", op, o.action)
			continue
		}
		authorized, ok := ref.Operations[op]
		if !ok {
			t.Errorf("%s: the reference lists no such operation", op)
		}
		if !slices.ContainsFunc(authorized, func(a authorizedAction) bool {
			return a.Service == "lambda" && a.Name == name
		}) {
			t.Errorf("%s: the reference does not authorize it as %s", op, o.action)
		}
		checkResourceType(t, op, o.resource, action.Resources)
	}
}

// checkResourceType checks the resource an operation is evaluated on against
// the resource types the reference lists for its action: none for "*", else
// each type the operation can act on.
func checkResourceType(t *testing.T, op string, got resourceType, listed []string) {
	t.Helper()
	want, ok := map[resourceType][]string{
		onAll:      nil,
		onFunction: {"function"},
		onMapping:  {"eventSourceMapping"},
		onTagged:   {"function", "eventSourceMapping"},
	}[got]
	if !ok {
		t.Errorf("%s: no resource type", op)
		return
	}
	if want == nil && len(listed) != 0 {
		t.Errorf("%s: evaluated on *, but the reference lists %v", op, listed)
	}
	for _, typ := range want {
		if !slices.Contains(listed, typ) {
			t.Errorf("%s: evaluated on a %s, but the reference lists %v", op, typ, listed)
		}
	}
}

// TestTheFurtherActionsAreTheReferences checks iam:PassRole and
// lambda:TagResource against the operations the reference authorizes them
// for.
func TestTheFurtherActionsAreTheReferences(t *testing.T) {
	ref := loadReference(t)
	has := func(op, service, name string) (map[string][]string, bool) {
		for _, a := range ref.Operations[op] {
			if a.Service == service && a.Name == name {
				return a.Context, true
			}
		}
		return nil, false
	}
	for _, op := range []string{"CreateFunction", "UpdateFunctionConfiguration"} {
		ctx, ok := has(op, "iam", "PassRole")
		if !ok {
			t.Errorf("%s: the reference does not authorize iam:PassRole", op)
		}
		if got := ctx[keyPassedToService]; !slices.Equal(got, []string{lambdaServicePrincipal}) {
			t.Errorf("%s: iam:PassedToService is %v", op, got)
		}
	}
	for _, op := range []string{"CreateFunction", "CreateEventSourceMapping"} {
		if _, ok := has(op, "lambda", strings.TrimPrefix(actionTagResource, "lambda:")); !ok {
			t.Errorf("%s: the reference does not authorize lambda:TagResource", op)
		}
	}
}

// TestTheConditionKeysAreTheReferences checks that each service key the
// service supplies is one the reference lists for the actions it is
// supplied to.
func TestTheConditionKeysAreTheReferences(t *testing.T) {
	ref := loadReference(t)
	supplied := map[string][]string{
		"CreateFunction":           {"aws:RequestTag/${TagKey}", keyTagKeys},
		"TagResource":              {"aws:RequestTag/${TagKey}", keyTagKeys},
		"UntagResource":            {keyTagKeys},
		"CreateEventSourceMapping": {"aws:RequestTag/${TagKey}", keyTagKeys, keyFunctionARN},
		"GetEventSourceMapping":    {keyFunctionARN},
		"UpdateEventSourceMapping": {keyFunctionARN},
		"DeleteEventSourceMapping": {keyFunctionARN},
	}
	for action, ks := range supplied {
		for _, k := range ks {
			if !slices.Contains(ref.Actions[action].ConditionKeys, k) {
				t.Errorf("%s: the reference lists no %s", action, k)
			}
		}
	}
	for _, typ := range []string{"function", "eventSourceMapping"} {
		if !slices.Contains(ref.Resources[typ].ConditionKeys, "aws:ResourceTag/${TagKey}") {
			t.Errorf("%s: the reference lists no aws:ResourceTag", typ)
		}
	}
}

func TestTheARNsAreTheReferences(t *testing.T) {
	ref := loadReference(t)
	s := &contracts.Settings{Region: "eu-west-1", AccountID: "123456789012"}
	fill := func(format, name, value string) string {
		r := strings.NewReplacer("${Partition}", "aws", "${Region}", s.Region,
			"${Account}", s.AccountID, "${"+name+"}", value)
		return r.Replace(format)
	}
	if got, want := s.FunctionARN("fn"),
		fill(ref.Resources["function"].ARNFormats[0], "FunctionName", "fn"); got != want {
		t.Errorf("FunctionARN = %s, want %s", got, want)
	}
	if got, want := s.MappingARN("u"),
		fill(ref.Resources["eventSourceMapping"].ARNFormats[0], "UUID", "u"); got != want {
		t.Errorf("MappingARN = %s, want %s", got, want)
	}
}
