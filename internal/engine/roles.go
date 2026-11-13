package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"tule.dev/identity/servicerole"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/lambdaapi"
	"tule.dev/functions/internal/runner"
)

// lambdaPrincipal is the service principal a function's execution role is
// assumed as, the one the Lambda Developer Guide's execution role trust
// policy names.
const lambdaPrincipal = "lambda.amazonaws.com"

// ErrRoleNotAssumable is a function role identity reports missing, whose
// trust policy does not allow lambda.amazonaws.com, that identity refuses
// as malformed, or that is of another account.
var ErrRoleNotAssumable = errors.New("engine: the role cannot be assumed by Lambda")

// errNoRoles is a role session asked for without an identity to assume it
// through, which only a wiring fault produces.
var errNoRoles = errors.New("engine: no identity to assume roles through")

// assumeRole assumes the execution role role of the function name, at arn,
// as lambda.amazonaws.com, for an hour, identity's default, with the
// function's ARN and account as aws:SourceArn and aws:SourceAccount, as
// Lambda supplies them to the trust policy. A role of another account is
// never assumed, whatever the function stored: identity would assume it in
// its own account, and a role is passed only within its account.
func (e *Engine) assumeRole(
	ctx context.Context,
	role, name, arn string,
) (*servicerole.Session, error) {
	if e.roles == nil {
		return nil, errNoRoles
	}
	if !e.ownRole(role) {
		return nil, fmt.Errorf("%w: %s is not a role of account %s", ErrRoleNotAssumable,
			role, e.settings.AccountID)
	}
	s, err := e.roles.AssumeServiceRole(ctx, role, sessionName(name), lambdaPrincipal, 0,
		servicerole.WithSourceArn(arn), servicerole.WithSourceAccount(e.settings.AccountID))
	var refused *servicerole.Error
	if errors.Is(err, servicerole.ErrNoSuchRole) || errors.Is(err, servicerole.ErrNotTrusted) ||
		errors.As(err, &refused) && refused.Code == servicerole.CodeInvalidRequest {
		return nil, fmt.Errorf("%w: %s: %w", ErrRoleNotAssumable, role, err)
	}
	if err != nil {
		return nil, fmt.Errorf("engine: assume the role %s: %w", role, err)
	}
	return s, nil
}

// ownRole reports whether role is a role ARN of the service's account.
func (e *Engine) ownRole(role string) bool {
	return strings.HasPrefix(role, "arn:aws:iam::"+e.settings.AccountID+":role/")
}

// sessionName is the role session name of the function name: the name, as
// Lambda names its sessions of an execution role, padded to the two
// characters a session name needs at least (STS AssumeRole,
// RoleSessionName), which a one-character function name falls short of.
func sessionName(name string) string {
	if len(name) < 2 {
		return name + "_"
	}
	return name
}

// CheckRole fails with InvalidParameterValueException when the function
// name, at arn, could not run as role: the role does not exist, or its
// trust policy does not allow Lambda, as Lambda refuses CreateFunction and
// UpdateFunctionConfiguration with "The role defined for the function
// cannot be assumed by Lambda." It checks nothing unless the functions run
// with their roles' credentials.
func (e *Engine) CheckRole(ctx context.Context, role, name, arn string) error {
	if e.settings.FunctionCredentials != contracts.CredentialsRole {
		return nil
	}
	_, err := e.assumeRole(ctx, role, name, arn)
	if errors.Is(err, ErrRoleNotAssumable) {
		return lambdaapi.ErrInvalidParameter("The role defined for the function cannot be " +
			"assumed by Lambda.")
	}
	return err
}

// containerCredentials is the runner's Credentials in role mode: a fresh
// session of the container's function's role.
func (e *Engine) containerCredentials(ctx context.Context, spec *runner.Spec) (
	*runner.Credentials, error,
) {
	s, err := e.assumeRole(ctx, spec.Role, spec.Function, spec.ARN)
	if err != nil {
		return nil, err
	}
	return &runner.Credentials{
		Expiration:      s.Credentials.Expiration,
		AccessKeyID:     s.Credentials.AccessKeyID,
		SecretAccessKey: s.Credentials.SecretAccessKey,
		SessionToken:    s.Credentials.SessionToken,
	}, nil
}

// The times a mapping's role session is reused for: until it is within
// sessionMargin of its expiry, and for at most recheckRole before the
// function's role is read again, so a role changed on the function is
// polled with soon.
const (
	sessionMargin = 5 * time.Minute
	recheckRole   = time.Minute
)

// roleProvider is an aws.CredentialsProvider of a session of the current
// execution role of the function name, for its mapping's SQS calls: Lambda
// polls a queue with the function's execution role.
type roleProvider struct {
	session *servicerole.Session
	e       *Engine
	// now reads the time; nil is time.Now.
	now     func() time.Time
	checked time.Time
	name    string
	role    string
	mu      sync.Mutex
}

// Retrieve returns the session of the function's role, assuming the role
// again when the function's role has changed or the session nears expiry.
func (p *roleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.now != nil {
		now = p.now()
	}
	if p.session == nil || now.Sub(p.checked) >= recheckRole ||
		p.session.Credentials.Expiration.Sub(now) < sessionMargin {
		fn, err := p.e.store.GetFunction(ctx, p.name)
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("engine: read the role of %s: %w", p.name, err)
		}
		if p.session == nil || fn.Role != p.role ||
			p.session.Credentials.Expiration.Sub(now) < sessionMargin {
			s, aErr := p.e.assumeRole(ctx, fn.Role, fn.Name, fn.ARN)
			if aErr != nil {
				return aws.Credentials{}, aErr
			}
			p.session, p.role = s, fn.Role
		}
		p.checked = now
	}
	c := p.session.Credentials
	return aws.Credentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Source:          "tule functions execution role",
		CanExpire:       true,
		Expires:         c.Expiration.Add(-sessionMargin),
	}, nil
}
