package contracts

import (
	"strings"
	"time"
)

// Settings configure how functions run: the Docker daemon, the Runtime API
// listener and the address the containers reach it at, the queues service
// the event source mappings poll, the account and region the ARNs carry,
// and the limits of the containers, the asynchronous retries and the
// history.
type Settings struct {
	FunctionAccessKeyID     string
	FunctionSecretAccessKey string
	QueuesEndpoint          string
	AccountID               string `validate:"required"`
	Region                  string `validate:"required"`
	DockerHost              string `validate:"required"`
	// FunctionCredentials is what the containers get as their AWS
	// credentials: the root key (CredentialsRoot), none (CredentialsNone),
	// or FunctionAccessKeyID and FunctionSecretAccessKey
	// (CredentialsCustom).
	FunctionCredentials string `validate:"required"`
	// RuntimeAPIBind is the address the Runtime API listens on; empty, the
	// address on the Docker host the containers reach it at.
	RuntimeAPIBind     string
	RuntimeAPIHost     string `validate:"required"`
	HistoryLimit       int
	AsyncRetryDelay    time.Duration
	MaxContainers      int
	RuntimeAPIPort     int
	IdleTimeout        time.Duration
	MaxTotalContainers int
	PidsLimit          int
	HistoryMaxBytes    int
	PullImages         bool
}

// The values of Settings.FunctionCredentials.
const (
	CredentialsRoot   = "root"
	CredentialsNone   = "none"
	CredentialsCustom = "custom"
)

// FunctionARN returns the ARN of the function name.
func (s *Settings) FunctionARN(name string) string {
	return "arn:aws:lambda:" + s.Region + ":" + s.AccountID + ":function:" + name
}

// MappingARN returns the ARN of the event source mapping uuid.
func (s *Settings) MappingARN(uuid string) string {
	return "arn:aws:lambda:" + s.Region + ":" + s.AccountID + ":event-source-mapping:" + uuid
}

// MappingOfARN returns the UUID an event source mapping ARN of this account
// and region names, or false when it names none.
func (s *Settings) MappingOfARN(arn string) (string, bool) {
	return strings.CutPrefix(arn,
		"arn:aws:lambda:"+s.Region+":"+s.AccountID+":event-source-mapping:")
}
