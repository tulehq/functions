package app

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/services/functions/sqlimpl"
)

// hstsSettings configures the Strict-Transport-Security header. It is only
// sent when MaxAge is set, so plain-HTTP deployments can leave it out.
type hstsSettings struct {
	MaxAge time.Duration
}

// authSettings holds the root key the server accepts. Every request must be
// SigV4-signed with it, so both key fields are required. IdentityEndpoint is
// the identity service's base URL, or empty to run standalone: set, a key
// identity issued is accepted too, and identity is asked with the root key,
// which must therefore be identity's root key as well; the functions'
// execution roles are assumed through identity with it too. The event
// source mappings' pollers sign their calls to the queues service with the
// root key, or with their functions' roles in role mode.
type authSettings struct {
	AccessKeyID      string
	SecretAccessKey  string
	IdentityEndpoint string
}

// errNoCredentials is returned when the access key is not configured.
var errNoCredentials = errors.New("config: TULE_Auth_AccessKeyID and " +
	"TULE_Auth_SecretAccessKey must be set; every request is verified against them")

// Config is the bound application configuration. It keeps the store it was
// bound from, which the app registers as the gas.ConfigProvider so services
// can read settings Config itself does not model.
type Config struct {
	HSTS      *hstsSettings
	Auth      *authSettings
	Store     *sqlimpl.Settings   `validate:"required"`
	Functions *contracts.Settings `validate:"required"`

	store gas.ConfigProvider
	Env   config.Environment
}

const (
	envVarSeparator = "_"
	envVarPrefix    = "TULE_"
)

// LoadConfig loads configuration from a .env file and then the process
// environment, the later source winning.
func LoadConfig() (*Config, error) {
	return LoadConfigFrom(
		config.NewDotEnvProvider(
			config.WithDotEnvSeparator(envVarSeparator),
			config.WithDotEnvFileNotFoundPanic(false),
		),
		config.NewEnvProvider(
			config.WithEnvSeparator(envVarSeparator),
			config.WithEnvPrefix(envVarPrefix),
		),
	)
}

// LoadConfigFrom loads configuration from the given providers in order, then
// applies the same defaults and binding as LoadConfig. Tests use it to inject
// a provider of their own.
func LoadConfigFrom(provs ...config.Provider) (*Config, error) {
	env := config.NewEnvExtension()

	opts := make([]config.Option, 0, len(provs)+1)
	opts = append(opts, config.WithExtension(env))

	for _, p := range provs {
		opts = append(opts, config.WithProvider(p))
	}

	store := config.New(opts...)

	if err := store.Load(); err != nil {
		return nil, fmt.Errorf("config: load: %w", err)
	}

	return bindConfig(store, env.Current())
}

func bindConfig(store gas.ConfigProvider, env config.Environment) (*Config, error) {
	if err := applyDefaults(store); err != nil {
		return nil, err
	}

	cfg := Config{Env: env, store: store}
	if err := store.Bind(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.Auth == nil || cfg.Auth.AccessKeyID == "" || cfg.Auth.SecretAccessKey == "" {
		return nil, errNoCredentials
	}
	if err := checkHTTPURL("Auth.IdentityEndpoint", cfg.Auth.IdentityEndpoint); err != nil {
		return nil, err
	}
	if err := checkFunctions(cfg.Functions, cfg.Auth.IdentityEndpoint); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// checkHTTPURL holds a URL setting, when set, to an absolute http or https
// URL.
func checkHTTPURL(name, value string) error {
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("config: %s %q is not an http or https URL", name, value)
	}
	return nil
}

var (
	accountIDPattern = regexp.MustCompile(`^\d{12}$`)
	// regionPattern is the shape of an AWS region name, such as us-east-1
	// or us-gov-west-1.
	regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)
)

// checkFunctions holds the account to 12 digits, the region to an AWS
// region's shape, the queues endpoint to an http or https URL, and the
// limits, the Runtime API's address and the credentials to theirs.
func checkFunctions(f *contracts.Settings, identityEndpoint string) error {
	if !accountIDPattern.MatchString(f.AccountID) {
		return fmt.Errorf("config: Functions.AccountID %q is not 12 digits", f.AccountID)
	}
	if !regionPattern.MatchString(f.Region) {
		return fmt.Errorf("config: Functions.Region %q is not an AWS region name", f.Region)
	}
	if err := checkHTTPURL("Functions.QueuesEndpoint", f.QueuesEndpoint); err != nil {
		return err
	}
	if err := checkLimits(f); err != nil {
		return err
	}
	if err := checkBind(f.RuntimeAPIBind); err != nil {
		return err
	}
	return checkCredentials(f, identityEndpoint)
}

// checkLimits holds the port to 0 to 65535, and the limits to positive
// values.
func checkLimits(f *contracts.Settings) error {
	if f.RuntimeAPIPort < 0 || f.RuntimeAPIPort > 65535 {
		return fmt.Errorf("config: Functions.RuntimeAPIPort %d is not a port", f.RuntimeAPIPort)
	}
	for name, n := range map[string]int{
		"MaxContainers": f.MaxContainers, "MaxTotalContainers": f.MaxTotalContainers,
		"PidsLimit": f.PidsLimit, "HistoryLimit": f.HistoryLimit,
		"HistoryMaxBytes": f.HistoryMaxBytes,
	} {
		if n < 1 {
			return fmt.Errorf("config: Functions.%s %d is not positive", name, n)
		}
	}
	if f.IdleTimeout <= 0 || f.AsyncRetryDelay <= 0 {
		return errors.New("config: Functions.IdleTimeout and Functions.AsyncRetryDelay " +
			"must be positive")
	}
	return nil
}

// checkBind holds the Runtime API's listen address, when set, to an IP.
func checkBind(bind string) error {
	if bind != "" && net.ParseIP(bind) == nil {
		return fmt.Errorf("config: Functions.RuntimeAPIBind %q is not an IP address", bind)
	}
	return nil
}

// checkCredentials holds FunctionCredentials to its four values, a custom
// key to both of its parts, and role to an identity endpoint, which assumes
// the roles.
func checkCredentials(f *contracts.Settings, identityEndpoint string) error {
	switch f.FunctionCredentials {
	case contracts.CredentialsRole:
		if identityEndpoint == "" {
			return errors.New("config: Functions.FunctionCredentials role needs " +
				"Auth.IdentityEndpoint, through which the functions' roles are assumed")
		}
		fallthrough
	case contracts.CredentialsRoot, contracts.CredentialsNone:
		if f.FunctionAccessKeyID != "" || f.FunctionSecretAccessKey != "" {
			return errors.New("config: Functions.FunctionAccessKeyID and " +
				"Functions.FunctionSecretAccessKey are set, but FunctionCredentials is not custom")
		}
		return nil
	case contracts.CredentialsCustom:
		if f.FunctionAccessKeyID == "" || f.FunctionSecretAccessKey == "" {
			return errors.New("config: Functions.FunctionCredentials custom needs " +
				"Functions.FunctionAccessKeyID and Functions.FunctionSecretAccessKey")
		}
		return nil
	default:
		return fmt.Errorf(
			"config: Functions.FunctionCredentials %q is not role, root, none or custom",
			f.FunctionCredentials)
	}
}

func applyDefaults(store gas.ConfigProvider) error {
	var errs []error
	setDefault := func(key string, value any) {
		if err := store.SetDefault(key, value); err != nil {
			errs = append(errs, fmt.Errorf("config: default %s: %w", key, err))
		}
	}

	// 9060, after the 9050 of queues and the ports of the other Tule
	// services below it, so they can all run at once.
	setDefault("Server.Port", 9060)

	// The server timeouts are set here rather than left to the gas defaults
	// (5s read, 10s write). A request body may be up to maxBodySize, 7 MiB,
	// a 6 MB invocation payload with room to spare, and 30s covers that at
	// about 2 Mbit/s. The write timeout runs from the end of the request's
	// headers, so it must hold a synchronous invocation of the longest
	// timeout, 900 seconds, with a cold start's 10 seconds of initialization
	// before it: 16 minutes does. IdleTimeout keeps the SDKs' connection
	// reuse working between calls, and matches the gas default.
	setDefault("Server.ReadTimeout", "30s")
	setDefault("Server.WriteTimeout", "16m")
	setDefault("Server.IdleTimeout", "120s")
	setDefault("Server.ReadHeaderTimeout", "30s")

	// ShutdownTimeout is shorter than the gas default of 30s, which is a
	// promise a container runtime does not keep: `docker stop` sends SIGTERM
	// and kills the process 10s later. It is not shorter than 7s because of a
	// connection that was opened but never sent a request, as an SDK
	// client's spare one is: net/http closes such a connection only 5s to 6s
	// after it opened, and with a shorter timeout gas reports the deadline as
	// an error. An invocation in flight is cut short: its container is
	// removed with the others.
	setDefault("Server.ShutdownTimeout", "7s")

	setDefault("Store.Path", "./data/functions.db")

	// Unset, functions runs standalone, on the root key alone.
	setDefault("Auth.IdentityEndpoint", "")

	setDefault("Functions.DockerHost", "unix:///var/run/docker.sock")
	// The host the containers reach the Runtime API at: the Docker host
	// itself, which Docker Desktop names host.docker.internal, and which
	// the containers are given a host-gateway mapping for on Linux.
	setDefault("Functions.RuntimeAPIHost", "host.docker.internal")
	setDefault("Functions.RuntimeAPIPort", 9061)
	// Unset, event source mappings cannot be created.
	setDefault("Functions.QueuesEndpoint", "")
	// The account and region ARNs carry: the other services' defaults, so
	// the ARNs agree out of the box.
	setDefault("Functions.AccountID", "000000000000")
	setDefault("Functions.Region", "us-east-1")
	// At most 10 containers, and so 10 invocations at once, per function.
	setDefault("Functions.MaxContainers", 10)
	// A warm container is removed after 10 minutes idle.
	setDefault("Functions.IdleTimeout", "10m")
	// Docker's create never pulls; with this off, an image must be built or
	// pulled into Docker before a function uses it.
	setDefault("Functions.PullImages", false)
	// A failed asynchronous invocation runs again after 1 minute, then
	// after 2 more, as Lambda retries.
	setDefault("Functions.AsyncRetryDelay", "1m")
	// With identity, every container gets a session of its function's
	// execution role, as Lambda gives it; standalone, there are no roles to
	// assume, and it gets the root key, so the function's SDK can call the
	// other Tule services either way.
	credentials := contracts.CredentialsRoot
	if v, ok := store.Find("Auth.IdentityEndpoint"); ok && fmt.Sprint(v) != "" {
		credentials = contracts.CredentialsRole
	}
	setDefault("Functions.FunctionCredentials", credentials)
	setDefault("Functions.FunctionAccessKeyID", "")
	setDefault("Functions.FunctionSecretAccessKey", "")
	// At most 50 containers across every function.
	setDefault("Functions.MaxTotalContainers", 50)
	// Lambda's quota of 1024 processes and threads per execution
	// environment.
	setDefault("Functions.PidsLimit", 1024)
	// Unset, the Runtime API listens on the Docker host's address the
	// containers reach it at, found through Docker; the image sets 0.0.0.0.
	setDefault("Functions.RuntimeAPIBind", "")
	// The history keeps the last 1000 invocations, and at most 256 MiB of
	// their payloads, results and logs.
	setDefault("Functions.HistoryLimit", 1000)
	setDefault("Functions.HistoryMaxBytes", 256<<20)

	return errors.Join(errs...)
}
