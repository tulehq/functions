package app

import (
	"errors"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"
)

func loadEnvConfig(t *testing.T, id, secret string) (*Config, error) {
	t.Helper()
	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Auth_AccessKeyID", id)
	t.Setenv("TULE_Auth_SecretAccessKey", secret)

	return LoadConfigFrom(config.NewEnvProvider(
		config.WithEnvSeparator(envVarSeparator),
		config.WithEnvPrefix(envVarPrefix),
	))
}

func TestLoadConfigRequiresCredentials(t *testing.T) {
	tests := []struct {
		name, id, secret string
		wantErr          bool
	}{
		{name: "both set", id: "AKID", secret: "secret"},
		{name: "neither set", wantErr: true},
		{name: "no secret", id: "AKID", wantErr: true},
		{name: "no access key", secret: "secret", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadEnvConfig(t, tt.id, tt.secret)
			if tt.wantErr != errors.Is(err, errNoCredentials) {
				t.Fatalf("got %v, want errNoCredentials: %v", err, tt.wantErr)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	f := cfg.Functions
	strs := []struct{ got, want, name string }{
		{cfg.Store.Path, "./data/functions.db", "store path"},
		{f.DockerHost, "unix:///var/run/docker.sock", "docker host"},
		{f.RuntimeAPIHost, "host.docker.internal", "runtime API host"},
		{f.QueuesEndpoint, "", "queues endpoint"},
		{f.AccountID, "000000000000", "account"},
		{f.Region, "us-east-1", "region"},
		{cfg.Auth.IdentityEndpoint, "", "identity endpoint"},
	}
	for _, tt := range strs {
		if tt.got != tt.want {
			t.Errorf("default %s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
	limits := []struct {
		got, want any
		name      string
	}{
		{f.RuntimeAPIPort, 9061, "runtime API port"},
		{f.MaxContainers, 10, "max containers"},
		{f.HistoryLimit, 1000, "history limit"},
		{f.IdleTimeout, 10 * time.Minute, "idle timeout"},
		{f.AsyncRetryDelay, time.Minute, "async retry delay"},
		{f.PullImages, false, "pull images"},
		{f.FunctionCredentials, "root", "function credentials"},
		{f.MaxTotalContainers, 50, "max total containers"},
		{f.PidsLimit, 1024, "pids limit"},
		{f.HistoryMaxBytes, 256 << 20, "history bytes"},
		{f.RuntimeAPIBind, "", "runtime API bind"},
		{cfg.store.Get("Server.Port"), 9060, "server port"},
	}
	for _, tt := range limits {
		if tt.got != tt.want {
			t.Errorf("default %s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestLoadConfigSetsServerTimeouts(t *testing.T) {
	cfg, err := loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	// Bound through gas's own Config, so a key this service spells wrong
	// fails here rather than silently leaving the gas default in place.
	gasCfg := gas.DefaultConfig()
	if bErr := cfg.store.Bind(gasCfg); bErr != nil {
		t.Fatalf("bind gas config: %v", bErr)
	}
	tests := []struct {
		name      string
		got, want time.Duration
	}{
		{"read", gasCfg.Server.ReadTimeout, 30 * time.Second},
		{"read header", gasCfg.Server.ReadHeaderTimeout, 30 * time.Second},
		{"write", gasCfg.Server.WriteTimeout, 16 * time.Minute},
		{"idle", gasCfg.Server.IdleTimeout, 2 * time.Minute},
		{"shutdown", gasCfg.Server.ShutdownTimeout, 7 * time.Second},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s timeout = %s, want %s", tt.name, tt.got, tt.want)
		}
	}
}

func TestLoadConfigChecksTheFunctionSettings(t *testing.T) {
	tests := []struct{ key, value string }{
		{"TULE_Functions_AccountID", "12345"},
		{"TULE_Functions_Region", "Earth"},
		{"TULE_Functions_QueuesEndpoint", "localhost:9050"},
		{"TULE_Functions_RuntimeAPIPort", "70000"},
		{"TULE_Functions_MaxContainers", "0"},
		{"TULE_Functions_HistoryLimit", "0"},
		{"TULE_Functions_IdleTimeout", "0s"},
		{"TULE_Auth_IdentityEndpoint", "ftp://localhost:9030"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Setenv(tt.key, tt.value)
			if _, err := loadEnvConfig(t, "AKID", "secret"); err == nil {
				t.Fatalf("load config with %s=%q succeeded", tt.key, tt.value)
			}
		})
	}
	t.Setenv("TULE_Functions_QueuesEndpoint", "http://127.0.0.1:9050")
	t.Setenv("TULE_Functions_RuntimeAPIPort", "0")
	if _, err := loadEnvConfig(t, "AKID", "secret"); err != nil {
		t.Fatalf("load config with valid settings: %v", err)
	}
}

func TestLoadConfigChecksTheFunctionCredentials(t *testing.T) {
	for _, tt := range []struct {
		mode, id, secret string
		ok               bool
	}{
		{"root", "", "", true},
		{"none", "", "", true},
		{"custom", "AKIDFN", "fn-secret", true},
		{"custom", "AKIDFN", "", false},
		{"none", "AKIDFN", "fn-secret", false},
		{"true", "", "", false},
	} {
		t.Run(tt.mode+"/"+tt.id, func(t *testing.T) {
			t.Setenv("TULE_Functions_FunctionCredentials", tt.mode)
			t.Setenv("TULE_Functions_FunctionAccessKeyID", tt.id)
			t.Setenv("TULE_Functions_FunctionSecretAccessKey", tt.secret)
			_, err := loadEnvConfig(t, "AKID", "secret")
			if (err == nil) != tt.ok {
				t.Fatalf("load config = %v, want ok %v", err, tt.ok)
			}
		})
	}
}
