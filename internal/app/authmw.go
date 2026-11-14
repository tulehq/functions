package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"tule.dev/identity/keysource"
	"tule.dev/sigv4"

	"tule.dev/functions/internal/lambdaapi"
	"tule.dev/functions/internal/modules/health"
	"tule.dev/functions/internal/modules/history"
	"tule.dev/functions/internal/modules/lambda"
	"tule.dev/functions/serviceinvoke"
)

// maxBodySize bounds the request body the verifier buffers to hash it: the
// largest legitimate request is a synchronous Invoke's 6 MB payload, and a
// body past that, up to this bound, is answered by Invoke itself with
// RequestTooLargeException.
const maxBodySize = lambda.MaxSyncPayload + 1<<20

// identityTimeout bounds a key lookup at identity, so an identity that hangs
// fails the request with ServiceException rather than holding it until the
// server's own timeout. It is a variable so a test can shorten it.
var identityTimeout = 10 * time.Second

// newVerifier returns the SigV4 verifiers. The api one is what every
// request but the probes and the service-invoke endpoint goes through, the
// Lambda API's and the retrieval API's alike. It knows the
// configured root key and, when an identity endpoint is configured, every
// key identity issued, asked of identity on each request after the root key.
// The root key may call every operation; any other key's principal is
// authorized by its identity policies, which identity sends with the key
// (package authz). Requests are accepted signed for lambda in any region. The path is
// canonicalized encoded twice, as every service but S3 signs it, since
// function ARNs, with their colons, appear in paths. The internal one, for
// the service-invoke endpoint, knows only the root principal's keys
// (rootOnly), and is otherwise the same.
func newVerifier(cfg *Config) (*verifiers, error) {
	account := cfg.Functions.AccountID
	root, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID:     cfg.Auth.AccessKeyID,
		SecretAccessKey: cfg.Auth.SecretAccessKey,
		AccountID:       account,
		ARN:             "arn:aws:iam::" + account + ":root",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build the signature verifier: %w", err)
	}
	var keys sigv4.KeySource = root
	if cfg.Auth.IdentityEndpoint != "" {
		identity, kErr := keysource.New(keysource.Config{
			HTTPClient:      &http.Client{Timeout: identityTimeout},
			Endpoint:        cfg.Auth.IdentityEndpoint,
			AccessKeyID:     cfg.Auth.AccessKeyID,
			SecretAccessKey: cfg.Auth.SecretAccessKey,
		})
		if kErr != nil {
			return nil, fmt.Errorf("failed to build the signature verifier: %w", kErr)
		}
		keys = sigv4.Chain(root, identity)
	}
	v, err := sigv4.New(
		keys,
		sigv4.WithBufferedPayload(maxBodySize),
		sigv4.WithRequiredSignedHeaders("host", "x-amz-date"),
		sigv4.WithService("lambda"),
		sigv4.WithErrorMap(sigv4Error),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build the signature verifier: %w", err)
	}
	internal, err := sigv4.New(
		rootOnly{keys: keys, account: account},
		sigv4.WithBufferedPayload(maxBodySize),
		sigv4.WithRequiredSignedHeaders("host", "x-amz-date"),
		sigv4.WithService(serviceinvoke.SigningName),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build the service-invoke verifier: %w", err)
	}
	return &verifiers{api: v, internal: internal}, nil
}

// verifiers are the service's two: api for the Lambda API and the
// retrieval API, internal for the service-invoke endpoint.
type verifiers struct {
	api      *sigv4.Verifier
	internal *sigv4.Verifier
}

// rootOnly is the key source of the service-invoke endpoint: the keys of
// the root principal only, the principal the authorizer never evaluates
// (package authz), which is the configured key, or with identity a key
// identity issued the root user of the service's own account. Any other
// key is unknown, as identity's internal endpoints, which know the root
// user's key alone, answer one, so the endpoint refuses it before its body
// is read.
type rootOnly struct {
	keys    sigv4.KeySource
	account string
}

func (s rootOnly) SigningKey(ctx context.Context, scope sigv4.Scope) (sigv4.Key, error) {
	k, err := s.keys.SigningKey(ctx, scope)
	if err != nil {
		//nolint:wrapcheck // the key sources' errors are the sentinels the verifier reads
		return sigv4.Key{}, err
	}
	p := k.Principal
	if !p.Root || p.Type != sigv4.PrincipalTypeAccount || p.AccountID != s.account {
		return sigv4.Key{}, sigv4.ErrUnknownAccessKey
	}
	return k, nil
}

// verifySignature rejects requests whose SigV4 signature does not verify,
// and serves the rest as Verify returns them, with the signer's principal
// in their context and the body the signature covered. The service-invoke
// endpoint is verified against the root key alone, its failures answered
// as identity's internal endpoints answer theirs; everything else against
// every key the service knows.
//
// The health probes are exempt, so a container's health check needs no
// credentials; nothing else is, because any web page the developer has open
// can reach a server on localhost, and this one runs containers.
func verifySignature(v *verifiers) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case isProbe(r.URL.Path):
				next.ServeHTTP(w, r)
			case r.URL.Path == serviceinvoke.Path:
				verified, err := v.internal.Verify(r)
				if err != nil {
					lambda.WriteServiceInvokeError(w, r, err)
					return
				}
				next.ServeHTTP(w, verified)
			default:
				verified, err := v.api.Verify(r)
				if err != nil {
					writeError(w, r, err)
					return
				}
				next.ServeHTTP(w, verified)
			}
		})
	}
}

func isProbe(path string) bool {
	return path == health.HealthPath || path == health.ReadyPath
}

// writeError renders err for middleware: as a retrieval API error under its
// prefix, else as a Lambda error.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	if strings.HasPrefix(r.URL.Path, history.Prefix) {
		history.WriteError(w, r, err)
		return
	}
	lambdaapi.WriteHTTPError(w, r, err)
}
