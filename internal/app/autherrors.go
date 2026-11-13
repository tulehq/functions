package app

import (
	"net/http"

	"tule.dev/sigv4"

	"tule.dev/functions/internal/lambdaapi"
)

// sigv4Error maps a verification failure to the error it is answered with,
// with the codes and statuses of the AWS JSON services' common errors, as
// the other Tule services answer them. The messages are the verifier's own,
// the AWS JSON services' texts.
//
// KindInvalidSessionToken and KindExpiredSessionToken come from identity,
// for role session keys, or from the root key, which takes no token. The
// Kinds this configuration cannot produce (presigned URLs, a streamed body)
// and KindKeyLookupFailed are returned as the *sigv4.Error itself: lambdaapi
// answers any error it does not know with ServiceException and logs it, so
// they surface as a 500 with their cause in the log. A failed lookup at
// identity is never answered as an unknown key, so the client sees a fault
// on the server's side rather than a key to throw away.
func sigv4Error(e *sigv4.Error) error {
	switch e.Kind {
	case sigv4.KindMissingAuth:
		return lambdaapi.NewError(http.StatusForbidden, lambdaapi.CodeMissingAuthToken, e.Message)
	case sigv4.KindUnsupportedAlgorithm, sigv4.KindIncompleteAuth, sigv4.KindInvalidDate,
		sigv4.KindUnsignedHeader, sigv4.KindMalformedCredential,
		sigv4.KindCredentialDateMismatch, sigv4.KindPayloadHashNotAccepted:
		return lambdaapi.NewError(
			http.StatusForbidden,
			lambdaapi.CodeIncompleteSignature,
			e.Message,
		)
	case sigv4.KindRequestTimeTooSkewed, sigv4.KindSignatureMismatch, sigv4.KindWrongService:
		return lambdaapi.NewError(http.StatusForbidden, lambdaapi.CodeInvalidSignature, e.Message)
	case sigv4.KindUnknownAccessKey, sigv4.KindInvalidSessionToken:
		return lambdaapi.NewError(http.StatusForbidden, lambdaapi.CodeUnrecognizedClient, e.Message)
	case sigv4.KindExpiredSessionToken:
		return lambdaapi.NewError(http.StatusForbidden, lambdaapi.CodeExpiredToken, e.Message)
	case sigv4.KindPayloadHashMismatch, sigv4.KindBodyUnreadable:
		return lambdaapi.NewError(
			http.StatusBadRequest,
			lambdaapi.CodeInvalidRequestContent,
			e.Message,
		)
	case sigv4.KindBodyTooLarge:
		return lambdaapi.NewError(
			http.StatusRequestEntityTooLarge,
			lambdaapi.CodeRequestTooLarge,
			e.Message,
		)
	default:
		return e
	}
}
