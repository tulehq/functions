package app

import (
	"errors"
	"net/http"
	"testing"

	"tule.dev/sigv4"

	"tule.dev/functions/internal/lambdaapi"
)

func TestSigv4ErrorMapsEveryKindTheVerifierReturns(t *testing.T) {
	tests := []struct {
		errType string
		kind    sigv4.Kind
		status  int
	}{
		{lambdaapi.CodeMissingAuthToken, sigv4.KindMissingAuth, http.StatusForbidden},
		{lambdaapi.CodeIncompleteSignature, sigv4.KindUnsupportedAlgorithm, http.StatusForbidden},
		{lambdaapi.CodeIncompleteSignature, sigv4.KindIncompleteAuth, http.StatusForbidden},
		{lambdaapi.CodeIncompleteSignature, sigv4.KindInvalidDate, http.StatusForbidden},
		{lambdaapi.CodeIncompleteSignature, sigv4.KindUnsignedHeader, http.StatusForbidden},
		{lambdaapi.CodeIncompleteSignature, sigv4.KindMalformedCredential, http.StatusForbidden},
		{lambdaapi.CodeIncompleteSignature, sigv4.KindCredentialDateMismatch, http.StatusForbidden},
		{lambdaapi.CodeIncompleteSignature, sigv4.KindPayloadHashNotAccepted, http.StatusForbidden},
		{lambdaapi.CodeInvalidSignature, sigv4.KindRequestTimeTooSkewed, http.StatusForbidden},
		{lambdaapi.CodeInvalidSignature, sigv4.KindSignatureMismatch, http.StatusForbidden},
		{lambdaapi.CodeInvalidSignature, sigv4.KindWrongService, http.StatusForbidden},
		{lambdaapi.CodeUnrecognizedClient, sigv4.KindUnknownAccessKey, http.StatusForbidden},
		{lambdaapi.CodeUnrecognizedClient, sigv4.KindInvalidSessionToken, http.StatusForbidden},
		{lambdaapi.CodeExpiredToken, sigv4.KindExpiredSessionToken, http.StatusForbidden},
		{lambdaapi.CodeInvalidRequestContent, sigv4.KindPayloadHashMismatch, http.StatusBadRequest},
		{lambdaapi.CodeInvalidRequestContent, sigv4.KindBodyUnreadable, http.StatusBadRequest},
		{lambdaapi.CodeRequestTooLarge, sigv4.KindBodyTooLarge, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			err := sigv4Error(&sigv4.Error{Kind: tt.kind, Message: "the verifier's text"})

			var apiErr *lambdaapi.Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %v, want a *lambdaapi.Error", err)
			}
			want := lambdaapi.Error{
				Status:  tt.status,
				Code:    tt.errType,
				Message: "the verifier's text",
			}
			if *apiErr != want {
				t.Fatalf("error = %+v, want %+v", *apiErr, want)
			}
		})
	}
}

func TestSigv4ErrorLeavesTheRestToServiceException(t *testing.T) {
	// The key lookup failing, and the Kinds this configuration cannot
	// produce, come back as the *sigv4.Error, which lambdaapi answers
	// with ServiceException and logs.
	for _, kind := range []sigv4.Kind{
		sigv4.KindKeyLookupFailed,
		sigv4.KindInvalidExpires,
		sigv4.KindExpired,
		sigv4.KindRequestNotYetValid,
		sigv4.KindMissingPayloadHash,
		sigv4.KindUnverifiedPayload,
	} {
		t.Run(kind.String(), func(t *testing.T) {
			in := &sigv4.Error{Kind: kind, Message: "the verifier's text"}
			var out *sigv4.Error
			if err := sigv4Error(in); !errors.As(err, &out) || out != in {
				t.Fatalf("error = %v, want the *sigv4.Error itself", err)
			}
			got := lambdaapi.ToError(t.Context(), in)
			if got.Status != http.StatusInternalServerError ||
				got.Code != lambdaapi.CodeService {
				t.Fatalf(
					"answered as %d %s, want 500 %s",
					got.Status,
					got.Code,
					lambdaapi.CodeService,
				)
			}
		})
	}
}
