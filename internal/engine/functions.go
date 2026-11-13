package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"tule.dev/functions/internal/contracts"
	"tule.dev/functions/internal/docker"
	"tule.dev/functions/internal/ids"
	"tule.dev/functions/internal/lambdaapi"
)

// imageCheckTimeout bounds one image check, a pull included.
const imageCheckTimeout = 10 * time.Minute

// The reason codes of a function whose image cannot be used.
const reasonInvalidImage = "InvalidImage"

// CreateFunction stores fn as Pending and checks its image in the
// background, which makes it Active or Failed.
func (e *Engine) CreateFunction(ctx context.Context, fn *contracts.Function) error {
	fn.ARN = e.settings.FunctionARN(fn.Name)
	fn.State = contracts.StatePending
	fn.StateReason = "The function is being created."
	fn.StateReasonCode = "Creating"
	fn.RevisionID = ids.UUID()
	fn.LastModified = time.Now().UTC()
	if err := e.store.PutFunction(ctx, fn); err != nil {
		if errors.Is(err, contracts.ErrFunctionExists) {
			return lambdaapi.ErrConflict("Function already exist: " + fn.Name)
		}
		return err
	}
	e.checkInBackground(fn.Name, fn.RevisionID, fn.Image.URI)
	return nil
}

// errNotFound is ResourceNotFoundException for the function name.
func (e *Engine) errNotFound(name string) error {
	return lambdaapi.ErrNotFound("Function not found: " + e.settings.FunctionARN(name))
}

// function returns the named function, or ResourceNotFoundException.
func (e *Engine) function(ctx context.Context, name string) (*contracts.Function, error) {
	fn, err := e.store.GetFunction(ctx, name)
	if errors.Is(err, contracts.ErrFunctionNotFound) {
		return nil, e.errNotFound(name)
	}
	return fn, err
}

// update changes the named function, as UpdateFunction does, answering a
// missing function with ResourceNotFoundException.
func (e *Engine) update(
	ctx context.Context,
	name string,
	fn func(*contracts.Function) error,
) (*contracts.Function, error) {
	out, err := e.store.UpdateFunction(ctx, name, fn)
	if errors.Is(err, contracts.ErrFunctionNotFound) {
		return nil, e.errNotFound(name)
	}
	return out, err
}

// errBusy is the conflict an operation meets while the function is being
// created or updated.
func errBusy(fn *contracts.Function) error {
	if fn.State == contracts.StatePending {
		return lambdaapi.ErrConflict("The operation cannot be performed at this time. " +
			"The function is currently in the following state: Pending")
	}
	if fn.LastUpdateStatus == contracts.UpdateInProgress {
		return lambdaapi.ErrConflict("The operation cannot be performed at this time. " +
			"An update is in progress for resource: " + fn.ARN)
	}
	return nil
}

// CheckRevision fails with PreconditionFailedException when revision is
// set and is not the function's.
func CheckRevision(fn *contracts.Function, revision *string) error {
	if revision != nil && *revision != fn.RevisionID {
		return lambdaapi.NewError(http.StatusPreconditionFailed, lambdaapi.CodePreconditionFailed,
			"The Revision Id provided does not match the latest Revision Id. "+
				"Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
	}
	return nil
}

// UpdateCode starts an update of the function's image: the image is
// checked in the background, and replaces the running one only when it can
// be used.
func (e *Engine) UpdateCode(
	ctx context.Context,
	name, imageURI string,
	revision *string,
) (*contracts.Function, error) {
	fn, err := e.update(ctx, name, func(fn *contracts.Function) error {
		if bErr := errBusy(fn); bErr != nil {
			return bErr
		}
		if rErr := CheckRevision(fn, revision); rErr != nil {
			return rErr
		}
		fn.PendingImage = &contracts.Image{URI: imageURI}
		startUpdate(fn)
		return nil
	})
	if err != nil {
		return nil, err
	}
	e.checkInBackground(fn.Name, fn.RevisionID, imageURI)
	return fn, nil
}

func startUpdate(fn *contracts.Function) {
	fn.RevisionID = ids.UUID()
	fn.LastModified = time.Now().UTC()
	fn.LastUpdateStatus = contracts.UpdateInProgress
	fn.LastUpdateStatusReason = "The function is being updated."
	fn.LastUpdateStatusReasonCode = ""
}

// UpdateConfiguration applies change to the function's configuration.
// Like Lambda, it reports the update InProgress; it completes at once, and
// the function's containers are replaced as their invocations end.
func (e *Engine) UpdateConfiguration(
	ctx context.Context,
	name string,
	revision *string,
	change func(*contracts.Function) error,
) (*contracts.Function, error) {
	fn, err := e.update(ctx, name, func(fn *contracts.Function) error {
		if bErr := errBusy(fn); bErr != nil {
			return bErr
		}
		if rErr := CheckRevision(fn, revision); rErr != nil {
			return rErr
		}
		if cErr := change(fn); cErr != nil {
			return cErr
		}
		startUpdate(fn)
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := *fn
	revisionID := fn.RevisionID
	e.goBackground(func(ctx context.Context) {
		_, uErr := e.store.UpdateFunction(ctx, name, func(fn *contracts.Function) error {
			if fn.RevisionID != revisionID {
				return errSuperseded
			}
			finishUpdate(fn)
			return nil
		})
		e.afterUpdate(name, uErr)
	})
	return &out, nil
}

// errSuperseded ends a background update that a later one replaced.
var errSuperseded = errors.New("engine: the function changed meanwhile")

func finishUpdate(fn *contracts.Function) {
	fn.LastUpdateStatus = contracts.UpdateSuccessful
	fn.LastUpdateStatusReason = ""
	fn.LastUpdateStatusReasonCode = ""
}

// afterUpdate retires the function's containers once an update completed,
// so the next invocation runs what the function now says.
func (e *Engine) afterUpdate(name string, err error) {
	switch {
	case err == nil:
		e.runner.Retire(name)
	case errors.Is(err, errSuperseded), errors.Is(err, contracts.ErrFunctionNotFound):
	default:
		e.logger.Error("failed to complete a function update").Str("function", name).
			Err("error", err).Send()
	}
}

// DeleteFunction deletes the function, its event source mappings, and its
// containers, those running an invocation included.
func (e *Engine) DeleteFunction(ctx context.Context, name string) error {
	fn, err := e.function(ctx, name)
	if err != nil {
		return err
	}
	mappings, err := e.store.AllMappings(ctx)
	if err != nil {
		return err
	}
	if err = e.store.DeleteFunction(ctx, name); err != nil {
		if errors.Is(err, contracts.ErrFunctionNotFound) {
			return e.errNotFound(name)
		}
		return err
	}
	for i := range mappings {
		if mappings[i].FunctionName != name {
			continue
		}
		unlock := e.lockMapping(mappings[i].UUID)
		e.stopPoller(mappings[i].UUID)
		unlock()
		if dErr := e.store.DeleteMapping(ctx, mappings[i].UUID); dErr != nil &&
			!errors.Is(dErr, contracts.ErrMappingNotFound) {
			return dErr
		}
	}
	e.runner.Delete(name, fn.RevisionID)
	return nil
}

func (e *Engine) checkInBackground(name, revision, uri string) {
	e.goBackground(func(ctx context.Context) {
		e.checkImage(ctx, name, revision, uri)
	})
}

// checkImage asks Docker for the image, pulling it first when it is
// missing and pulling is on, and records the outcome: a created function
// turns Active or Failed, an updated one's update Successful or Failed.
func (e *Engine) checkImage(ctx context.Context, name, revision, uri string) {
	ctx, cancel := context.WithTimeout(ctx, imageCheckTimeout)
	defer cancel()
	img, checkErr := e.inspect(ctx, uri)
	if ctx.Err() != nil && e.ctx.Err() != nil {
		// Shutting down: the next start checks again.
		return
	}
	_, err := e.store.UpdateFunction(ctx, name, func(fn *contracts.Function) error {
		if fn.RevisionID != revision {
			return errSuperseded
		}
		applyCheck(fn, img, checkErr)
		return nil
	})
	if err == nil && checkErr == nil {
		e.runner.Retire(name)
		return
	}
	if err != nil && !errors.Is(err, errSuperseded) &&
		!errors.Is(err, contracts.ErrFunctionNotFound) {
		e.logger.Error("failed to record an image check").Str("function", name).
			Err("error", err).Send()
	}
}

// applyCheck records an image check's outcome on fn.
func applyCheck(fn *contracts.Function, img *contracts.Image, checkErr error) {
	creating := fn.State == contracts.StatePending
	if checkErr != nil {
		reason := checkErr.Error()
		fn.LastUpdateStatus = contracts.UpdateFailed
		fn.LastUpdateStatusReason = reason
		fn.LastUpdateStatusReasonCode = reasonInvalidImage
		fn.PendingImage = nil
		if creating {
			fn.State = contracts.StateFailed
			fn.StateReason = reason
			fn.StateReasonCode = reasonInvalidImage
		}
		return
	}
	fn.Image = *img
	fn.PendingImage = nil
	fn.State = contracts.StateActive
	fn.StateReason = ""
	fn.StateReasonCode = ""
	finishUpdate(fn)
}

// imageError is why an image cannot be used, as the function's state
// reason says it: a sentence, capitalized and punctuated as Lambda's are.
type imageError struct {
	err    error
	reason string
}

func (e *imageError) Error() string { return e.reason }

func (e *imageError) Unwrap() error { return e.err }

// inspect resolves uri to the image the containers will run.
func (e *Engine) inspect(ctx context.Context, uri string) (*contracts.Image, error) {
	ref, err := docker.ParseReference(uri)
	if err != nil {
		return nil, &imageError{
			reason: "The image URI " + uri + " is not valid: " + err.Error(),
			err:    err,
		}
	}
	img, err := e.docker.InspectImage(ctx, ref.String())
	if errors.Is(err, docker.ErrNotFound) && e.settings.PullImages {
		if pErr := e.docker.PullImage(ctx, ref); pErr != nil {
			return nil, &imageError{
				reason: fmt.Sprintf("Lambda was unable to pull the image %s: %v", uri, pErr),
				err:    pErr,
			}
		}
		img, err = e.docker.InspectImage(ctx, ref.String())
	}
	if errors.Is(err, docker.ErrNotFound) {
		return nil, &imageError{
			reason: "The image " + uri + " is not present in Docker, and pulling is off " +
				"(TULE_Functions_PullImages).",
			err: err,
		}
	}
	if err != nil {
		return nil, err
	}
	digest := strings.TrimPrefix(img.ID, "sha256:")
	resolved := uri + "@" + img.ID
	for _, rd := range img.RepoDigests {
		if _, d, ok := strings.Cut(rd, "@sha256:"); ok {
			digest = d
			resolved = rd
			break
		}
	}
	return &contracts.Image{URI: uri, ID: img.ID, ResolvedURI: resolved, CodeSha256: digest}, nil
}

// resumeFunctions checks again the images of the functions and updates an
// interrupted run left in progress.
func (e *Engine) resumeFunctions(ctx context.Context) error {
	fns, err := e.store.AllFunctions(ctx)
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	for i := range fns {
		fn := &fns[i]
		switch {
		case fn.State == contracts.StatePending:
			e.checkInBackground(fn.Name, fn.RevisionID, fn.Image.URI)
		case fn.LastUpdateStatus == contracts.UpdateInProgress && fn.PendingImage != nil:
			e.checkInBackground(fn.Name, fn.RevisionID, fn.PendingImage.URI)
		case fn.LastUpdateStatus == contracts.UpdateInProgress:
			if _, uErr := e.store.UpdateFunction(ctx, fn.Name, func(f *contracts.Function) error {
				finishUpdate(f)
				return nil
			}); uErr != nil {
				return fmt.Errorf("engine: %w", uErr)
			}
		}
	}
	return nil
}
