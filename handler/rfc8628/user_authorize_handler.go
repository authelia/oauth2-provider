// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/reflection"
	"authelia.com/provider/oauth2/x/errorsx"
)

// UserAuthorizeHandler handles the RFC 8628 user verification request.
type UserAuthorizeHandler struct {
	Storage  Storage
	Strategy CodeStrategy
	Config   interface {
		oauth2.RFC8628DeviceAuthorizeConfigProvider
	}
}

// PopulateRFC8628UserAuthorizeEndpointResponse implements the Device Authorization Grant Flow's resource owner / user
// interactions Device Authorization Request as defined in RFC8638 Section 3.3 and 3.4.
//
// See: https://datatracker.ietf.org/doc/html/rfc8628#section-3.3 and https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
func (d *UserAuthorizeHandler) PopulateRFC8628UserAuthorizeEndpointResponse(ctx context.Context, request oauth2.DeviceAuthorizeRequester, response oauth2.DeviceUserAuthorizeResponder) (err error) {
	status := request.GetStatus()

	// At this stage the request must be either approved or denied.
	if status != oauth2.DeviceAuthorizeStatusApproved && status != oauth2.DeviceAuthorizeStatusDenied {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithDebug("Failed to perform device authorization because the request status is invalid."))
	}

	response.SetStatus(oauth2.DeviceAuthorizeStatusToString(status))

	if decider, ok := d.Storage.(DecisionStorage); ok {
		err = decider.DecideDeviceCodeSession(ctx, request.GetDeviceCodeSignature(), request)
	} else {
		err = d.Storage.UpdateDeviceCodeSession(ctx, request.GetDeviceCodeSignature(), request)
	}

	switch {
	case errors.Is(err, oauth2.ErrDeviceAuthorizeDecided), errors.Is(err, oauth2.ErrNotFound):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Cannot process the request, the user_code is either invalid or expired.").WithWrap(err).WithDebugError(err))
	case err != nil:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

// HandleRFC8628UserAuthorizeEndpointRequest implements the Device Authorization Grant Flow's resource owner / user
// interactions Device Authorization Response as defined in RFC8638 Section 3.5. A user code which is not accepted is
// answered with 'invalid_grant' wrapping oauth2.ErrUserCodeUnknown, oauth2.ErrUserCodeExpired,
// oauth2.ErrUserCodeDecided or oauth2.ErrUserCodeClaimed. Unless disabled, an undecided user code is bound to the
// subject of the session of the first request presenting it, and refused when any other subject presents it.
//
// See: https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
// See: https://www.rfc-editor.org/rfc/rfc8628#section-5.1
// See: https://www.rfc-editor.org/rfc/rfc10027#section-6.1.3
//
//nolint:gocyclo
func (d *UserAuthorizeHandler) HandleRFC8628UserAuthorizeEndpointRequest(ctx context.Context, request oauth2.DeviceAuthorizeRequester) (err error) {
	var (
		code, signature string

		storedReq oauth2.DeviceAuthorizeRequester
	)

	if code = request.GetRequestForm().Get(consts.FormParameterUserCode); len(code) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Cannot process the request, user_code is missing."))
	}

	if reflection.IsNil(request.GetSession()) {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Cannot process the request, the session is nil."))
	}

	// See: https://www.rfc-editor.org/rfc/rfc8628#section-5.1
	if err = d.allowUserCodeAttempt(ctx, request); err != nil {
		return err
	}

	// The stored session replaces the session of the request, so the presenting subject is read first.
	binding, subject := d.isUserCodeSubjectBindingEnforced(ctx), request.GetSession().GetSubject()

	if binding && subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Cannot process the request, the session must carry the subject of the authenticated End-User presenting the user_code."))
	}

	claims, ok := d.Storage.(ClaimStorage)

	if binding && !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Cannot process the request, the storage must implement rfc8628.ClaimStorage to bind the user_code to the End-User presenting it."))
	}

	if signature, err = d.Strategy.RFC8628UserCodeSignature(ctx, code); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	switch storedReq, err = d.Storage.GetDeviceCodeSessionByUserCode(ctx, signature, request.GetSession()); {
	case errors.Is(err, oauth2.ErrNotFound):
		return errUserCode(oauth2.ErrUserCodeUnknown)
	case errors.Is(err, oauth2.ErrInvalidatedDeviceCode):
		return errUserCode(oauth2.ErrUserCodeDecided)
	case err != nil:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	request.Merge(storedReq)

	client := request.GetClient()

	if !client.GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
	}

	session := request.GetSession()

	if reflection.IsNil(session) {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Cannot process the request, the stored session is nil."))
	}

	if request.GetUserCodeSignature() != signature {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Cannot process the request, user code signature mismatch."))
	}

	if status := request.GetStatus(); status != oauth2.DeviceAuthorizeStatusNew && status != oauth2.DeviceAuthorizeStatusClaimed {
		return errUserCode(oauth2.ErrUserCodeDecided)
	}

	if session.GetExpiresAt(oauth2.UserCode).Before(time.Now().UTC()) {
		return errUserCode(oauth2.ErrUserCodeExpired)
	}

	if !binding {
		return nil
	}

	// See: https://www.rfc-editor.org/rfc/rfc10027#section-6.1.3
	return d.claim(ctx, claims, request, subject)
}

func (d *UserAuthorizeHandler) allowUserCodeAttempt(ctx context.Context, request oauth2.DeviceAuthorizeRequester) (err error) {
	config, ok := d.Config.(oauth2.RFC8628UserCodeRateLimiterProvider)
	if !ok {
		return nil
	}

	limiter := config.GetRFC8628UserCodeRateLimiter(ctx)
	if limiter == nil {
		return nil
	}

	if err = limiter.AllowRFC8628UserCodeAttempt(ctx, request); err == nil {
		return nil
	}

	var rfc *oauth2.RFC6749Error

	if errors.As(err, &rfc) {
		return err
	}

	return errorsx.WithStack(oauth2.ErrTooManyRequests.WithHint("Too many user_code attempts have been made.").WithWrap(err).WithDebugError(err))
}

func (d *UserAuthorizeHandler) isUserCodeSubjectBindingEnforced(ctx context.Context) (enforce bool) {
	if config, ok := d.Config.(oauth2.RFC8628UserCodeSubjectBindingProvider); ok {
		return config.GetRFC8628UserCodeSubjectBinding(ctx)
	}

	return true
}

func (d *UserAuthorizeHandler) claim(ctx context.Context, storage ClaimStorage, request oauth2.DeviceAuthorizeRequester, subject string) (err error) {
	switch err = storage.ClaimDeviceCodeSession(ctx, request.GetDeviceCodeSignature(), subject); {
	case err == nil:
	case errors.Is(err, oauth2.ErrUserCodeClaimed):
		return errUserCode(oauth2.ErrUserCodeClaimed)
	case errors.Is(err, oauth2.ErrDeviceAuthorizeDecided):
		return errUserCode(oauth2.ErrUserCodeDecided)
	case errors.Is(err, oauth2.ErrNotFound):
		return errUserCode(oauth2.ErrUserCodeUnknown)
	default:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	request.SetStatus(oauth2.DeviceAuthorizeStatusClaimed)

	if claimant, ok := request.(oauth2.DeviceAuthorizeClaimRequester); ok {
		claimant.SetClaimSubject(subject)
	}

	return nil
}

func errUserCode(cause error) (err error) {
	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Cannot process the request, the user_code is either invalid or expired.").WithWrap(cause).WithDebugError(cause))
}

var (
	_ oauth2.RFC8628UserAuthorizeEndpointHandler = (*UserAuthorizeHandler)(nil)
)
