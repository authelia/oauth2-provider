package rfc8628

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type UserAuthorizeHandler struct {
	Storage  Storage
	Strategy CodeStrategy
	Config   interface {
		oauth2.RFC9628DeviceAuthorizeConfigProvider
	}
}

// PopulateRFC8628UserAuthorizeEndpointResponse is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
func (d *UserAuthorizeHandler) PopulateRFC8628UserAuthorizeEndpointResponse(ctx context.Context, request oauth2.DeviceAuthorizeRequester, response oauth2.DeviceUserAuthorizeResponder) (err error) {
	status := request.GetStatus()

	// The request shall be either approved or denied.
	if status != oauth2.DeviceAuthorizeStatusApproved && status != oauth2.DeviceAuthorizeStatusDenied {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithDebug("Failed to perform device authorization because the request status is invalid."))
	}

	response.SetStatus(oauth2.DeviceAuthorizeStatusToString(status))

	// Stores the auth session and approval status into user code session instead of device code session.
	if err = d.Storage.UpdateDeviceCodeSession(ctx, request.GetDeviceCodeSignature(), request); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (d *UserAuthorizeHandler) HandleRFC8628UserAuthorizeEndpointRequest(ctx context.Context, request oauth2.DeviceAuthorizeRequester) (err error) {
	var (
		userCode, signature string

		storedReq oauth2.DeviceAuthorizeRequester
	)

	if userCode = request.GetRequestForm().Get(consts.FormParameterUserCode); len(userCode) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Cannot process the request, user_code is missing."))
	}

	if signature, err = d.Strategy.RFC8628UserCodeSignature(ctx, userCode); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if storedReq, err = d.Storage.GetDeviceCodeSessionByUserCode(ctx, signature, request.GetSession()); errors.Is(err, oauth2.ErrNotFound) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Cannot process the request, the user_code is either invalid or expired."))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	request.Merge(storedReq)

	client := request.GetClient()

	if !client.GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
	}

	session := request.GetSession()

	if request.GetUserCodeSignature() != signature {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Cannot process the request, user code signature mismatch."))
	}

	if session.GetExpiresAt(oauth2.UserCode).Before(time.Now().UTC()) || request.GetStatus() != oauth2.DeviceAuthorizeStatusNew {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Cannot process the request, the user_code is either invalid or expired."))
	}

	return nil
}

var (
	_ oauth2.RFC8628UserAuthorizeEndpointHandler = (*UserAuthorizeHandler)(nil)
)
