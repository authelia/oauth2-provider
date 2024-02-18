package rfc8628

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

type UserAuthorizeHandler struct {
	Storage  RFC8628Storage
	Strategy RFC8628CodeStrategy
	Config   interface {
		oauth2.DeviceAuthorizeConfigProvider
	}
}

// PopulateRFC8628UserAuthorizeEndpointResponse is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
func (d *UserAuthorizeHandler) PopulateRFC8628UserAuthorizeEndpointResponse(ctx context.Context, req oauth2.DeviceAuthorizeRequester, resp oauth2.RFC8628UserAuthorizeResponder) error {
	status := req.GetStatus()
	// the request shall be either approved or denied
	if status != oauth2.DeviceAuthorizeStatusApproved && status != oauth2.DeviceAuthorizeStatusDenied {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithDebug("Failed to perform device authorization because the request status is invalid."))
	}

	resp.SetStatus(oauth2.DeviceAuthorizeStatusToString(status))

	// Stores the auth session and approval status into user code session instead of device code session.
	userCodeSignature := req.GetUserCodeSignature()
	if err := d.Storage.UpdateUserCodeSession(ctx, userCodeSignature, req); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (d *UserAuthorizeHandler) HandleRFC8628UserAuthorizeEndpointRequest(ctx context.Context, dur oauth2.DeviceAuthorizeRequester) error {
	userCode := dur.GetRequestForm().Get(consts.FormParameterUserCode)
	if len(userCode) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Cannot process the request, user_code is missing."))
	}

	userCodeSig, err := d.Strategy.UserCodeSignature(ctx, userCode)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	storedReq, err := d.Storage.GetUserCodeSession(ctx, userCodeSig, dur.GetSession())
	if errors.Is(err, oauth2.ErrNotFound) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Cannot process the request, the user_code is either invalid or expired."))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	dur.Merge(storedReq)

	client := dur.GetClient()
	if !client.GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) { // shall not happen?
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
	}

	session := dur.GetSession()
	if dur.GetUserCodeSignature() != userCodeSig { // shall not happen?
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Cannot process the request, user code signature mismatching."))
	}

	if session.GetExpiresAt(oauth2.UserCode).Before(time.Now().UTC()) || dur.GetStatus() != oauth2.DeviceAuthorizeStatusNew {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Cannot process the request, the user_code is either invalid or expired."))
	}

	return nil
}

var (
	_ oauth2.RFC8628UserAuthorizeEndpointHandler = (*UserAuthorizeHandler)(nil)
)
