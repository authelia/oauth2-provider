package oauth2

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type CodeTokenEndpointHandler interface {
	ValidateGrantTypes(ctx context.Context, requester oauth2.AccessRequester) error
	ValidateCodeAndSession(ctx context.Context, request oauth2.AccessRequester, authorizeRequest oauth2.Requester, code string) error
	GetCodeAndSession(ctx context.Context, request oauth2.AccessRequester) (string, string, oauth2.Requester, error)
	UpdateLastChecked(ctx context.Context, request oauth2.AccessRequester, authorizeRequest oauth2.Requester) error
	InvalidateSession(ctx context.Context, signature string, authorizeRequest oauth2.Requester) error
	CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool
	CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool
	DeviceCodeSignature(ctx context.Context, code string) (string, error)
}

type GenericCodeTokenEndpointHandler struct {
	CodeTokenEndpointHandler

	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	CoreStorage            CoreStorage
	TokenRevocationStorage TokenRevocationStorage
	Config                 interface {
		oauth2.AccessTokenLifespanProvider
		oauth2.RefreshTokenLifespanProvider
		oauth2.RefreshTokenScopesProvider
	}
}

var _ oauth2.TokenEndpointHandler = (*GenericCodeTokenEndpointHandler)(nil)

func (c *GenericCodeTokenEndpointHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(oauth2.ErrUnknownRequest))
	}

	if err := c.ValidateGrantTypes(ctx, request); err != nil {
		return err
	}

	code, _, ar, err := c.GetCodeAndSession(ctx, request)
	if errors.Is(err, oauth2.ErrInvalidatedDeviceCode) {
		if ar == nil {
			return oauth2.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug(`getCodeSession must return a value for "oauth2.Requester" when returning "ErrInvalidatedAuthorizeCode" or "ErrInvalidatedDeviceCode".`)
		}

		hint := "The authorization code has already been used."
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hint))
	} else if errors.Is(err, oauth2.ErrInvalidatedAuthorizeCode) {
		if ar == nil {
			return oauth2.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug(`getCodeSession must return a value for "oauth2.Requester" when returning "ErrInvalidatedAuthorizeCode" or "ErrInvalidatedDeviceCode".`)
		}

		// If an authorize code is used twice, we revoke all refresh and access tokens associated with this request.
		reqID := ar.GetID()
		hint := "The authorization code has already been used."
		debug := ""
		if revErr := c.TokenRevocationStorage.RevokeAccessToken(ctx, reqID); revErr != nil {
			hint += " Additionally, an error occurred during processing the access token revocation."
			debug += "Revocation of access_token lead to error " + revErr.Error() + "."
		}
		if revErr := c.TokenRevocationStorage.RevokeRefreshToken(ctx, reqID); revErr != nil {
			hint += " Additionally, an error occurred during processing the refresh token revocation."
			debug += "Revocation of refresh_token lead to error " + revErr.Error() + "."
		}
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hint).WithDebug(debug))
	} else if errors.Is(err, oauth2.ErrAuthorizationPending) || errors.Is(err, oauth2.ErrAccessDenied) ||
		errors.Is(err, oauth2.ErrDeviceExpiredToken) || errors.Is(err, oauth2.ErrSlowDown) ||
		errors.Is(err, oauth2.ErrInvalidGrant) {
		return errorsx.WithStack(err)
	} else if err != nil && errors.Is(err, oauth2.ErrNotFound) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	// update last checked if there is error validating / processing the request.
	defer func() {
		if err != nil && ar != nil {
			_ = c.UpdateLastChecked(ctx, request, ar)
		}
	}()

	err = c.ValidateCodeAndSession(ctx, request, ar, code)
	if err != nil {
		return errorsx.WithStack(err)
	}

	// Override scopes.
	request.SetRequestedScopes(ar.GetRequestedScopes())

	// Override audiences.
	request.SetRequestedAudience(ar.GetRequestedAudience())

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if ar.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// ensure that the "redirect_uri" parameter is present if the
	// "redirect_uri" parameter was included in the initial authorization
	// request as described in Section 4.1.1, and if included ensure that
	// their values are identical.
	forcedRedirectURI := ar.GetRequestForm().Get(consts.FormParameterRedirectURI)
	if forcedRedirectURI != "" && forcedRedirectURI != request.GetRequestForm().Get(consts.FormParameterRedirectURI) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'redirect_uri' from this request does not match the one from the authorize request."))
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetSession(ar.GetSession())
	request.SetID(ar.GetID())

	gt := oauth2.GrantTypeAuthorizationCode

	if request.GetGrantTypes().ExactOne(string(oauth2.GrantTypeDeviceCode)) {
		gt = oauth2.GrantTypeDeviceCode
	}

	var lifespan time.Duration

	lifespan = oauth2.GetEffectiveLifespan(request.GetClient(), gt, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(lifespan).Truncate(jwt.TimePrecision))

	lifespan = oauth2.GetEffectiveLifespan(request.GetClient(), gt, oauth2.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))

	if lifespan > -1 {
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(lifespan).Truncate(jwt.TimePrecision))
	}

	return nil
}

func (c *GenericCodeTokenEndpointHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	code, signature, ar, err := c.GetCodeAndSession(ctx, requester)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if err := c.ValidateCodeAndSession(ctx, requester, ar, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithWrap(err).WithDebugError(err))
	}

	for _, scope := range ar.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range ar.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	var refresh, refreshSignature string
	if c.canIssueRefreshToken(ctx, ar) {
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}
	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.InvalidateSession(ctx, signature, ar); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType(oauth2.BearerAccessToken)
	atLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeAuthorizationCode, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, oauth2.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra(consts.AccessResponseRefreshToken, refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (c *GenericCodeTokenEndpointHandler) canIssueRefreshToken(ctx context.Context, request oauth2.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)

	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !request.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}

	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return false
	}

	return true
}

func (c *GenericCodeTokenEndpointHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return c.CodeTokenEndpointHandler.CanSkipClientAuth(ctx, requester)
}

func (c *GenericCodeTokenEndpointHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	return c.CodeTokenEndpointHandler.CanHandleTokenEndpointRequest(ctx, requester)
}

var (
	_ CodeTokenEndpointHandler = (*GenericCodeTokenEndpointHandler)(nil)
)
