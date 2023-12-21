// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/storage"
)

// RefreshTokenGrantHandler handles access requests for the Refresh Token Flow.
type RefreshTokenGrantHandler struct {
	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	TokenRevocationStorage TokenRevocationStorage
	Config                 interface {
		oauth2.AccessTokenLifespanProvider
		oauth2.RefreshTokenLifespanProvider
		oauth2.ScopeStrategyProvider
		oauth2.AudienceStrategyProvider
		oauth2.RefreshTokenScopesProvider
	}
}

var (
	_ oauth2.TokenEndpointHandler = (*RefreshTokenGrantHandler)(nil)
)

// HandleTokenEndpointRequest implements https://datatracker.ietf.org/doc/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'refresh_token'."))
	}

	refresh := request.GetRequestForm().Get(consts.FormParameterRefreshToken)
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(ctx, refresh)
	orequest, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, request.GetSession())

	switch {
	case err == nil:
		if err = c.RefreshTokenStrategy.ValidateRefreshToken(ctx, orequest, refresh); err != nil {
			// The authorization server MUST ... validate the refresh token.
			// This needs to happen after store retrieval for the session to be hydrated properly.
			if errors.Is(err, oauth2.ErrTokenExpired) {
				return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebug(oauth2.ErrorToDebugRFC6749Error(err).Error()))
			}

			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithWrap(err).WithDebug(oauth2.ErrorToDebugRFC6749Error(err).Error()))
		}
	case errors.Is(err, oauth2.ErrInactiveToken):
		// Detected refresh token reuse.
		if e := c.handleRefreshTokenReuse(ctx, signature, orequest); e != nil {
			return errorsx.WithStack(e)
		}

		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebug(oauth2.ErrorToDebugRFC6749Error(err).Error()))
	case errors.Is(err, oauth2.ErrNotFound):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebugf("The refresh token has not been found: %s", oauth2.ErrorToDebugRFC6749Error(err).Error()))
	default:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(oauth2.ErrorToDebugRFC6749Error(err).Error()))
	}

	if !(len(c.Config.GetRefreshTokenScopes(ctx)) == 0 || orequest.GetGrantedScopes().HasOneOf(c.Config.GetRefreshTokenScopes(ctx)...)) {
		scopeNames := strings.Join(c.Config.GetRefreshTokenScopes(ctx), " or ")
		hint := fmt.Sprintf("The OAuth 2.0 Client was not granted scope %s and may thus not perform the 'refresh_token' authorization grant.", scopeNames)
		return errorsx.WithStack(oauth2.ErrScopeNotGranted.WithHint(hint))
	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if orequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance."))
	}

	request.SetID(orequest.GetID())
	request.SetSession(orequest.GetSession().Clone())

	/*
			There are two key points in the following spec section this addresses:
				1. If omitted the scope param should be treated as the same as the scope originally granted by the resource owner.
				2. The REQUESTED scope MUST NOT include any scope not originally granted.

			scope
					OPTIONAL.  The scope of the access request as described by Section 3.3.  The requested scope MUST NOT
		  			include any scope not originally granted by the resource owner, and if omitted is treated as equal to
		   			the scope originally granted by the resource owner.

			See https://datatracker.ietf.org/doc/html/rfc6749#section-6
	*/

	scopes := orequest.GetGrantedScopes()
	oscopes := false

	// Addresses point 1 of the text in RFC6749 Section 6.
	if len(request.GetRequestedScopes()) == 0 {
		request.SetRequestedScopes(scopes)
		oscopes = true
	}

	if len(request.GetRequestedAudience()) == 0 {
		request.SetRequestedAudience(orequest.GetGrantedAudience())
	}

	strategy := c.Config.GetScopeStrategy(ctx)

	for _, scope := range request.GetRequestedScopes() {
		if !oscopes && !scopes.Has(scope) {
			if client, ok := request.GetClient().(oauth2.RefreshFlowScopeClient); ok && client.GetRefreshFlowIgnoreOriginalGrantedScopes(ctx) {
				// Skips addressing point 2 of the text in RFC6749 Section 6 and instead just prevents the scope
				// requested from being granted.
				continue
			}

			// Addresses point 2 of the text in RFC6749 Section 6.
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The requested scope '%s' was not originally granted by the resource owner.", scope))
		}

		if !strategy(request.GetClient().GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}

		request.GrantScope(scope)
	}

	if err = c.Config.GetAudienceStrategy(ctx)(request.GetClient().GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	for _, audience := range request.GetRequestedAudience() {
		request.GrantAudience(audience)
	}

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeRefreshToken, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeRefreshToken, oauth2.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://datatracker.ietf.org/doc/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var (
		accessToken, refreshToken         string
		accessSignature, refreshSignature string
	)

	if accessToken, accessSignature, err = c.AccessTokenStrategy.GenerateAccessToken(ctx, requester); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(oauth2.ErrorToDebugRFC6749Error(err).Error()))
	}

	if refreshToken, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(oauth2.ErrorToDebugRFC6749Error(err).Error()))
	}

	signature := c.RefreshTokenStrategy.RefreshTokenSignature(ctx, requester.GetRequestForm().Get(consts.FormParameterRefreshToken))

	if ctx, err = storage.MaybeBeginTx(ctx, c.TokenRevocationStorage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(oauth2.ErrorToDebugRFC6749Error(err).Error()))
	}

	defer func() {
		err = c.handleRefreshTokenEndpointStorageError(ctx, err)
	}()

	var orequester oauth2.Requester

	if orequester, err = c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil); err != nil {
		return err
	}

	if err = c.TokenRevocationStorage.RevokeAccessToken(ctx, orequester.GetID()); err != nil {
		return err
	}

	if err = c.TokenRevocationStorage.RevokeRefreshTokenMaybeGracePeriod(ctx, orequester.GetID(), signature); err != nil {
		return err
	}

	srequester := requester.Sanitize(nil)
	srequester.SetID(orequester.GetID())

	if err = c.TokenRevocationStorage.CreateAccessTokenSession(ctx, accessSignature, srequester); err != nil {
		return err
	}

	if rtrequester, ok := requester.(oauth2.RefreshTokenAccessRequester); ok {
		srtrequester := rtrequester.SanitizeRestoreRefreshTokenOriginalRequester(orequester)

		srtrequester.SetSession(requester.GetSession().Clone())

		if err = c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, srtrequester); err != nil {
			return err
		}
	} else {
		if err = c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, srequester); err != nil {
			return err
		}
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType(oauth2.BearerAccessToken)
	responder.SetExpiresIn(getExpiresIn(requester, oauth2.AccessToken, oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeRefreshToken, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx)), time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra(consts.AccessResponseRefreshToken, refreshToken)

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return err
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.3
//
//	The basic idea is to change the refresh token
//	value with every refresh request in order to detect attempts to
//	obtain access tokens using old refresh tokens.  Since the
//	authorization server cannot determine whether the attacker or the
//	legitimate client is trying to access, in case of such an access
//	attempt the valid refresh token and the access authorization
//	associated with it are both revoked.
func (c *RefreshTokenGrantHandler) handleRefreshTokenReuse(ctx context.Context, signature string, req oauth2.Requester) (err error) {
	ctx, err = storage.MaybeBeginTx(ctx, c.TokenRevocationStorage)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		err = c.handleRefreshTokenEndpointStorageError(ctx, err)
	}()

	if err = c.TokenRevocationStorage.DeleteRefreshTokenSession(ctx, signature); err != nil {
		return err
	} else if err = c.TokenRevocationStorage.RevokeRefreshToken(
		ctx, req.GetID(),
	); err != nil && !errors.Is(err, oauth2.ErrNotFound) {
		return err
	} else if err = c.TokenRevocationStorage.RevokeAccessToken(
		ctx, req.GetID(),
	); err != nil && !errors.Is(err, oauth2.ErrNotFound) {
		return err
	}

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return err
	}

	return nil
}

func (c *RefreshTokenGrantHandler) handleRefreshTokenEndpointStorageError(ctx context.Context, storageErr error) (err error) {
	if storageErr == nil {
		return nil
	}

	defer func() {
		if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.TokenRevocationStorage); rollBackTxnErr != nil {
			err = errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
		}
	}()

	if errors.Is(storageErr, oauth2.ErrSerializationFailure) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.
			WithDebugf(storageErr.Error()).
			WithHint("Failed to refresh token because of multiple concurrent requests using the same token which is not allowed."))
	}

	if errors.Is(storageErr, oauth2.ErrNotFound) || errors.Is(storageErr, oauth2.ErrInactiveToken) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.
			WithDebugf(storageErr.Error()).
			WithHint("Failed to refresh token because of multiple concurrent requests using the same token which is not allowed."))
	}

	return errorsx.WithStack(oauth2.ErrServerError.WithWrap(storageErr).WithDebug(storageErr.Error()))
}

func (c *RefreshTokenGrantHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

func (c *RefreshTokenGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token".
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeRefreshToken)
}
