// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/storage"
)

var _ oauth2.TokenEndpointHandler = (*RefreshTokenGrantHandler)(nil)

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

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'refresh_token'."))
	}

	refresh := request.GetRequestForm().Get("refresh_token")
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(ctx, refresh)
	originalRequest, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, request.GetSession())
	if errors.Is(err, oauth2.ErrInactiveToken) {
		// Detected refresh token reuse
		if rErr := c.handleRefreshTokenReuse(ctx, signature, originalRequest); rErr != nil {
			return errorsx.WithStack(rErr)
		}

		return errorsx.WithStack(oauth2.ErrInactiveToken.WithWrap(err).WithDebug(err.Error()))
	} else if errors.Is(err, oauth2.ErrNotFound) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebugf("The refresh token has not been found: %s", err.Error()))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.RefreshTokenStrategy.ValidateRefreshToken(ctx, originalRequest, refresh); err != nil {
		// The authorization server MUST ... validate the refresh token.
		// This needs to happen after store retrieval for the session to be hydrated properly
		if errors.Is(err, oauth2.ErrTokenExpired) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
		}
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	if !(len(c.Config.GetRefreshTokenScopes(ctx)) == 0 || originalRequest.GetGrantedScopes().HasOneOf(c.Config.GetRefreshTokenScopes(ctx)...)) {
		scopeNames := strings.Join(c.Config.GetRefreshTokenScopes(ctx), " or ")
		hint := fmt.Sprintf("The OAuth 2.0 Client was not granted scope %s and may thus not perform the 'refresh_token' authorization grant.", scopeNames)
		return errorsx.WithStack(oauth2.ErrScopeNotGranted.WithHint(hint))
	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if originalRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance."))
	}

	request.SetSession(originalRequest.GetSession().Clone())
	request.SetRequestedScopes(originalRequest.GetRequestedScopes())
	request.SetRequestedAudience(originalRequest.GetRequestedAudience())

	for _, scope := range originalRequest.GetGrantedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(request.GetClient().GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
		request.GrantScope(scope)
	}

	if err := c.Config.GetAudienceStrategy(ctx)(request.GetClient().GetAudience(), originalRequest.GetGrantedAudience()); err != nil {
		return err
	}

	for _, audience := range originalRequest.GetGrantedAudience() {
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

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	accessToken, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	refreshToken, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	signature := c.RefreshTokenStrategy.RefreshTokenSignature(ctx, requester.GetRequestForm().Get("refresh_token"))

	ctx, err = storage.MaybeBeginTx(ctx, c.TokenRevocationStorage)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		err = c.handleRefreshTokenEndpointStorageError(ctx, err)
	}()

	ts, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)
	if err != nil {
		return err
	} else if err := c.TokenRevocationStorage.RevokeAccessToken(ctx, ts.GetID()); err != nil {
		return err
	}

	if err := c.TokenRevocationStorage.RevokeRefreshTokenMaybeGracePeriod(ctx, ts.GetID(), signature); err != nil {
		return err
	}

	storeReq := requester.Sanitize([]string{})
	storeReq.SetID(ts.GetID())

	if err = c.TokenRevocationStorage.CreateAccessTokenSession(ctx, accessSignature, storeReq); err != nil {
		return err
	}

	if err = c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, storeReq); err != nil {
		return err
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	atLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeRefreshToken, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, oauth2.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("refresh_token", refreshToken)

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return err
	}

	return nil
}

// Reference: https://tools.ietf.org/html/rfc6819#section-5.2.2.3
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
	return requester.GetGrantTypes().ExactOne("refresh_token")
}
