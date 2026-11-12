// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

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

// Deprecated: This handler is deprecated as a means to communicate that the ROPC grant type is widely discouraged and
// is at the time of this writing going to be omitted in the OAuth 2.1 spec. For more information on why this grant type
// is discouraged see: https://www.scottbrady91.com/oauth/why-the-resource-owner-password-credentials-grant-type-is-not-authentication-nor-suitable-for-modern-applications
type ResourceOwnerPasswordCredentialsGrantHandler struct {
	*HandleHelper
	// ResourceOwnerPasswordCredentialsGrantStorage is used to persist session data across requests.
	ResourceOwnerPasswordCredentialsGrantStorage ResourceOwnerPasswordCredentialsGrantStorage
	RefreshTokenStrategy                         RefreshTokenStrategy
	Config                                       interface {
		oauth2.ScopeStrategyProvider
		oauth2.AudienceStrategyProvider
		oauth2.ResourceStrategyProvider
		oauth2.RefreshTokenScopesProvider
		oauth2.RefreshTokenLifespanProvider
		oauth2.RefreshTokenMaximumLifespanProvider
		oauth2.AccessTokenLifespanProvider
	}
}

// HandleTokenEndpointRequest implements https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
func (c *ResourceOwnerPasswordCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeResourceOwnerPasswordCredentials) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The client is not allowed to use authorization grant 'password'."))
	}

	client := request.GetClient()
	strategy := oauth2.GetScopeStrategy(ctx, c.Config, client)

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err = oauth2.GetAudienceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	if err = oauth2.GetResourceStrategy(ctx, c.Config, client)(client.GetResource(), request.GetRequestedResource()); err != nil {
		return err
	}

	var subject string

	username := request.GetRequestForm().Get(consts.FormParameterUsername)
	password := request.GetRequestForm().Get(consts.FormParameterPassword)

	if username == "" || password == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Username or password are missing from the POST body."))
	} else if subject, err = c.ResourceOwnerPasswordCredentialsGrantStorage.Authenticate(ctx, username, password); errors.Is(err, oauth2.ErrNotFound) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Unable to authenticate the provided username and password credentials.").WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if session, ok := request.GetSession().(ResourceOwnerSession); ok {
		session.SetSubject(subject)
	}

	// Credentials must not be passed around, potentially leaking to the database!
	delete(request.GetRequestForm(), consts.FormParameterPassword)

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypePassword, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	rtLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypePassword, oauth2.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))

	now := time.Now().UTC()

	request.GetSession().SetExpiresAt(oauth2.AccessToken, oauth2.CapToExpiryDeadline(request.GetSession(), now.Add(atLifespan).Truncate(jwt.TimePrecision)))

	if expires := oauth2.RefreshTokenExpiry(request.GetSession(), rtLifespan, now); !expires.IsZero() {
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, expires)
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var refresh, refreshSignature string

	if canIssueRefreshToken(ctx, c.Config, request) {
		now := time.Now().UTC()

		if err = oauth2.RecordRefreshTokenExpiryDeadline(ctx, c.Config, request.GetClient(), request.GetSession(), now); err != nil {
			return err
		}

		request.GetSession().SetExpiresAt(oauth2.AccessToken, oauth2.CapToExpiryDeadline(request.GetSession(), request.GetSession().GetExpiresAt(oauth2.AccessToken)))

		rtLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypePassword, oauth2.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))

		if expires := oauth2.RefreshTokenExpiry(request.GetSession(), rtLifespan, now); !expires.IsZero() {
			request.GetSession().SetExpiresAt(oauth2.RefreshToken, expires)
		}

		if refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, request); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	if ctx, err = storage.MaybeBeginTx(ctx, c.ResourceOwnerPasswordCredentialsGrantStorage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.ResourceOwnerPasswordCredentialsGrantStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypePassword, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	var accessSignature string

	if accessSignature, err = c.IssueAccessToken(ctx, atLifespan, request, response); err != nil {
		return err
	}

	if refreshSignature != "" {
		if err = c.ResourceOwnerPasswordCredentialsGrantStorage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, request.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	if refresh != "" {
		response.SetExtra(consts.AccessResponseRefreshToken, refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.ResourceOwnerPasswordCredentialsGrantStorage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

// CanSkipClientAuth always returns false, client authentication is never skipped for the resource owner password
// credentials grant.
func (c *ResourceOwnerPasswordCredentialsGrantHandler) CanSkipClientAuth(ctx context.Context, _ oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly 'password'.
func (c *ResourceOwnerPasswordCredentialsGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (handle bool) {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return request.GetGrantTypes().ExactOne(consts.GrantTypeResourceOwnerPasswordCredentials)
}

// GrantTypesSupported returns the grant types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *ResourceOwnerPasswordCredentialsGrantHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.GrantTypeResourceOwnerPasswordCredentials}
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns nil because the handler does not issue ID Tokens.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *ResourceOwnerPasswordCredentialsGrantHandler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return nil
}

// RFC8693TokenTypesSupported returns nil because the handler does not issue RFC 8693 tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return nil
}

var (
	_ oauth2.TokenEndpointHandler = (*ResourceOwnerPasswordCredentialsGrantHandler)(nil)
)
