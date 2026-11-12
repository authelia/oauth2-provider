// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// AccessTokenTypeHandler validates an access token 'subject_token' or 'actor_token' and issues access tokens.
//
// An issued access token, and any refresh token issued with it, never outlives the 'subject_token', as RFC 8693
// Section 5 suggests a limited token lifetime to mitigate abuse of delegated rights. A refresh token is only issued
// with the access token when the 'subject_token' is itself a refresh token and the client opts in with
// GetAllowTokenExchangeRefreshToken: RFC 8693 Section 2.2.1 states one will typically not be issued when a temporary
// credential is exchanged for another. Issuing one rotates the 'subject_token' as the refresh token grant does, per RFC
// 9700 Section 4.14.2, unless oauth2.IsRefreshTokenRotationDisabledForRequest or RefreshTokenRotationOverrideClient
// disables rotation.
//
// AccessTokenLifespan and RefreshTokenLifespan apply unless the client sets its own lifespans for the token exchange
// grant. A RefreshTokenLifespan of -1 removes the configured limit, but the refresh token still expires with the
// 'subject_token'.
//
// When RFC 9396 authorization details are enabled, the access token carries the details granted to an access token or
// refresh token 'subject_token', of the types the client may request, as oauth2.AssignAuthorizationDetails assigns
// them for any 'authorization_details' parameter. A refresh token issued with it keeps every such granted detail. The
// details of an 'actor_token' are never carried.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6
type AccessTokenTypeHandler struct {
	Config oauth2.RFC8693ConfigProvider

	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration

	RefreshTokenScopes []string

	ScopeStrategy oauth2.ScopeStrategy

	hoauth2.CoreStrategy

	Storage

	// TokenRevocationStorage rotates a refresh token 'subject_token' and revokes its grant when it is replayed. An
	// exchange which must rotate is refused with a server error when it is nil.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
	TokenRevocationStorage hoauth2.TokenRevocationStorage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *AccessTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var (
		session Session
		ok      bool
	)

	if session, ok = request.GetSession().(Session); !ok || session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()

	if form.Get(consts.FormParameterSubjectTokenType) != consts.TokenTypeRFC8693AccessToken && form.Get(consts.FormParameterActorTokenType) != consts.TokenTypeRFC8693AccessToken {
		return nil
	}

	var claims map[string]any

	if form.Get(consts.FormParameterActorTokenType) == consts.TokenTypeRFC8693AccessToken {
		token := form.Get(consts.FormParameterActorToken)

		var actor oauth2.Requester

		priorActor := bindingOf(request.GetSession())

		if actor, claims, err = c.validate(ctx, request, token, tokenRoleActor); err != nil {
			return err
		}

		if err = inheritTokenBinding(ctx, c.Config, request, bindingOf(actor.GetSession()), tokenRoleActor, priorActor); err != nil {
			return err
		}

		session.SetActorToken(claims)
	}

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693AccessToken {
		token := form.Get(consts.FormParameterSubjectToken)

		var original oauth2.Requester

		priorSubject := bindingOf(request.GetSession())

		if original, claims, err = c.validate(ctx, request, token, tokenRoleSubject); err != nil {
			return err
		}

		subjectTokenSession := original.GetSession()

		if err = inheritTokenBinding(ctx, c.Config, request, bindingOf(subjectTokenSession), tokenRoleSubject, priorSubject); err != nil {
			return err
		}

		session.SetSubjectToken(claims)
		session.SetSubject(subjectTokenSession.GetSubject())
		carryAuthenticationContext(session, sessionAuthentication(subjectTokenSession))
		carrySubjectAuthorizationDetails(ctx, c.Config, request, original)
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *AccessTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	requestedTokenType := form.Get(consts.FormParameterRequestedTokenType)

	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	if !c.issues(requestedTokenType) {
		return nil
	}

	if err = c.issue(ctx, request, response); err != nil {
		return err
	}

	return nil
}

// CanHandleAuthorizationDetails implements oauth2.AuthorizationDetailsTokenEndpointHandler. It accepts the RFC 9396
// 'authorization_details' parameter of a token exchange requesting an access token, which is assigned from the
// details granted to the 'subject_token'.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-6
func (c *AccessTokenTypeHandler) CanHandleAuthorizationDetails(ctx context.Context, request oauth2.AccessRequester) bool {
	return c.issues(requestedTokenTypeIdentifier(ctx, request, c.Config))
}

// CanSkipClientAuth indicates if client auth can be skipped.
func (c *AccessTokenTypeHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled.
func (c *AccessTokenTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *AccessTokenTypeHandler) validate(ctx context.Context, request oauth2.AccessRequester, token string, role tokenRole) (original oauth2.Requester, claims map[string]any, err error) {
	if session, ok := request.GetSession().(Session); !ok || session == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	client := request.GetClient()

	signature := c.AccessTokenSignature(ctx, token)

	original, err = c.GetAccessTokenSession(ctx, signature, newTokenSession(request.GetSession()))

	restoreTokenSession(original)

	if err != nil {
		return nil, nil, errExchangeTokenLookup(err)
	} else if err = c.ValidateAccessToken(ctx, original, token); err != nil {
		return nil, nil, errExchangeTokenValidation(err)
	}

	if err = validateExchangeTokenPolicy(ctx, request, c.Config, c.Storage, c.GetScopeStrategy(ctx, client), original, role, false); err != nil {
		return nil, nil, err
	}

	// Convert to flat session with only access token claims.
	claims = tokenClaimsMap(original.GetSession())

	claims[consts.ClaimClientIdentifier] = original.GetClient().GetID()
	claims[consts.ClaimScope] = original.GetGrantedScopes()

	if expires := original.GetSession().GetExpiresAt(oauth2.AccessToken); !expires.IsZero() {
		claims[consts.ClaimExpirationTime] = expires.Unix()
	}

	claims[consts.ClaimAudience] = oauth2.JoinGrantedAudienceAndResource(request.GetGrantedAudience(), request.GetGrantedResource())

	return original, claims, nil
}

func (c *AccessTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if err = requireSubjectToken(request); err != nil {
		return err
	}

	if err = requireActorToken(request); err != nil {
		return err
	}

	var grant oauth2.AuthorizationDetails

	if grant, err = assignAuthorizationDetails(ctx, c.Config, request); err != nil {
		return err
	}

	issueRefreshToken := c.canIssueRefreshToken(request)

	var subjectSignature string

	rotate := issueRefreshToken && rotatesSubjectRefreshToken(ctx, c.Config, request)

	if rotate {
		if subjectSignature, err = beginSubjectRefreshTokenRotation(ctx, c.CoreStrategy, c.TokenRevocationStorage, request); err != nil {
			return err
		}
	}

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeTokenExchange, oauth2.AccessToken, c.AccessTokenLifespan)

	request.GetSession().SetExpiresAt(oauth2.AccessToken, capToSubjectTokenExpiry(request, time.Now().UTC().Add(atLifespan)))

	var token, signature string

	if token, signature, err = c.GenerateAccessToken(ctx, request); err != nil {
		return err
	}

	create := func(ctx context.Context) (err error) {
		if err = c.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
			return err
		}

		if !issueRefreshToken {
			return nil
		}

		var refresh, refreshSignature string

		recordSubjectTokenDeadline(request)
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, refreshTokenExpiry(request, oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeTokenExchange, oauth2.RefreshToken, c.RefreshTokenLifespan)))

		if refresh, refreshSignature, err = c.GenerateRefreshToken(ctx, request); err != nil {
			return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
		}

		if refreshSignature != "" {
			requester := request.Sanitize([]string{})

			// See: https://www.rfc-editor.org/rfc/rfc9396#section-6.1
			requester.SetRequestedAuthorizationDetails(grant)
			requester.SetGrantedAuthorizationDetails(grant)

			if err = c.CreateRefreshTokenSession(ctx, refreshSignature, signature, requester); err != nil {
				return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
			}
		}

		response.SetExtra(consts.FormParameterRefreshToken, refresh)

		return nil
	}

	switch {
	case rotate:
		err = commitSubjectRefreshTokenRotation(ctx, c.TokenRevocationStorage, request, subjectSignature, create)
	case issueRefreshToken:
		err = createInTransaction(ctx, c.Storage, create)
	default:
		err = create(ctx)
	}

	if err != nil {
		return err
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.BearerAccessToken)
	response.SetExpiresIn(c.GetExpiresIn(request, oauth2.AccessToken, atLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())
	response.SetExtra(consts.FormParameterIssuedTokenType, consts.TokenTypeRFC8693AccessToken)

	if details := request.GetGrantedAuthorizationDetails(); len(details) != 0 {
		response.SetExtra(consts.AccessResponseAuthorizationDetails, details)
	}

	return nil
}

func (c *AccessTokenTypeHandler) canIssueRefreshToken(request oauth2.Requester) bool {
	if !isRefreshTokenSubject(request) {
		return false
	}

	if !allowsRefreshTokenIssuance(request.GetClient()) {
		return false
	}

	// Require one of the refresh token scopes, if set.
	if len(c.RefreshTokenScopes) > 0 && !request.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...) {
		return false
	}

	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return false
	}

	return true
}

// GetScopeStrategy returns the locally-configured scope strategy if set, otherwise the one from Config.
func (c *AccessTokenTypeHandler) GetScopeStrategy(ctx context.Context, client oauth2.Client) oauth2.ScopeStrategy {
	if client != nil {
		if p, ok := client.(oauth2.ScopeStrategyProvider); ok {
			if strategy := p.GetScopeStrategy(ctx); strategy != nil {
				return strategy
			}
		}
	}

	if c.ScopeStrategy != nil {
		return c.ScopeStrategy
	}

	return c.Config.GetScopeStrategy(ctx)
}

// GetExpiresIn returns the time remaining until the session's expiration of the given token type, or the default
// lifespan when the session has none.
func (c *AccessTokenTypeHandler) GetExpiresIn(r oauth2.Requester, key oauth2.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}

	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}

// GrantTypesSupported returns nil because the handler only augments another grant.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *AccessTokenTypeHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return nil
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *AccessTokenTypeHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns nil because the handler does not issue ID Tokens.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *AccessTokenTypeHandler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return nil
}

// RFC8693TokenTypesSupported returns the configured access token type identifier when it is issuable.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *AccessTokenTypeHandler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return IssuableTokenTypes(ctx, c.Config, func(identifier string, _ oauth2.RFC8693TokenType) bool {
		return c.issues(identifier)
	})
}

func (c *AccessTokenTypeHandler) issues(identifier string) bool {
	return identifier == consts.TokenTypeRFC8693AccessToken
}

var (
	_ oauth2.TokenEndpointHandler                     = (*AccessTokenTypeHandler)(nil)
	_ oauth2.AuthorizationDetailsTokenEndpointHandler = (*AccessTokenTypeHandler)(nil)
)
