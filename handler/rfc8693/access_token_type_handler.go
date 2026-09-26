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
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// AccessTokenTypeHandler validates an access token 'subject_token' or 'actor_token' and issues access tokens.
//
// An issued access token, and any refresh token issued with it, never outlives the 'subject_token', as RFC 8693
// Section 5 suggests a limited token lifetime to mitigate abuse of delegated rights. A refresh token is only issued
// with the access token when the 'subject_token' is itself a refresh token: RFC 8693 Section 2.2.1 states one will
// typically not be issued when a temporary credential is exchanged for another.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1
type AccessTokenTypeHandler struct {
	Config oauth2.RFC8693ConfigProvider

	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration

	RefreshTokenScopes []string

	ScopeStrategy oauth2.ScopeStrategy

	hoauth2.CoreStrategy

	Storage
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

		var actorTokenSession oauth2.Session

		priorActor := bindingOf(request.GetSession())

		if actorTokenSession, claims, err = c.validate(ctx, request, token, tokenRoleActor); err != nil {
			return err
		}

		if err = inheritTokenBinding(request, bindingOf(actorTokenSession), tokenRoleActor, priorActor); err != nil {
			return err
		}

		session.SetActorToken(claims)
	}

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693AccessToken {
		token := form.Get(consts.FormParameterSubjectToken)

		var subjectTokenSession oauth2.Session

		priorSubject := bindingOf(request.GetSession())

		if subjectTokenSession, claims, err = c.validate(ctx, request, token, tokenRoleSubject); err != nil {
			return err
		}

		if err = inheritTokenBinding(request, bindingOf(subjectTokenSession), tokenRoleSubject, priorSubject); err != nil {
			return err
		}

		session.SetSubjectToken(claims)
		session.SetSubject(subjectTokenSession.GetSubject())
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

	if requestedTokenType != consts.TokenTypeRFC8693AccessToken {
		return nil
	}

	if err = c.issue(ctx, request, response); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped.
func (c *AccessTokenTypeHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled.
func (c *AccessTokenTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *AccessTokenTypeHandler) validate(ctx context.Context, request oauth2.AccessRequester, token string, role tokenRole) (s oauth2.Session, claims map[string]any, err error) {
	var original oauth2.Requester

	if session, ok := request.GetSession().(Session); !ok || session == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	client := request.GetClient()

	signature := c.AccessTokenSignature(ctx, token)

	if original, err = c.GetAccessTokenSession(ctx, signature, newTokenSession(request.GetSession())); err != nil {
		return nil, nil, errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
	} else if err = c.ValidateAccessToken(ctx, original, token); err != nil {
		return nil, nil, err
	}

	if err = validateExchangeTokenPolicy(ctx, request, c.Config, c.GetScopeStrategy(ctx, client), original, role); err != nil {
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

	return original.GetSession(), claims, nil
}

func (c *AccessTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if err = requireSubjectToken(request); err != nil {
		return err
	}

	request.GetSession().SetExpiresAt(oauth2.AccessToken, capToSubjectTokenExpiry(request, time.Now().UTC().Add(c.AccessTokenLifespan)))

	var token, signature string

	if token, signature, err = c.GenerateAccessToken(ctx, request); err != nil {
		return err
	} else if err = c.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return err
	}

	issueRefreshToken := c.canIssueRefreshToken(request)

	if issueRefreshToken {
		var refresh, refreshSignature string

		recordSubjectTokenDeadline(request)
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, capToSubjectTokenExpiry(request, time.Now().UTC().Add(c.RefreshTokenLifespan)).Truncate(jwt.TimePrecision))
		if refresh, refreshSignature, err = c.GenerateRefreshToken(ctx, request); err != nil {
			return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
		}

		if refreshSignature != "" {
			if err = c.CreateRefreshTokenSession(ctx, refreshSignature, signature, request.Sanitize([]string{})); err != nil {
				if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.Storage); rollBackTxnErr != nil {
					err = rollBackTxnErr
				}
				return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
			}
		}

		response.SetExtra(consts.FormParameterRefreshToken, refresh)
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.BearerAccessToken)
	response.SetExpiresIn(c.GetExpiresIn(request, oauth2.AccessToken, c.AccessTokenLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())
	response.SetExtra(consts.FormParameterIssuedTokenType, consts.TokenTypeRFC8693AccessToken)

	return nil
}

func (c *AccessTokenTypeHandler) canIssueRefreshToken(request oauth2.Requester) bool {
	if !isRefreshTokenSubject(request) {
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

func (c *AccessTokenTypeHandler) GetExpiresIn(r oauth2.Requester, key oauth2.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}

	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
