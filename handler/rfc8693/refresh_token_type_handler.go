// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type RefreshTokenTypeHandler struct {
	Config oauth2.RFC8693ConfigProvider

	RefreshTokenLifespan time.Duration

	RefreshTokenScopes []string

	ScopeStrategy oauth2.ScopeStrategy

	hoauth2.CoreStrategy

	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *RefreshTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
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

	if form.Get(consts.FormParameterSubjectTokenType) != consts.TokenTypeRFC8693RefreshToken && form.Get(consts.FormParameterActorTokenType) != consts.TokenTypeRFC8693RefreshToken {
		return nil
	}

	if form.Get(consts.FormParameterActorTokenType) == consts.TokenTypeRFC8693RefreshToken {
		var unpacked map[string]any

		token := form.Get(consts.FormParameterActorToken)

		var actorTokenSession oauth2.Session

		priorActor := bindingOf(request.GetSession())

		if actorTokenSession, unpacked, err = c.validate(ctx, request, token, tokenRoleActor); err != nil {
			return err
		}

		if err = inheritTokenBinding(request, bindingOf(actorTokenSession), tokenRoleActor, priorActor); err != nil {
			return err
		}

		session.SetActorToken(unpacked)
	}

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693RefreshToken {
		var (
			subjectTokenSession oauth2.Session
			unpacked            map[string]any
		)

		token := form.Get(consts.FormParameterSubjectToken)

		priorSubject := bindingOf(request.GetSession())

		if subjectTokenSession, unpacked, err = c.validate(ctx, request, token, tokenRoleSubject); err != nil {
			return err
		}

		if err = inheritTokenBinding(request, bindingOf(subjectTokenSession), tokenRoleSubject, priorSubject); err != nil {
			return err
		}

		session.SetSubjectToken(unpacked)
		session.SetSubject(subjectTokenSession.GetSubject())
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *RefreshTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
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

	if requestedTokenType != consts.TokenTypeRFC8693RefreshToken {
		return nil
	}

	if err = c.issue(ctx, request, response); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *RefreshTokenTypeHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *RefreshTokenTypeHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *RefreshTokenTypeHandler) validate(ctx context.Context, request oauth2.AccessRequester, token string, role tokenRole) (s oauth2.Session, claims map[string]any, err error) {
	session, _ := request.GetSession().(Session)
	if session == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	client := request.GetClient()

	signature := c.RefreshTokenSignature(ctx, token)

	var or oauth2.Requester

	if or, err = c.GetRefreshTokenSession(ctx, signature, request.GetSession()); err != nil {
		return nil, nil, errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
	} else if err = c.ValidateRefreshToken(ctx, or, token); err != nil {
		return nil, nil, err
	}

	if err = validateExchangeTokenPolicy(ctx, request, c.Config, c.GetScopeStrategy(ctx, client), or, role); err != nil {
		return nil, nil, err
	}

	// Convert to flat session with only access token claims.
	claims = session.AccessTokenClaimsMap()

	claims[consts.ClaimClientIdentifier] = or.GetClient().GetID()
	claims[consts.ClaimScope] = or.GetGrantedScopes()
	claims[consts.ClaimAudience] = oauth2.JoinGrantedAudienceAndResource(request.GetGrantedAudience(), request.GetGrantedResource())

	return or.GetSession(), claims, nil
}

func (c *RefreshTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	// Apply the same refresh-token gating that AccessTokenTypeHandler.canIssueRefreshToken applies, but as an error
	// rather than a silent skip: when a client EXPLICITLY requests a refresh token via 'requested_token_type', the
	// AS must refuse with the spec-appropriate code if policy disallows it rather than silently downgrading.
	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return errors.WithStack(oauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not registered for the '%s' grant type and so cannot be issued a refresh token via token exchange.", consts.GrantTypeRefreshToken))
	}

	if len(c.RefreshTokenScopes) > 0 && !request.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...) {
		return errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The token exchange request was not granted any of the scopes (%s) required by the authorization server to issue a refresh token.", strings.Join(c.RefreshTokenScopes, ", ")))
	}

	request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Truncate(jwt.TimePrecision))

	var token, signature string

	if token, signature, err = c.GenerateRefreshToken(ctx, request); err != nil {
		return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
	}

	if signature != "" {
		// This exchange issues a refresh token only, so there is no paired access token signature to record.
		if err = c.CreateRefreshTokenSession(ctx, signature, "", request.Sanitize([]string{})); err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.Storage); rollBackTxnErr != nil {
				err = rollBackTxnErr
			}

			return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
		}
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.RFC8693NAToken)
	response.SetExpiresIn(c.GetExpiresIn(request, oauth2.RefreshToken, c.RefreshTokenLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())
	response.SetExtra(consts.FormParameterIssuedTokenType, consts.TokenTypeRFC8693RefreshToken)

	return nil
}

// GetScopeStrategy returns the locally-configured scope strategy if set, otherwise the one from Config.
func (c *RefreshTokenTypeHandler) GetScopeStrategy(ctx context.Context, client oauth2.Client) oauth2.ScopeStrategy {
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

func (c *RefreshTokenTypeHandler) GetExpiresIn(r oauth2.Requester, key oauth2.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}

	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
