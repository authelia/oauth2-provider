// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"maps"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/x/errorsx"
)

// RefreshTokenTypeHandler validates a refresh token 'subject_token' or 'actor_token' and issues refresh tokens.
//
// A refresh token is only issued when the 'subject_token' is itself a refresh token, the case RFC 8693 Section 2.2.1
// describes of a client that needs access once the original credential is no longer valid, and never outlives it.
//
// RefreshTokenLifespan applies unless the client sets its own lifespan for the token exchange grant. A value of -1
// removes the configured limit, but the refresh token still expires with the 'subject_token'.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1
type RefreshTokenTypeHandler struct {
	Config oauth2.RFC8693ConfigProvider

	RefreshTokenLifespan time.Duration

	RefreshTokenScopes []string

	ScopeStrategy oauth2.ScopeStrategy

	hoauth2.CoreStrategy

	Storage

	// TokenRevocationStorage revokes the grant of a rotated refresh token presented as a 'subject_token' or
	// 'actor_token'. A replayed refresh token is refused with a server error when it is nil.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
	TokenRevocationStorage hoauth2.TokenRevocationStorage
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
	if session, _ := request.GetSession().(Session); session == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	client := request.GetClient()

	signature := c.RefreshTokenSignature(ctx, token)

	var or oauth2.Requester

	or, err = c.GetRefreshTokenSession(ctx, signature, newTokenSession(request.GetSession()))

	switch {
	case err == nil:
		if err = c.ValidateRefreshToken(ctx, or, token); err != nil {
			return nil, nil, errExchangeTokenValidation(err)
		}
	case errors.Is(err, oauth2.ErrInactiveToken):
		return nil, nil, c.handleRefreshTokenReuse(ctx, or, token, signature, err)
	default:
		return nil, nil, errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
	}

	if err = c.validateRefreshTokenUse(client, or); err != nil {
		return nil, nil, err
	}

	if err = validateExchangeTokenPolicy(ctx, request, c.Config, c.GetScopeStrategy(ctx, client), or, role); err != nil {
		return nil, nil, err
	}

	if role == tokenRoleSubject && IsIDJAGRequest(ctx, request, c.Config) {
		if err = c.validateIDJAGGrant(ctx, request, or); err != nil {
			return nil, nil, err
		}
	}

	// Convert to flat session with only access token claims.
	claims = tokenClaimsMap(or.GetSession())

	claims[consts.ClaimClientIdentifier] = or.GetClient().GetID()
	claims[consts.ClaimScope] = or.GetGrantedScopes()

	if expires := or.GetSession().GetExpiresAt(oauth2.RefreshToken); !expires.IsZero() {
		claims[consts.ClaimExpirationTime] = expires.Unix()
	}

	claims[consts.ClaimAudience] = oauth2.JoinGrantedAudienceAndResource(request.GetGrantedAudience(), request.GetGrantedResource())

	// An ID-JAG carries the authentication context of the login the refresh token was issued for (Section 4.3.3).
	if role == tokenRoleSubject && IsIDJAGRequest(ctx, request, c.Config) {
		maps.Copy(claims, authenticationContextClaims(or.GetSession()))
	}

	return or.GetSession(), claims, nil
}

func (c *RefreshTokenTypeHandler) validateRefreshTokenUse(client oauth2.Client, or oauth2.Requester) error {
	if scopes := c.RefreshTokenScopes; len(scopes) != 0 && !or.GetGrantedScopes().HasOneOf(scopes...) {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The refresh token was not granted scope %s and may thus not be used for token exchange.", strings.Join(scopes, " or ")))
	}

	// A refresh token is only usable while the client it was issued to may use the refresh_token grant, as ID-JAG
	// draft 04 Section 4.3.3 validates a refresh token subject as the refresh_token grant would. The registration of
	// the requesting client is current, so it is preferred when it is that client.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3.3
	owner := or.GetClient()
	if owner.GetID() == client.GetID() {
		owner = client
	}

	if !owner.GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 Client the refresh token was issued to is not allowed to use authorization grant '%s'.", consts.GrantTypeRefreshToken))
	}

	return nil
}

func (c *RefreshTokenTypeHandler) handleRefreshTokenReuse(ctx context.Context, or oauth2.Requester, token, signature string, inactive error) (err error) {
	if or == nil {
		return errors.WithStack(oauth2.ErrServerError.
			WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
			WithDebug("GetRefreshTokenSession must return a value for 'oauth2.Requester' when returning 'ErrInactiveToken'."))
	}

	if err = c.ValidateRefreshToken(ctx, or, token); !hoauth2.IsIntactToken(err) {
		return errExchangeTokenValidation(err)
	}

	if c.TokenRevocationStorage == nil {
		return errors.WithStack(oauth2.ErrServerError.WithDebug("The refresh token was reused but the handler has no TokenRevocationStorage to revoke its grant."))
	}

	if err = hoauth2.RevokeRefreshTokenFamily(ctx, c.TokenRevocationStorage, signature, or); err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithWrap(inactive).WithDebugError(inactive))
}

func (c *RefreshTokenTypeHandler) validateIDJAGGrant(ctx context.Context, request oauth2.AccessRequester, original oauth2.Requester) (err error) {
	client := request.GetClient()
	strategy := c.GetScopeStrategy(ctx, client)

	if err = validateSubjectTokenScope(request, original.GetGrantedScopes()); err != nil {
		return err
	}

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	audience := oauth2.GetAudienceStrategy(ctx, c.Config, client)

	if err = audience(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return errors.WithStack(err)
	}

	if err = audience(original.GetGrantedAudience(), request.GetRequestedAudience()); err != nil {
		return errors.WithStack(err)
	}

	resource := oauth2.GetResourceStrategy(ctx, c.Config, client)

	if err = resource(client.GetAudience(), request.GetRequestedResource()); err != nil {
		return errors.WithStack(err)
	}

	if err = resource(original.GetGrantedResource(), request.GetRequestedResource()); err != nil {
		return errors.WithStack(err)
	}

	if details := request.GetRequestedAuthorizationDetails(); len(details) != 0 {
		if err = oauth2.CheckAuthorizationDetailsContained(ctx, c.Config, original.GetGrantedAuthorizationDetails(), details); err != nil {
			return err
		}
	}

	return nil
}

func (c *RefreshTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if err = requireSubjectToken(request); err != nil {
		return err
	}

	if err = requireActorToken(request); err != nil {
		return err
	}

	// Apply the same refresh-token gating that AccessTokenTypeHandler.canIssueRefreshToken applies, but as an error
	// rather than a silent skip: when a client EXPLICITLY requests a refresh token via 'requested_token_type', the
	// AS must refuse with the spec-appropriate code if policy disallows it rather than silently downgrading.
	if !isRefreshTokenSubject(request) {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("A refresh token can only be issued by a token exchange whose '%s' is a refresh token.", consts.FormParameterSubjectToken))
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return errors.WithStack(oauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not registered for the '%s' grant type and so cannot be issued a refresh token via token exchange.", consts.GrantTypeRefreshToken))
	}

	if len(c.RefreshTokenScopes) > 0 && !request.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...) {
		return errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The token exchange request was not granted any of the scopes (%s) required by the authorization server to issue a refresh token.", strings.Join(c.RefreshTokenScopes, ", ")))
	}

	recordSubjectTokenDeadline(request)

	rtLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeTokenExchange, oauth2.RefreshToken, c.RefreshTokenLifespan)
	request.GetSession().SetExpiresAt(oauth2.RefreshToken, refreshTokenExpiry(request, rtLifespan))

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

	if !request.GetSession().GetExpiresAt(oauth2.RefreshToken).IsZero() {
		response.SetExpiresIn(c.GetExpiresIn(request, oauth2.RefreshToken, rtLifespan, time.Now().UTC()))
	}

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
