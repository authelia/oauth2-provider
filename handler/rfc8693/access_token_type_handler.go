package rfc8693

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/storage"
)

type AccessTokenTypeHandler struct {
	Config               oauth2.RFC8693ConfigProvider
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
	RefreshTokenScopes   []string
	hoauth2.CoreStrategy
	ScopeStrategy oauth2.ScopeStrategy
	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *AccessTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	if form.Get(consts.FormParameterSubjectTokenType) != consts.TokenTypeRFC8693AccessToken && form.Get(consts.FormParameterActorTokenType) != consts.TokenTypeRFC8693AccessToken {
		return nil
	}

	if form.Get(consts.FormParameterActorTokenType) == consts.TokenTypeRFC8693AccessToken {
		token := form.Get(consts.FormParameterActorToken)
		if _, unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetActorToken(unpacked)
		}
	}

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693AccessToken {
		token := form.Get(consts.FormParameterSubjectToken)
		if subjectTokenSession, unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetSubjectToken(unpacked)
			session.SetSubject(subjectTokenSession.GetSubject())
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *AccessTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, responder oauth2.AccessResponder) error {
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

	if err := c.issue(ctx, request, responder); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *AccessTokenTypeHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *AccessTokenTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *AccessTokenTypeHandler) validate(ctx context.Context, request oauth2.AccessRequester, token string) (oauth2.Session, map[string]any, error) {
	session, _ := request.GetSession().(Session)
	if session == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug(
			"Failed to perform token exchange because the session is not of the right type."))
	}

	client := request.GetClient()

	sig := c.CoreStrategy.AccessTokenSignature(ctx, token)
	or, err := c.Storage.GetAccessTokenSession(ctx, sig, request.GetSession())
	if err != nil {
		return nil, nil, errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, or, token); err != nil {
		return nil, nil, err
	}

	subjectTokenClientID := or.GetClient().GetID()
	// forbid original subjects client to exchange its own token
	if client.GetID() == subjectTokenClientID {
		return nil, nil, errors.WithStack(oauth2.ErrRequestForbidden.WithHint("Clients are not allowed to perform a token exchange on their own tokens."))
	}

	// Check if the client is allowed to exchange this token
	if subjectTokenClient, ok := or.GetClient().(Client); ok {
		allowed := subjectTokenClient.GetTokenExchangePermitted(client)
		if !allowed {
			return nil, nil, errors.WithStack(oauth2.ErrRequestForbidden.WithHintf(
				"The OAuth 2.0 client is not permitted to exchange a subject token issued to client %s", subjectTokenClientID))
		}
	}

	// Scope check
	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(or.GetGrantedScopes(), scope) {
			return nil, nil, errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The subject token is not granted '%s' and so this scope cannot be requested.", scope))
		}
	}

	// Convert to flat session with only access token claims
	claims := session.AccessTokenClaimsMap()
	claims[consts.ClaimClientIdentifier] = or.GetClient().GetID()
	claims[consts.ClaimScope] = or.GetGrantedScopes()
	claims[consts.ClaimAudience] = or.GetGrantedAudience()

	return or.GetSession(), claims, nil
}

func (c *AccessTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
	request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan))

	token, signature, err := c.CoreStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		return err
	} else if err := c.Storage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return err
	}

	issueRefreshToken := c.canIssueRefreshToken(request)
	if issueRefreshToken {
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Round(time.Second))
		refresh, refreshSignature, err := c.CoreStrategy.GenerateRefreshToken(ctx, request)
		if err != nil {
			return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
		}

		if refreshSignature != "" {
			if err := c.Storage.CreateRefreshTokenSession(ctx, refreshSignature, request.Sanitize([]string{})); err != nil {
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
	response.SetExpiresIn(c.getExpiresIn(request, oauth2.AccessToken, c.AccessTokenLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())

	return nil
}

func (c *AccessTokenTypeHandler) canIssueRefreshToken(request oauth2.Requester) bool {
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

func (c *AccessTokenTypeHandler) getExpiresIn(r oauth2.Requester, key oauth2.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
