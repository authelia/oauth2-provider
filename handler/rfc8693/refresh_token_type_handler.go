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

type RefreshTokenTypeHandler struct {
	Config               oauth2.RFC8693ConfigProvider
	RefreshTokenLifespan time.Duration
	RefreshTokenScopes   []string
	hoauth2.CoreStrategy
	ScopeStrategy oauth2.ScopeStrategy
	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *RefreshTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	if form.Get(consts.FormParameterSubjectTokenType) != consts.TokenTypeRFC8693RefreshToken && form.Get(consts.FormParameterActorTokenType) != consts.TokenTypeRFC8693RefreshToken {
		return nil
	}

	if form.Get(consts.FormParameterActorTokenType) == consts.TokenTypeRFC8693RefreshToken {
		token := form.Get(consts.FormParameterActorToken)
		if _, unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetActorToken(unpacked)
		}
	}

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693RefreshToken {
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
func (c *RefreshTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	session, _ := requester.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := requester.GetRequestForm()
	requestedTokenType := form.Get(consts.FormParameterRequestedTokenType)
	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	if requestedTokenType != consts.TokenTypeRFC8693RefreshToken {
		return nil
	}

	if err := c.issue(ctx, requester, responder); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *RefreshTokenTypeHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *RefreshTokenTypeHandler) CanHandleTokenEndpointRequest(_ context.Context, requester oauth2.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *RefreshTokenTypeHandler) validate(ctx context.Context, requester oauth2.AccessRequester, token string) (s oauth2.Session, claims map[string]any, err error) {
	session, _ := requester.GetSession().(Session)
	if session == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug(
			"Failed to perform token exchange because the session is not of the right type."))
	}

	client := requester.GetClient()

	signature := c.RefreshTokenSignature(ctx, token)

	var or oauth2.Requester

	if or, err = c.GetRefreshTokenSession(ctx, signature, requester.GetSession()); err != nil {
		return nil, nil, errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
	} else if err = c.ValidateRefreshToken(ctx, or, token); err != nil {
		return nil, nil, err
	}

	tokenClientID := or.GetClient().GetID()

	// Prevent clients from exchanging their own tokens.
	if client.GetID() == tokenClientID {
		return nil, nil, errors.WithStack(
			oauth2.ErrRequestForbidden.WithHint("Clients are not allowed to perform a token exchange on their own tokens."))
	}

	// Check if the client is allowed to exchange this token.
	if subjectTokenClient, ok := or.GetClient().(Client); ok {
		allowed := subjectTokenClient.GetTokenExchangePermitted(client)
		if !allowed {
			return nil, nil, errors.WithStack(oauth2.ErrRequestForbidden.WithHintf(
				"The OAuth 2.0 client is not permitted to exchange a subject token issued to client %s", tokenClientID))
		}
	}

	// Scope check.
	for _, scope := range requester.GetRequestedScopes() {
		if !c.ScopeStrategy(or.GetGrantedScopes(), scope) {
			return nil, nil, errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The subject token is not granted '%s' and so this scope cannot be requested.", scope))
		}
	}

	// Convert to flat session with only access token claims.
	claims = session.AccessTokenClaimsMap()

	claims[consts.ClaimClientIdentifier] = or.GetClient().GetID()
	claims[consts.ClaimScope] = or.GetGrantedScopes()
	claims[consts.ClaimAudience] = or.GetGrantedAudience()

	return or.GetSession(), claims, nil
}

func (c *RefreshTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
	request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Truncate(jwt.TimePrecision))
	refresh, refreshSignature, err := c.GenerateRefreshToken(ctx, request)
	if err != nil {
		return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
	}

	if refreshSignature != "" {
		if err = c.CreateRefreshTokenSession(ctx, refreshSignature, request.Sanitize([]string{})); err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.Storage); rollBackTxnErr != nil {
				err = rollBackTxnErr
			}

			return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
		}
	}

	response.SetAccessToken(refresh)
	response.SetTokenType("N_A")
	response.SetExpiresIn(c.getExpiresIn(request, oauth2.RefreshToken, c.RefreshTokenLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())

	return nil
}

func (c *RefreshTokenTypeHandler) getExpiresIn(r oauth2.Requester, key oauth2.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
