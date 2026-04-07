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

		if _, claims, err = c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetActorToken(claims)
		}
	}

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693AccessToken {
		token := form.Get(consts.FormParameterSubjectToken)

		var subjectTokenSession oauth2.Session

		if subjectTokenSession, claims, err = c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetSubjectToken(claims)
			session.SetSubject(subjectTokenSession.GetSubject())
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *AccessTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, responder oauth2.AccessResponder) (err error) {
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

	if err = c.issue(ctx, request, responder); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped.
func (c *AccessTokenTypeHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled.
func (c *AccessTokenTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *AccessTokenTypeHandler) validate(ctx context.Context, requester oauth2.AccessRequester, token string) (s oauth2.Session, claims map[string]any, err error) {
	var (
		original oauth2.Requester
		session  Session
		ok       bool
	)

	if session, ok = requester.GetSession().(Session); !ok || session == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug(
			"Failed to perform token exchange because the session is not of the right type."))
	}

	client := requester.GetClient()

	signature := c.AccessTokenSignature(ctx, token)

	if original, err = c.GetAccessTokenSession(ctx, signature, requester.GetSession()); err != nil {
		return nil, nil, errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
	} else if err = c.ValidateAccessToken(ctx, original, token); err != nil {
		return nil, nil, err
	}

	var (
		subjectTokenClientID string
		subjectTokenClient   Client
	)

	subjectTokenClientID = original.GetClient().GetID()

	// Prevent clients from exchanging their own tokens.
	if client.GetID() == subjectTokenClientID {
		return nil, nil, errors.WithStack(oauth2.ErrRequestForbidden.WithHint("Clients are not allowed to perform a token exchange on their own tokens."))
	}

	// Check if the client is allowed to exchange this token.
	if subjectTokenClient, ok = original.GetClient().(Client); ok {
		allowed := subjectTokenClient.GetTokenExchangePermitted(client)
		if !allowed {
			return nil, nil, errors.WithStack(oauth2.ErrRequestForbidden.WithHintf(
				"The OAuth 2.0 client is not permitted to exchange a subject token issued to client %s", subjectTokenClientID))
		}
	}

	// Validate the scopes.
	for _, scope := range requester.GetRequestedScopes() {
		if !c.ScopeStrategy(original.GetGrantedScopes(), scope) {
			return nil, nil, errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The subject token is not granted '%s' and so this scope cannot be requested.", scope))
		}
	}

	// Convert to flat session with only access token claims.
	claims = session.AccessTokenClaimsMap()

	claims[consts.ClaimClientIdentifier] = original.GetClient().GetID()
	claims[consts.ClaimScope] = original.GetGrantedScopes()
	claims[consts.ClaimAudience] = original.GetGrantedAudience()

	return original.GetSession(), claims, nil
}

func (c *AccessTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan))

	var token, signature string

	if token, signature, err = c.GenerateAccessToken(ctx, request); err != nil {
		return err
	} else if err = c.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return err
	}

	issueRefreshToken := c.canIssueRefreshToken(request)

	if issueRefreshToken {
		var refresh, refreshSignature string

		request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Truncate(jwt.TimePrecision))
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
