package rfc8693

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/token/jwt"
)

type IDTokenTypeHandler struct {
	Config             oauth2.Configurator
	JWTStrategy        jwt.Signer
	IssueStrategy      openid.OpenIDConnectTokenStrategy
	ValidationStrategy openid.TokenValidationStrategy
	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *IDTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	if form.Get(consts.FormParameterSubjectTokenType) != consts.TokenTypeRFC8693IDToken && form.Get(consts.FormParameterActorTokenType) != consts.TokenTypeRFC8693IDToken {
		return nil
	}

	if form.Get(consts.FormParameterActorTokenType) == consts.TokenTypeRFC8693IDToken {
		token := form.Get(consts.FormParameterActorToken)
		if unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetActorToken(unpacked)
		}
	}

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693IDToken {
		token := form.Get(consts.FormParameterSubjectToken)
		if unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			// Get the subject and populate session
			session.SetSubject(unpacked[consts.ClaimSubject].(string))
			session.SetSubjectToken(unpacked)
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *IDTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, responder oauth2.AccessResponder) error {
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
		if config, ok := c.Config.(oauth2.RFC8693ConfigProvider); ok {
			requestedTokenType = config.GetDefaultRFC8693RequestedTokenType(ctx)
		}
	}

	if requestedTokenType != consts.TokenTypeRFC8693IDToken {
		return nil
	}

	if err := c.issue(ctx, request, responder); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *IDTokenTypeHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *IDTokenTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *IDTokenTypeHandler) validate(ctx context.Context, request oauth2.AccessRequester, token string) (map[string]any, error) {
	claims, err := c.ValidationStrategy.ValidateIDToken(ctx, request, token)
	if err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Unable to parse the id_token").WithWrap(err).WithDebugError(err))
	}

	expectedIssuer := ""
	if config, ok := c.Config.(oauth2.AccessTokenIssuerProvider); ok {
		expectedIssuer = config.GetAccessTokenIssuer(ctx)
	}

	if !claims.VerifyIssuer(expectedIssuer, true) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'iss' from token must match the '%s'.", expectedIssuer))
	}

	if _, ok := claims[consts.ClaimSubject].(string); !ok {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'sub' is missing."))
	}

	return map[string]any(claims), nil
}

func (c *IDTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
	sess, ok := request.GetSession().(openid.Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug(
			"Failed to generate id token because session must be of type 'openid.Session'."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	token, err := c.IssueStrategy.GenerateIDToken(ctx, c.Config.GetIDTokenLifespan(ctx), request)
	if err != nil {
		return err
	}

	response.SetAccessToken(token)
	response.SetTokenType("N_A")

	return nil
}
