// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// IDTokenTypeHandler is a response handler for the ID Token grant using the implicit grant type
// as defined in RFC8693.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693
type IDTokenTypeHandler struct {
	Config oauth2.Configurator

	Strategy           jwt.Strategy
	IssueStrategy      openid.OpenIDConnectTokenStrategy
	ValidationStrategy openid.TokenValidationStrategy

	Storage
}

// HandleTokenEndpointRequest implements RFC8693 Section 2.1 and the oauth2.TokenEndpointHandler.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
func (c *IDTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
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

	if form.Get(consts.FormParameterSubjectTokenType) != consts.TokenTypeRFC8693IDToken && form.Get(consts.FormParameterActorTokenType) != consts.TokenTypeRFC8693IDToken {
		return nil
	}

	if form.Get(consts.FormParameterActorTokenType) == consts.TokenTypeRFC8693IDToken {
		var unpacked map[string]any

		token := form.Get(consts.FormParameterActorToken)

		if unpacked, err = c.validate(ctx, request, token, tokenRoleActor); err != nil {
			return err
		}

		session.SetActorToken(unpacked)
	}

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693IDToken {
		var unpacked map[string]any

		token := form.Get(consts.FormParameterSubjectToken)

		if unpacked, err = c.validate(ctx, request, token, tokenRoleSubject); err != nil {
			return err
		}

		// Get the subject and populate session
		session.SetSubject(unpacked[consts.ClaimSubject].(string))
		session.SetSubjectToken(unpacked)
	}

	return nil
}

// PopulateTokenEndpointResponse implements RFC8693 Section 2.2 and the oauth2.TokenEndpointHandler.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2
func (c *IDTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
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

	requestedTokenType := form.Get(consts.FormParameterRequestedTokenType)

	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	if requestedTokenType != consts.TokenTypeRFC8693IDToken {
		return nil
	}

	if err = c.issue(ctx, request, response); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped, which is not possible for RFC8693.
func (c *IDTokenTypeHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled which is true only if the
// 'grant_type' is exactly and only 'urn:ietf:params:oauth:grant-type:token-exchange'.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
func (c *IDTokenTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *IDTokenTypeHandler) validate(ctx context.Context, request oauth2.AccessRequester, token string, role tokenRole) (claims map[string]any, err error) {
	if claims, err = c.ValidationStrategy.ValidateIDToken(ctx, request, token); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Unable to parse the id_token").WithWrap(err).WithDebugError(err))
	}

	expectedIssuer := ""

	if config, ok := c.Config.(oauth2.AccessTokenIssuerProvider); ok {
		expectedIssuer = config.GetAccessTokenIssuer(ctx)
	}

	iss, _ := claims[consts.ClaimIssuer].(string)
	allowed := clientAllowedIssuers(request.GetClient(), role)

	var ok bool

	if _, ok = ValidateIssuer(iss, expectedIssuer, allowed); !ok {
		if len(allowed) > 0 {
			return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'iss' from token is not in the OAuth 2.0 Client's permitted issuer list."))
		}

		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'iss' from token must match the '%s'.", expectedIssuer))
	}

	if _, ok = claims[consts.ClaimSubject].(string); !ok {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'sub' is missing."))
	}

	return claims, nil
}

func (c *IDTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	var (
		session openid.Session
		ok      bool
	)

	if session, ok = request.GetSession().(openid.Session); !ok || session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because session must be of type 'openid.Session'."))
	}

	claims := session.IDTokenClaims()

	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because subject is an empty string."))
	}

	var token string

	if token, err = c.IssueStrategy.GenerateIDToken(ctx, c.Config.GetIDTokenLifespan(ctx), request); err != nil {
		return err
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.RFC8693NAToken)
	response.SetExpiresIn(c.Config.GetIDTokenLifespan(ctx))
	response.SetScopes(request.GetGrantedScopes())
	response.SetExtra(consts.FormParameterIssuedTokenType, consts.TokenTypeRFC8693IDToken)

	return nil
}
