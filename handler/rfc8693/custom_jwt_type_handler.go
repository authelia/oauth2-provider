package rfc8693

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type CustomJWTTypeHandler struct {
	Config oauth2.RFC8693ConfigProvider

	jwt.Strategy
	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *CustomJWTTypeHandler) HandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	session, _ := requester.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := requester.GetRequestForm()
	tokenTypes := c.Config.GetRFC8693TokenTypes(ctx)
	actorTokenType := tokenTypes[form.Get(consts.FormParameterActorTokenType)]
	subjectTokenType := tokenTypes[form.Get(consts.FormParameterSubjectTokenType)]

	if actorTokenType != nil && actorTokenType.GetType(ctx) == consts.TokenTypeRFC8693JWT {
		token := form.Get(consts.FormParameterActorToken)
		if unpacked, err := c.validate(ctx, requester, actorTokenType, token); err != nil {
			return err
		} else {
			session.SetActorToken(unpacked)
		}
	}

	if subjectTokenType != nil && subjectTokenType.GetType(ctx) == consts.TokenTypeRFC8693JWT {
		token := form.Get(consts.FormParameterSubjectToken)
		if unpacked, err := c.validate(ctx, requester, subjectTokenType, token); err != nil {
			return err
		} else {
			session.SetSubjectToken(unpacked)

			var subject string

			// Get the subject and populate session.
			if subject, err = c.GetSubjectForTokenExchange(ctx, requester, unpacked); err != nil {
				return err
			} else {
				session.SetSubject(subject)
			}
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *CustomJWTTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var (
		session Session
		ok      bool
	)

	if session, ok = requester.GetSession().(Session); !ok || session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := requester.GetRequestForm()
	requestedTokenType := form.Get(consts.FormParameterRequestedTokenType)

	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	tokenTypes := c.Config.GetRFC8693TokenTypes(ctx)
	tokenType := tokenTypes[requestedTokenType]

	if tokenType == nil || tokenType.GetType(ctx) != consts.TokenTypeRFC8693JWT {
		return nil
	}

	if err := c.issue(ctx, requester, tokenType, responder); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *CustomJWTTypeHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *CustomJWTTypeHandler) CanHandleTokenEndpointRequest(_ context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *CustomJWTTypeHandler) validate(ctx context.Context, _ oauth2.AccessRequester, tokenType oauth2.RFC8693TokenType, token string) (map[string]any, error) {
	jwtType, _ := tokenType.(*JWTType)
	if jwtType == nil {
		return nil, errorsx.WithStack(
			oauth2.ErrServerError.WithDebugf(
				"Token type '%s' is supposed to be of type JWT but is not castable to 'JWTType'", tokenType.GetName(ctx)))
	}

	// Parse the token
	ftoken, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, jwtType.ValidateFunc)
	if err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Unable to parse the JSON web token").WithWrap(err).WithDebugError(err))
	}

	window := jwtType.JWTLifetimeToleranceWindow
	if window == 0 {
		window = 1 * time.Hour
	}
	claims := ftoken.Claims.ToMapClaims()

	if issued, exists := claims[consts.ClaimIssuedAt]; exists {
		if time.Unix(toInt64(issued), 0).Add(window).Before(time.Now()) {
			return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'iat' from token is too far in the past."))
		}
	}

	if _, exists := claims[consts.ClaimExpirationTime]; !exists { // Validate 'exp' is mandatory
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'exp' from token is missing."))
	}
	expiry := toInt64(claims[consts.ClaimExpirationTime])
	if time.Now().Add(window).Before(time.Unix(expiry, 0)) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'exp' from token is too far in the future."))
	}

	if !claims.VerifyIssuer(jwtType.Issuer, true) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'iss' from token must match the '%s'.", jwtType.Issuer))
	}

	// Validate the JTI is unique if required.
	if jwtType.ValidateJTI {
		jti, _ := claims[consts.ClaimJWTID].(string)

		if jti == "" {
			return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'jti' from token is missing."))
		}

		if c.SetTokenExchangeCustomJWT(ctx, jti, time.Unix(expiry, 0)) != nil {
			return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'jti' from the token must be used only once."))
		}
	}

	return claims, nil
}

func (c *CustomJWTTypeHandler) issue(ctx context.Context, requester oauth2.AccessRequester, tokenType oauth2.RFC8693TokenType, responder oauth2.AccessResponder) (err error) {
	jwtType, _ := tokenType.(*JWTType)
	if jwtType == nil {
		return errorsx.WithStack(
			oauth2.ErrServerError.WithDebugf(
				"Token type '%s' is supposed to be of type JWT but is not castable to 'JWTType'", tokenType.GetName(ctx)))
	}

	session, ok := requester.GetSession().(openid.Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate JWT because session must be of type 'openid.Session'."))
	}

	claims := session.IDTokenClaims()

	if claims.Subject == "" {
		claims.Subject = requester.GetClient().GetID()
	}

	if claims.ExpirationTime == nil || claims.ExpirationTime.IsZero() {
		claims.ExpirationTime = jwt.NewNumericDate(time.Now().Add(jwtType.Expiry))
	}

	if claims.Issuer == "" {
		claims.Issuer = jwtType.Issuer
	}

	if len(requester.GetRequestedAudience()) > 0 {
		claims.Audience = append(claims.Audience, requester.GetRequestedAudience()...)
	}

	if len(claims.Audience) == 0 {
		aud := jwtType.Audience

		if len(aud) == 0 {
			aud = append(aud, requester.GetClient().GetID())
		}

		claims.Audience = append(claims.Audience, aud...)
	}

	if claims.JTI == "" {
		claims.JTI = uuid.New().String()
	}

	claims.IssuedAt = jwt.Now()

	var token string

	if token, _, err = c.Encode(ctx, claims.ToMapClaims(), jwt.WithHeaders(session.IDTokenHeaders()), jwt.WithIDTokenClient(requester.GetClient())); err != nil {
		return err
	}

	responder.SetAccessToken(token)
	responder.SetTokenType(oauth2.RFC8693NAToken)
	responder.SetExpiresIn(time.Duration(claims.GetExpirationTimeSafe().UnixNano() - time.Now().UTC().UnixNano()))

	return nil
}

// type conversion according to jwt.MapClaims.toInt64 - ignore error
func toInt64(claim any) int64 {
	switch t := claim.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case json.Number:
		v, err := t.Int64()
		if err == nil {
			return v
		}
		vf, err := t.Float64()
		if err != nil {
			return 0
		}
		return int64(vf)
	}
	return 0
}
