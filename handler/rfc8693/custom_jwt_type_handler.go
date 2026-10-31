// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// CustomJWTTypeHandler handles the token types configured as a *JWTType.
//
// A token exchange with a custom JWT as the 'subject_token' may only request the scopes in the token's 'scope' claim,
// either the space-delimited list RFC 8693 Section 4.2 defines or an array of strings, and cannot request a scope
// when the token has no such claim. When the 'requested_token_type' is an Identity Assertion JWT Authorization Grant,
// the 'subject_token' must instead be an assertion whose 'aud' claim includes the requesting client and whose 'typ' is
// not an access token type, and its 'scope' claim does not limit the requested scopes.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-4.2
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
type CustomJWTTypeHandler struct {
	Config oauth2.RFC8693ConfigProvider

	jwt.Strategy
	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *CustomJWTTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
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
	tokenTypes := c.Config.GetRFC8693TokenTypes(ctx)
	actorTokenType := tokenTypes[form.Get(consts.FormParameterActorTokenType)]
	subjectTokenType := tokenTypes[form.Get(consts.FormParameterSubjectTokenType)]

	if actorTokenType != nil && actorTokenType.GetType(ctx) == consts.TokenTypeRFC8693JWT {
		var unpacked map[string]any

		token := form.Get(consts.FormParameterActorToken)

		if unpacked, err = c.validate(ctx, request, actorTokenType, token, tokenRoleActor); err != nil {
			return err
		}

		if err = c.inherit(ctx, request, unpacked, tokenRoleActor); err != nil {
			return err
		}

		session.SetActorToken(unpacked)
	}

	if subjectTokenType != nil && subjectTokenType.GetType(ctx) == consts.TokenTypeRFC8693JWT {
		var unpacked map[string]any

		token := form.Get(consts.FormParameterSubjectToken)

		if unpacked, err = c.validate(ctx, request, subjectTokenType, token, tokenRoleSubject); err != nil {
			return err
		}

		if err = c.inherit(ctx, request, unpacked, tokenRoleSubject); err != nil {
			return err
		}

		session.SetSubjectToken(unpacked)

		var subject string

		// Get the subject and populate session.
		if subject, err = c.GetSubjectForTokenExchange(ctx, request, unpacked); err != nil {
			return err
		}

		session.SetSubject(subject)
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *CustomJWTTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
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

	if IsIDJAGRequest(ctx, request, c.Config) {
		return nil
	}

	form := request.GetRequestForm()
	requestedTokenType := form.Get(consts.FormParameterRequestedTokenType)

	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	tokenTypes := c.Config.GetRFC8693TokenTypes(ctx)
	tokenType := tokenTypes[requestedTokenType]

	if tokenType == nil || tokenType.GetType(ctx) != consts.TokenTypeRFC8693JWT {
		return nil
	}

	if err = c.issue(ctx, request, tokenType, response); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *CustomJWTTypeHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *CustomJWTTypeHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) bool {
	// The parameter 'grant_type' is REQUIRED. Value MUST be set to "urn:ietf:params:oauth:grant-type:token-exchange".
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

func (c *CustomJWTTypeHandler) inherit(ctx context.Context, request oauth2.AccessRequester, claims map[string]any, role tokenRole) (err error) {
	var incoming tokenBinding

	if incoming, err = bindingOfConfirmation(claims); err != nil {
		return err
	}

	return inheritTokenBinding(ctx, c.Config, request, incoming, role, bindingOf(request.GetSession()))
}

func (c *CustomJWTTypeHandler) validate(ctx context.Context, request oauth2.AccessRequester, tokenType oauth2.RFC8693TokenType, token string, role tokenRole) (map[string]any, error) {
	jwtType, ok := tokenType.(*JWTType)
	if !ok || jwtType == nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("Token type '%s' is supposed to be of type JWT but is not castable to 'JWTType'", tokenType.GetName(ctx)))
	}

	// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
	if jwtType.AuthorizationGrant {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("A JWT authorization grant of the type '%s' cannot be exchanged.", jwtType.GetName(ctx)))
	}

	ftoken, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, jwtType.ValidateFunc)
	if err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Unable to parse the JSON web token").WithWrap(err).WithDebugError(err))
	}

	idjag := role == tokenRoleSubject && IsIDJAGRequest(ctx, request, c.Config)

	if err = validateCustomJWTType(ctx, jwtType, ftoken, idjag); err != nil {
		return nil, err
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

	if _, exists := claims[consts.ClaimExpirationTime]; !exists {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'exp' from token is missing."))
	}

	expiry := toInt64(claims[consts.ClaimExpirationTime])
	if time.Now().Add(window).Before(time.Unix(expiry, 0)) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'exp' from token is too far in the future."))
	}

	iss, _ := claims[consts.ClaimIssuer].(string)

	if err = c.validateIssuerIsNotIDTokenIssuer(ctx, iss); err != nil {
		return nil, err
	}

	allowed := clientAllowedIssuers(request.GetClient(), role)

	if _, ok = ValidateIssuer(iss, jwtType.Issuer, allowed); !ok {
		if len(allowed) > 0 {
			return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'iss' from token is not in the OAuth 2.0 Client's permitted issuer list."))
		}

		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'iss' from token must match the '%s'.", jwtType.Issuer))
	}

	if idjag {
		// Draft ID-JAG Section 4.3.3: the audience of the assertion MUST match the authenticated client, and the
		// requested scopes are governed by the relationship rather than the assertion.
		if clientID := request.GetClient().GetID(); !claims.VerifyAudience(clientID, true) {
			return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'aud' from token must include the OAuth 2.0 Client '%s'.", clientID))
		}
	} else if err = validateCustomJWTScope(request, role, claims); err != nil {
		return nil, err
	}

	// The JTI is marked as used by TokenExchangeGrantHandler.PopulateTokenEndpointResponse.
	if jwtType.ValidateJTI {
		if jti, _ := claims[consts.ClaimJWTID].(string); jti == "" {
			return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'jti' from token is missing."))
		}
	}

	return claims, nil
}

func validateCustomJWTType(ctx context.Context, jwtType *JWTType, token *jwt.Token, idjag bool) error {
	typ, _ := token.Header[jwt.JSONWebTokenHeaderType].(string)

	if oauth2.IsIDJAGTokenType(typ) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("A '%s' cannot be exchanged.", consts.TokenTypeRFC8693IDJAG))
	}

	// RFC 8725 Section 3.11 explicit typing keeps another kind of JWT signed by a trusted key, such as an RFC 9068
	// access token or a Logout Token, from being accepted as this type.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.11
	if err := token.Valid(jwt.ValidateTypes(jwtType.GetTypes()...), jwt.ValidateAllowEmptyType(true)); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The 'typ' header '%s' is not permitted for the token type '%s'.", typ, jwtType.GetName(ctx)).WithWrap(err).WithDebugError(err))
	}

	// Draft ID-JAG Section 4.3: the subject token is an Identity Assertion or a Refresh Token.
	if idjag && (strings.EqualFold(typ, consts.JSONWebTokenTypeAccessToken) || strings.EqualFold(typ, "application/"+consts.JSONWebTokenTypeAccessToken)) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("An access token is not supported as a '%s' when the '%s' is '%s'.", consts.FormParameterSubjectToken, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693IDJAG))
	}

	return nil
}

func (c *CustomJWTTypeHandler) validateIssuerIsNotIDTokenIssuer(ctx context.Context, iss string) error {
	// An ID Token is validated by the ID Token type, which binds it to the client it was issued to. RFC 8725 Section
	// 3.12 requires mutually exclusive validation rules for JWTs from one issuer.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
	if provider, ok := c.Config.(oauth2.IDTokenIssuerProvider); ok {
		if issuer := provider.GetIDTokenIssuer(ctx); issuer != "" && iss == issuer {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'iss' from token is the ID Token issuer, so the token must be exchanged as '%s'.", consts.TokenTypeRFC8693IDToken))
		}
	}

	return nil
}

func (c *CustomJWTTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, tokenType oauth2.RFC8693TokenType, response oauth2.AccessResponder) (err error) {
	if err = requireSubjectToken(request); err != nil {
		return err
	}

	if err = requireActorToken(request); err != nil {
		return err
	}

	jwtType, _ := tokenType.(*JWTType)
	if jwtType == nil {
		return errorsx.WithStack(
			oauth2.ErrServerError.WithDebugf("Token type '%s' is supposed to be of type JWT but is not castable to 'JWTType'", tokenType.GetName(ctx)))
	}

	if jwtType.AuthorizationGrant {
		return c.issueAuthorizationGrant(ctx, request, jwtType, response)
	}

	session, ok := request.GetSession().(openid.Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate JWT because session must be of type 'openid.Session'."))
	}

	claims := session.IDTokenClaims()

	if claims.Subject = session.GetSubject(); claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.
			WithDebug("Failed to generate the JSON Web Token because the session subject is empty. The token exchange handler chain must populate the subject from the subject_token before the custom JWT handler runs."))
	}

	if claims.ExpirationTime == nil || claims.ExpirationTime.IsZero() {
		claims.ExpirationTime = jwt.NewNumericDate(time.Now().Add(c.expiry(ctx, jwtType)))
	}

	claims.ExpirationTime = jwt.NewNumericDate(capToSubjectTokenExpiry(request, claims.ExpirationTime.Time))

	if claims.Issuer == "" {
		claims.Issuer = jwtType.Issuer
	}

	// The token is signed with the ID Token key and typed 'JWT', so an ID Token issuer would make it valid as an ID
	// Token. RFC 8725 Section 3.12 requires mutually exclusive validation rules for JWTs from one issuer.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
	if err = c.validateIssuedIssuer(ctx, jwtType, claims.Issuer); err != nil {
		return err
	}

	// The issued JWT's audience MUST reflect THIS exchange's audience/resource parameters per RFC 8693 §2.1, not
	// any audience that happened to be on the session from a prior OIDC flow. Replace rather than append.
	switch {
	case len(request.GetGrantedAudience()) > 0 || len(request.GetGrantedResource()) > 0:
		claims.Audience = oauth2.JoinGrantedAudienceAndResource(request.GetGrantedAudience(), request.GetGrantedResource())
	case len(jwtType.Audience) > 0:
		claims.Audience = append([]string(nil), jwtType.Audience...)
	default:
		return errorsx.WithStack(oauth2.ErrInvalidTarget.
			WithHint("Unable to determine the audience for the issued JSON Web Token.").
			WithDebugf("The token exchange request did not include an 'audience' or 'resource' parameter and the JSON Web Token type '%s' has no default audience configured.", jwtType.GetName(ctx)))
	}

	if claims.JTI == "" {
		claims.JTI = uuid.New().String()
	}

	claims.IssuedAt = jwt.Now()

	// OpenID Connect Key Binding 1.0 Section 4 pairs the 'cnf' claim with a 'typ' of 'dpop+id_token', and Section 9.3
	// has the Relying Party read that pair as the marker of a key-bound ID Token. The exchanged token is not an ID
	// Token and no proof of possession is confirmed for it, so neither may be carried over from the ID Token state
	// oauth2.ApplyIDTokenConfirmation leaves on the session.
	mapped := claims.ToMapClaims()

	delete(mapped, consts.ClaimConfirmation)

	headers := stripIDTokenConfirmationHeader(session.IDTokenHeaders())

	var token string

	if token, _, err = c.Encode(ctx, mapped, jwt.WithHeaders(headers), jwt.WithIDTokenClient(request.GetClient())); err != nil {
		return err
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.RFC8693NAToken)
	response.SetExpiresIn(time.Duration(claims.GetExpirationTimeSafe().UnixNano() - time.Now().UTC().UnixNano()))
	response.SetScopes(request.GetGrantedScopes())
	response.SetExtra(consts.FormParameterIssuedTokenType, jwtType.GetName(ctx))

	return nil
}

// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.3.3
//
//nolint:gocyclo
func (c *CustomJWTTypeHandler) issueAuthorizationGrant(ctx context.Context, request oauth2.AccessRequester, jwtType *JWTType, response oauth2.AccessResponder) (err error) {
	session, ok := request.GetSession().(Session)
	if !ok || session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	targets := oauth2.JoinGrantedAudienceAndResource(request.GetGrantedAudience(), request.GetGrantedResource())
	if len(targets) != 1 {
		return errorsx.WithStack(oauth2.ErrInvalidTarget.WithHint("A JWT authorization grant must identify a single authorization server."))
	}

	if jwtType.Issuer == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The JSON Web Token type '%s' has no issuer.", jwtType.GetName(ctx)))
	}

	if err = c.validateIssuedIssuer(ctx, jwtType, jwtType.Issuer); err != nil {
		return err
	}

	if err = c.validateIDTokenIssuerConfigured(ctx, jwtType); err != nil {
		return err
	}

	now := time.Now().UTC()
	expires := capToSubjectTokenExpiry(request, now.Add(c.expiry(ctx, jwtType)))

	if expires.Unix() <= now.Unix() {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' expires too soon to issue a JWT authorization grant.", consts.FormParameterSubjectToken))
	}

	protected := map[string]any{
		consts.ClaimIssuer:         jwtType.Issuer,
		consts.ClaimAudience:       slices.Clone([]string(targets)),
		consts.ClaimExpirationTime: expires.Unix(),
		consts.ClaimIssuedAt:       now.Unix(),
		consts.ClaimJWTID:          uuid.New().String(),
	}

	subject := request.GetSession().GetSubject()

	claims := map[string]any{consts.ClaimSubject: subject}

	if scopes := request.GetGrantedScopes(); len(scopes) > 0 {
		claims[consts.ClaimScope] = strings.Join(scopes, " ")
	}

	var act map[string]any

	if act, err = buildActClaim(session); err != nil {
		return err
	}

	if act == nil {
		if prior, ok := session.GetSubjectToken()[consts.ClaimActor].(map[string]any); ok {
			act = copyClaimMap(prior)
		}
	}

	if len(act) > 0 {
		claims[consts.ClaimActor] = act
	}

	maps.Copy(claims, protected)

	if jwtType.TranscribeClaims != nil {
		claims[consts.ClaimAudience] = slices.Clone([]string(targets))

		if err = jwtType.TranscribeClaims(ctx, request, claims); err != nil {
			return errorsx.WithStack(err)
		}

		maps.Copy(claims, protected)
	}

	if transcribed, _ := claims[consts.ClaimSubject].(string); transcribed == "" {
		// RFC 8693 Section 2.2.2: a subject token that is unacceptable is an 'invalid_request'.
		if subject == "" {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' does not identify a subject.", consts.FormParameterSubjectToken))
		}

		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate the JWT authorization grant because its 'sub' claim is not a non-empty string."))
	}

	var token string

	if token, _, err = c.Encode(ctx, jwt.MapClaims(claims), jwt.WithIssuerSigningAlg(jwtType.SigningAlg)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.RFC8693NAToken)
	response.SetExpiresIn(time.Until(expires))

	if scopes := scopeClaim(claims); len(scopes) > 0 {
		response.SetScopes(scopes)
	}

	response.SetExtra(consts.FormParameterIssuedTokenType, jwtType.GetName(ctx))

	return nil
}

// validateIDTokenIssuerConfigured refuses to issue while the ID Token token type is registered with no issuer, as it
// would then accept a grant whose 'aud' claim names a client as an ID Token.
//
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
func (c *CustomJWTTypeHandler) validateIDTokenIssuerConfigured(ctx context.Context, jwtType *JWTType) error {
	if c.Config.GetRFC8693TokenTypes(ctx)[consts.TokenTypeRFC8693IDToken] == nil {
		return nil
	}

	if provider, ok := c.Config.(oauth2.IDTokenIssuerProvider); ok && provider.GetIDTokenIssuer(ctx) != "" {
		return nil
	}

	return errorsx.WithStack(oauth2.ErrServerError.
		WithDebugf("The JSON Web Token type '%s' issues JWT authorization grants but the ID Token token type is registered without an ID Token issuer, so a grant would be accepted as an ID Token.", jwtType.GetName(ctx)))
}

func (c *CustomJWTTypeHandler) validateIssuedIssuer(ctx context.Context, jwtType *JWTType, iss string) error {
	if provider, ok := c.Config.(oauth2.IDTokenIssuerProvider); ok {
		if issuer := provider.GetIDTokenIssuer(ctx); issuer != "" && iss == issuer {
			return errorsx.WithStack(oauth2.ErrServerError.
				WithDebugf("The JSON Web Token type '%s' has the issuer '%s' which is the ID Token issuer, so the issued token would be accepted as an ID Token.", jwtType.GetName(ctx), iss))
		}
	}

	return nil
}

func (c *CustomJWTTypeHandler) expiry(ctx context.Context, jwtType *JWTType) time.Duration {
	if jwtType.Expiry > 0 {
		return jwtType.Expiry
	}

	if provider, ok := c.Config.(oauth2.AccessTokenLifespanProvider); ok {
		if lifespan := provider.GetAccessTokenLifespan(ctx); lifespan > 0 {
			return lifespan
		}
	}

	return time.Hour
}

func stripIDTokenConfirmationHeader(headers *jwt.Headers) (stripped *jwt.Headers) {
	if headers == nil {
		return nil
	}

	if typ, ok := headers.Get(consts.JSONWebTokenHeaderType).(string); !ok || typ != consts.JSONWebTokenTypeDPoPIDToken {
		return headers
	}

	stripped = &jwt.Headers{Extra: make(map[string]any, len(headers.Extra))}

	for key, value := range headers.Extra {
		if key == consts.JSONWebTokenHeaderType {
			continue
		}

		stripped.Extra[key] = value
	}

	return stripped
}

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

func validateCustomJWTScope(request oauth2.AccessRequester, role tokenRole, claims map[string]any) (err error) {
	if role != tokenRoleSubject {
		return nil
	}

	return validateSubjectTokenScope(request, scopeClaim(claims))
}
