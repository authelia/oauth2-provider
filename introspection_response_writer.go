// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// WriteIntrospectionError writes the introspection error response. An inactive token is not an error and is answered
// with an introspection response whose 'active' member is false. Only an error describing the condition of the
// introspected token is answered that way: ErrInactiveToken, ErrTokenSignatureMismatch, ErrInvalidTokenFormat,
// ErrNotFound and ErrUnknownRequest. Any other error is answered with the error, and an error that is not an
// RFC6749Error with ErrServerError.
//
// The outermost RFC6749Error of err decides the response, not the errors it wraps. A rejection of the caller is answered
// with the error, and for a bearer credential with the RFC 6750 Section 3 'WWW-Authenticate' challenge, even when the
// cause is an inactive credential. An error with a 5xx status, such as ErrTemporarilyUnavailable, or a 429 status
// describes the server or the caller and never the introspected token, so it is answered with the error as well.
//
// r is the request being answered and may be nil. A request which included no access token is answered with HTTP 401
// and the challenge alone, without a body (RFC 6750 Section 3.1). Without r the challenge omits the RFC 9728 Section
// 5.1 'resource_metadata' parameter and the body is written.
//
// See: https://datatracker.ietf.org/doc/html/rfc7662#section-2.3
func (f *Fosite) WriteIntrospectionError(ctx context.Context, rw http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}

	// RFC 9701 Section 5: an inactive token is answered in the format the authenticated caller is due.
	var inactive *inactiveIntrospectionError

	if errors.As(err, &inactive) {
		f.WriteIntrospectionResponse(ctx, rw, inactive.responder)

		return
	}

	// RFC 7662 Section 2.3: the outermost error decides the response. An error which rejects the caller remains an
	// error whatever it wraps, as its cause describes the credential of the caller and not the introspected token.
	outer := outermostRFC6749Error(err)

	switch {
	case IsBearerCredentialError(outer):
		rfc, bare := f.writeBearerAuthorizationChallenge(ctx, rw, r, err)
		if bare {
			writeBareAuthorizationChallenge(rw)

			return
		}

		// RFC 7662 Section 2.3: a bearer credential that "does not contain sufficient privileges or is otherwise
		// invalid for this request" is answered with HTTP 401. That is more specific than RFC 6750 Section 3.1's
		// general 403 for insufficient_scope, so it wins here. The RFC 7591 client registration endpoint has no such
		// override and answers 403 for the same condition.
		if rfc.ErrorField == errInsufficientScopeName {
			rfc = rfc.WithCode(http.StatusUnauthorized)
		}

		f.writeErrorJSONRFC(ctx, rw, rfc)
	case isIntrospectionTokenConditionError(outer):
		rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
		rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
		rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
		_ = json.NewEncoder(rw).Encode(struct {
			Active bool `json:"active"`
		}{Active: false})
	case outer.ErrorField == "" || outer.ErrorField == errUnknownErrorName:
		f.writeErrorJSON(ctx, rw, nil, errors.WithStack(ErrServerError.WithWrap(err).WithDebugError(err)))
	default:
		f.writeErrorJSON(ctx, rw, nil, err)
	}
}

func isIntrospectionTokenConditionError(outer *RFC6749Error) bool {
	return errors.Is(outer, ErrInactiveToken) ||
		errors.Is(outer, ErrTokenSignatureMismatch) ||
		errors.Is(outer, ErrInvalidTokenFormat) ||
		errors.Is(outer, ErrNotFound) ||
		errors.Is(outer, ErrUnknownRequest)
}

func outermostRFC6749Error(err error) *RFC6749Error {
	if outer, ok := AsRFC6749Error(err); ok {
		return outer.WithWrap(nil)
	}

	return &RFC6749Error{}
}

// WriteIntrospectionResponse writes the introspection response.
//
// See: https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
//
//nolint:gocyclo
func (f *Fosite) WriteIntrospectionResponse(ctx context.Context, rw http.ResponseWriter, r IntrospectionResponder) {
	var (
		caller   Client
		client   IntrospectionJWTResponseClient
		ok       bool
		alg, kid string
	)

	if responder, isResponderClient := r.(IntrospectionResponderClient); isResponderClient {
		caller = responder.GetClient()
	}

	// RFC 9701 Sections 5 and 6: the signing algorithm and 'aud' both come from the caller, not from the introspected
	// token's client.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9701#section-5
	// See: https://www.rfc-editor.org/rfc/rfc9701#section-6
	if client, ok = caller.(IntrospectionJWTResponseClient); ok {
		alg, kid = client.GetIntrospectionSignedResponseAlg(), client.GetIntrospectionSignedResponseKeyID()
	}

	// RFC 9701 Section 4: the caller requests a JWT with the 'Accept' header, and Section 6 makes RS256 the default
	// algorithm. A registered algorithm always applies, so a caller cannot be downgraded by the header being absent.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9701#section-4
	// See: https://www.rfc-editor.org/rfc/rfc9701#section-6
	var permitted []string

	if provider, isProvider := f.Config.(SignedResponseAlgValuesProvider); isProvider {
		permitted = provider.GetIntrospectionSignedResponseAlgValues(ctx)
	}

	if alg == "" && ((kid == "" && f.isIntrospectionJWTRequested(ctx, r, caller)) || (kid != "" && len(permitted) != 0)) {
		if alg = IntrospectionSignedResponseAlgDefault(ctx, f.Config.GetIntrospectionJWTResponseStrategy(ctx), permitted); alg == "" {
			f.writeErrorJSON(ctx, rw, nil, errors.WithStack(ErrServerError.WithHint("The introspection response could not be signed.").WithDebugf("The first of the permitted algorithms '%s' is empty.", strings.Join(permitted, "', '"))))

			return
		}
	}

	// FAPI 2.0 Message Signing Section 5.2: only a permitted algorithm signs the response, and only a caller which is a
	// jwt.IntrospectionClient can have the algorithm chosen for it.
	if _, ok = caller.(jwt.IntrospectionClient); (alg != "" || kid != "") && alg != jwt.JSONWebTokenAlgNone && len(permitted) != 0 && (!ok || (alg != "" && !slices.Contains(permitted, alg))) {
		f.writeErrorJSON(ctx, rw, nil, errors.WithStack(ErrServerError.WithHint("The introspection response could not be signed.").WithDebugf("The client with id '%s' is registered to sign introspection responses with the 'alg' '%s', which is not one of the permitted algorithms '%s'.", clientID(caller), alg, strings.Join(permitted, "', '"))))

		return
	}

	response := map[string]any{jwt.ClaimActive: false}

	if !r.IsActive() {
		f.writeIntrospectionResponse(ctx, rw, r, caller, response, alg, kid)

		return
	}

	response[jwt.ClaimActive] = true

	extraClaimsSession, ok := r.GetAccessRequester().GetSession().(ExtraClaimsSession)
	if ok {
		extraClaims := extraClaimsSession.GetExtraClaims()
		policyClaim := f.Config.GetRFC7591ClientRegistrationPolicyClaim(ctx)

		for name, value := range extraClaims {
			switch name {
			// We do not allow these to be set through extra claims.
			case jwt.ClaimActive, jwt.ClaimExpirationTime, jwt.ClaimClientIdentifier, jwt.ClaimScope, jwt.ClaimIssuedAt, jwt.ClaimSubject, jwt.ClaimAudience, jwt.ClaimUsername, jwt.ClaimConfirmation, jwt.ClaimAuthorizationDetails, consts.AccessResponseRefreshTokenTimeout, consts.AccessResponseAuthorizationExpiresIn, policyClaim:
				continue
			default:
				response[name] = value
			}
		}
	}

	expires := r.GetAccessRequester().GetSession().GetExpiresAt(r.GetTokenUse())

	if r.GetTokenUse() == RefreshToken {
		expires = GetRefreshTokenEffectiveExpiry(r.GetAccessRequester().GetSession())
	}

	if !expires.IsZero() {
		response[jwt.ClaimExpirationTime] = expires.Unix()
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration-03#section-7
	if r.GetTokenUse() == RefreshToken && !f.Config.GetDisableRefreshTokenExpirationParameters(ctx) {
		for name, value := range GetRefreshTokenExpirationParameters(r.GetAccessRequester().GetSession(), time.Now()) {
			response[name] = value
		}
	}

	if r.GetAccessRequester().GetClient().GetID() != "" {
		response[jwt.ClaimClientIdentifier] = r.GetAccessRequester().GetClient().GetID()
	}

	if len(r.GetAccessRequester().GetGrantedScopes()) > 0 {
		response[jwt.ClaimScope] = strings.Join(r.GetAccessRequester().GetGrantedScopes(), " ")
	}

	if !r.GetAccessRequester().GetRequestedAt().IsZero() {
		response[jwt.ClaimIssuedAt] = r.GetAccessRequester().GetRequestedAt().Unix()
	}

	if r.GetAccessRequester().GetSession().GetSubject() != "" {
		response[jwt.ClaimSubject] = r.GetAccessRequester().GetSession().GetSubject()
	}

	if aud := JoinGrantedAudienceAndResource(r.GetAccessRequester().GetGrantedAudience(), r.GetAccessRequester().GetGrantedResource()); len(aud) > 0 {
		response[jwt.ClaimAudience] = aud
	}

	if r.GetAccessRequester().GetSession().GetUsername() != "" {
		response[jwt.ClaimUsername] = r.GetAccessRequester().GetSession().GetUsername()
	}

	// See: https://www.rfc-editor.org/rfc/rfc9396#section-9.2
	details, err := DiscloseAuthorizationDetails(ctx, f.Config, r.GetAccessRequester(), AuthorizationDetailsRecipient{Client: caller})
	if err != nil {
		f.WriteIntrospectionError(ctx, rw, nil, err)

		return
	}

	if len(details) != 0 {
		response[jwt.ClaimAuthorizationDetails] = details
	}

	ApplyAuthenticationContext(response, r.GetAccessRequester().GetSession(), caller)

	ApplyConfirmation(ctx, f.Config, response, r.GetAccessRequester().GetSession())

	switch {
	case r.GetTokenUse() == RefreshToken:
		// RFC 7662 Section 2.2 defines 'token_type' by the RFC 6749 Section 5.1 access token types.
		delete(response, consts.AccessResponseTokenType)
	case f.isIntrospectionTokenTypeEnabled(ctx, caller):
		if tokenType := r.GetAccessTokenType(); tokenType != "" {
			response[consts.AccessResponseTokenType] = tokenType
		} else {
			delete(response, consts.AccessResponseTokenType)
		}
	}

	f.writeIntrospectionResponse(ctx, rw, r, caller, response, alg, kid)
}

func (f *Fosite) writeIntrospectionResponse(ctx context.Context, rw http.ResponseWriter, r IntrospectionResponder, caller Client, response map[string]any, alg, kid string) {
	switch {
	case (alg != "" && alg != jwt.JSONWebTokenAlgNone) || (kid != "" && alg != jwt.JSONWebTokenAlgNone):
		var (
			token string
			jti   uuid.UUID
			err   error
		)

		header := &jwt.Headers{
			Extra: map[string]any{
				jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeTokenIntrospection,
			},
		}

		if alg != "" {
			header.Add(jwt.JSONWebTokenHeaderAlgorithm, alg)
		}

		if kid != "" {
			header.Add(jwt.JSONWebTokenHeaderKeyIdentifier, kid)
		}

		if jti, err = uuid.NewRandom(); err != nil {
			f.WriteIntrospectionError(ctx, rw, nil, errors.WithStack(ErrServerError.WithHint("Failed to lookup required information to perform this request.").WithDebugf("The JTI could not be generated for the Introspection JWT response type with error %+v.", err)))

			return
		}

		claims := jwt.MapClaims{
			jwt.ClaimJWTID:              jti.String(),
			jwt.ClaimIssuer:             f.Config.GetIssuer(ctx),
			jwt.ClaimIssuedAt:           time.Now().UTC().Unix(),
			jwt.ClaimTokenIntrospection: response,
		}

		if aud, _ := r.ToMap(); len(aud) != 0 {
			claims[jwt.ClaimAudience] = aud
		}

		strategy := f.Config.GetIntrospectionJWTResponseStrategy(ctx)

		if strategy == nil {
			f.WriteIntrospectionError(ctx, rw, nil, errors.WithStack(ErrServerError.WithHint("Failed to generate the response.").WithDebug("The Introspection JWT could not be generated as the server is misconfigured. The Introspection jwt.Strategy was not configured.")))

			return
		}

		var signer any = caller

		if c, ok := caller.(jwt.IntrospectionClient); ok && alg != "" && c.GetIntrospectionSignedResponseAlg() == "" {
			signer = &introspectionSignedResponseAlgClient{IntrospectionClient: c, alg: alg}
		}

		if token, _, err = strategy.Encode(ctx, claims, append(FAPI2SecurityProfileEncodeOptions(ctx, f.Config, caller), jwt.WithHeaders(header), jwt.WithIntrospectionClient(signer))...); err != nil {
			f.WriteIntrospectionError(ctx, rw, nil, errors.WithStack(ErrServerError.WithHint("Failed to generate the response.").WithDebugf("The Introspection JWT itself could not be generated with error %+v.", err)))

			return
		}

		rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationTokenIntrospectionJWT)
		rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
		rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
		rw.WriteHeader(http.StatusOK)

		_, _ = rw.Write([]byte(token))
	default:
		rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
		rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
		rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
		rw.WriteHeader(http.StatusOK)

		_ = json.NewEncoder(rw).Encode(response)
	}
}

func (f *Fosite) isIntrospectionJWTRequested(ctx context.Context, r IntrospectionResponder, caller Client) (requested bool) {
	responder, ok := r.(interface{ IsJWTRequested() bool })

	return ok && responder.IsJWTRequested() && caller != nil && f.Config.GetIntrospectionJWTResponseStrategy(ctx) != nil
}

func (f *Fosite) isIntrospectionTokenTypeEnabled(ctx context.Context, caller Client) (enabled bool) {
	if client, ok := caller.(IntrospectionTokenTypeClient); ok {
		return client.GetIntrospectionTokenTypeEnabled()
	}

	return f.Config != nil && f.Config.GetIntrospectionTokenTypeEnabled(ctx)
}

type introspectionSignedResponseAlgClient struct {
	jwt.IntrospectionClient

	alg string
}

func (c *introspectionSignedResponseAlgClient) GetIntrospectionSignedResponseAlg() string {
	return c.alg
}

func (c *introspectionSignedResponseAlgClient) IsClientIDMetadataDocumentClient() (is bool) {
	return jwt.IsClientIDMetadataDocumentClient(c.IntrospectionClient)
}

func (c *introspectionSignedResponseAlgClient) GetClientSecretExpiresAt() (expires time.Time) {
	if client, ok := c.IntrospectionClient.(jwt.ExpiringClientSecretClient); ok {
		return client.GetClientSecretExpiresAt()
	}

	return time.Time{}
}

// IntrospectionSignedResponseAlgDefault returns the algorithm which signs an RFC 9701 introspection response when the
// caller has not registered one. It is RS256 when the permitted algorithms are empty, or when RS256 is permitted and
// the strategy signs with it. Otherwise it is the first permitted algorithm the strategy signs with, or the first
// permitted algorithm when there is none. A nil strategy is treated as signing with every algorithm.
//
// See: https://www.rfc-editor.org/rfc/rfc9701#section-6
func IntrospectionSignedResponseAlgDefault(ctx context.Context, strategy jwt.Strategy, permitted []string) (alg string) {
	if len(permitted) == 0 {
		return string(jose.RS256)
	}

	var supported []string

	if strategy != nil {
		supported = strategy.SigningAlgValues(ctx)
	}

	isSupported := func(alg string) bool {
		return alg != "" && slices.Contains(permitted, alg) && (strategy == nil || slices.Contains(supported, alg))
	}

	if isSupported(string(jose.RS256)) {
		return string(jose.RS256)
	}

	for _, alg = range permitted {
		if isSupported(alg) {
			return alg
		}
	}

	return permitted[0]
}
