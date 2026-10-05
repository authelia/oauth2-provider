// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// WriteIntrospectionError writes the introspection error response. An inactive token is not an error and is answered
// with an introspection response whose 'active' member is false.
//
// See: https://datatracker.ietf.org/doc/html/rfc7662#section-2.3
func (f *Fosite) WriteIntrospectionError(ctx context.Context, rw http.ResponseWriter, err error) {
	if err == nil {
		return
	}

	// Inactive token errors should never be written out as an error.
	if !errors.Is(err, ErrInactiveToken) && (errors.Is(err, ErrInvalidRequest) || errors.Is(err, ErrInvalidClient) || errors.Is(err, ErrRequestUnauthorized)) {
		f.writeErrorJSON(ctx, rw, nil, err)

		return
	}

	// A rejected bearer credential additionally warrants a challenge naming the schemes this endpoint accepts.
	if !errors.Is(err, ErrInactiveToken) && IsBearerCredentialError(err) {
		// The request is present when the caller writes the error from the context NewIntrospectionRequest derived,
		// and absent otherwise. WriteBearerAuthorizationChallenge accepts either.
		r, _ := ctx.Value(RequestContextKey).(*http.Request)

		rfc := f.WriteBearerAuthorizationChallenge(ctx, rw, r, err)

		// RFC 7662 Section 2.3: a bearer credential that "does not contain sufficient privileges or is otherwise
		// invalid for this request" is answered with HTTP 401. That is more specific than RFC 6750 Section 3.1's
		// general 403 for insufficient_scope, so it wins here. The RFC 7591 client registration endpoint has no such
		// override and answers 403 for the same condition.
		if rfc.ErrorField == errInsufficientScopeName {
			rfc = rfc.WithCode(http.StatusUnauthorized)
		}

		f.writeErrorJSONRFC(ctx, rw, rfc)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	_ = json.NewEncoder(rw).Encode(struct {
		Active bool `json:"active"`
	}{Active: false})
}

// WriteIntrospectionResponse writes the introspection response.
//
// See: https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
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

	response := map[string]any{jwt.ClaimActive: false}

	if !r.IsActive() {
		f.writeIntrospectionResponse(ctx, rw, r, caller, response, alg, kid)

		return
	}

	response[jwt.ClaimActive] = true

	extraClaimsSession, ok := r.GetAccessRequester().GetSession().(ExtraClaimsSession)
	if ok {
		extraClaims := extraClaimsSession.GetExtraClaims()
		for name, value := range extraClaims {
			switch name {
			// We do not allow these to be set through extra claims.
			case jwt.ClaimExpirationTime, jwt.ClaimClientIdentifier, jwt.ClaimScope, jwt.ClaimIssuedAt, jwt.ClaimSubject, jwt.ClaimAudience, jwt.ClaimUsername, jwt.ClaimConfirmation, jwt.ClaimAuthorizationDetails:
				continue
			default:
				response[name] = value
			}
		}
	}

	if expires := r.GetAccessRequester().GetSession().GetExpiresAt(r.GetTokenUse()); !expires.IsZero() {
		response[jwt.ClaimExpirationTime] = expires.Unix()
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
	if details := r.GetAccessRequester().GetGrantedAuthorizationDetails(); len(details) != 0 {
		response[jwt.ClaimAuthorizationDetails] = details
	}

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
			f.WriteIntrospectionError(ctx, rw, errors.WithStack(ErrServerError.WithHint("Failed to lookup required information to perform this request.").WithDebugf("The JTI could not be generated for the Introspection JWT response type with error %+v.", err)))

			return
		}

		claims := jwt.MapClaims{
			jwt.ClaimJWTID:              jti.String(),
			jwt.ClaimIssuer:             f.Config.GetIntrospectionIssuer(ctx),
			jwt.ClaimIssuedAt:           time.Now().UTC().Unix(),
			jwt.ClaimTokenIntrospection: response,
		}

		if aud, _ := r.ToMap(); len(aud) != 0 {
			claims[jwt.ClaimAudience] = aud
		}

		strategy := f.Config.GetIntrospectionJWTResponseStrategy(ctx)

		if strategy == nil {
			f.WriteIntrospectionError(ctx, rw, errors.WithStack(ErrServerError.WithHint("Failed to generate the response.").WithDebug("The Introspection JWT could not be generated as the server is misconfigured. The Introspection jwt.Strategy was not configured.")))

			return
		}

		if token, _, err = strategy.Encode(ctx, claims, jwt.WithHeaders(header), jwt.WithIntrospectionClient(caller)); err != nil {
			f.WriteIntrospectionError(ctx, rw, errors.WithStack(ErrServerError.WithHint("Failed to generate the response.").WithDebugf("The Introspection JWT itself could not be generated with error %+v.", err)))

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

func (f *Fosite) isIntrospectionTokenTypeEnabled(ctx context.Context, caller Client) (enabled bool) {
	if client, ok := caller.(IntrospectionTokenTypeClient); ok {
		return client.GetIntrospectionTokenTypeEnabled()
	}

	return f.Config != nil && f.Config.GetIntrospectionTokenTypeEnabled(ctx)
}
