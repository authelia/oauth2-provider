// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// IssueHandler issues an Identity Assertion JWT Authorization Grant for an RFC 8693 token exchange whose
// 'requested_token_type' is 'urn:ietf:params:oauth:token-type:id-jag'. It MUST be registered after the
// rfc8693.TokenExchangeGrantHandler and before the rfc8693.ActorTokenValidationHandler.
//
// The granted scopes are the requested scopes the relationship permits. For a refresh token 'subject_token' the
// rfc8693.RefreshTokenTypeHandler also rejects any requested scope, 'audience' or 'resource' outside the grant of the
// refresh token or the current registration of the client (Section 4.3.3).
//
// The 'auth_time', 'acr' and 'amr' claims come from the validated 'subject_token' when it is an ID token or a refresh
// token, then the ID token claims of the session (Section 3.1). Those of any other 'subject_token' are not issued. For a refresh token 'subject_token' the rfc8693.RefreshTokenTypeHandler supplies them from the
// ID token claims of the session the refresh token was issued for (Section 4.3.3).
//
// It accepts the RFC 9396 'authorization_details' parameter and grants the requested details whose type the
// relationship permits. For a refresh token 'subject_token' the rfc8693.RefreshTokenTypeHandler also rejects any
// requested detail not contained in the details granted to the refresh token.
//
// The 'cnf' claim carries the thumbprint bound to the session, which equals the validated DPoP proof key only when
// rfc9449.Handler is composed; with DPoP enabled and no rfc9449.Handler it may be the binding of the subject token.
//
// The 'sub' claim is the session subject, so a deployment with pairwise subjects sets the subject the Resource
// Authorization Server knows on the session before the response is issued (Section 5). The 'tenant', 'aud_tenant'
// and 'aud_sub' claims are supplied through Session.IDJAGClaims (Section 6).
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3.3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-5
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.8.1.1
type IssueHandler struct {
	Config   IssueConfig
	Strategy jwt.Strategy
	Storage  IssueStorage
}

// HandleTokenEndpointRequest resolves the relationship for the 'audience' and grants the permitted scopes and
// resources.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3.3
func (h *IssueHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !rfc8693.IsIDJAGRequest(ctx, request, h.Config) {
		return nil
	}

	relationship, err := h.relationship(ctx, request)
	if err != nil {
		return err
	}

	for _, resource := range request.GetRequestedResource() {
		if !slices.Contains(relationship.Resources, resource) {
			return errorsx.WithStack(oauth2.ErrInvalidTarget.WithHintf("The resource '%s' is not permitted for the requested audience.", resource))
		}

		request.GrantResource(resource)
	}

	strategy := oauth2.GetScopeStrategy(ctx, h.Config, request.GetClient())

	for _, scope := range request.GetRequestedScopes() {
		if strategy(relationship.Scopes, scope) {
			request.GrantScope(scope)
		}
	}

	grantAuthorizationDetails(request, relationship)

	request.GrantAudience(relationship.Issuer)

	return nil
}

// PopulateTokenEndpointResponse issues the grant.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3.4
func (h *IssueHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !rfc8693.IsIDJAGRequest(ctx, request, h.Config) {
		return nil
	}

	if err = rfc8693.RequireSubjectToken(request); err != nil {
		return err
	}

	if err = rfc8693.RequireActorToken(request); err != nil {
		return err
	}

	relationship, err := h.relationship(ctx, request)
	if err != nil {
		return err
	}

	subject := request.GetSession().GetSubject()
	if subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The session has no subject to issue the grant for."))
	}

	now := time.Now().UTC()
	expires := rfc8693.CapToSubjectTokenExpiry(request, now.Add(h.Config.GetIDJAGLifespan(ctx))).Truncate(jwt.TimePrecision)

	if expires.Sub(now) < time.Second {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The subject token expires too soon to issue an Identity Assertion JWT Authorization Grant."))
	}

	claims := h.claims(ctx, request, relationship, subject, now, expires)

	token, _, err := h.Strategy.Encode(ctx, claims,
		jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: consts.JSONWebTokenTypeIDJAG}}),
		jwt.WithIssuerSigningAlg(relationship.SigningAlg),
	)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.RFC8693NAToken)
	response.SetExpiresIn(expires.Sub(now))
	response.SetScopes(request.GetGrantedScopes())
	response.SetExtra(consts.FormParameterIssuedTokenType, consts.TokenTypeRFC8693IDJAG)

	if len(request.GetRequestedAuthorizationDetails()) != 0 {
		granted := request.GetGrantedAuthorizationDetails()
		if granted == nil {
			granted = oauth2.AuthorizationDetails{}
		}

		response.SetExtra(consts.AccessResponseAuthorizationDetails, granted)
	}

	return nil
}

// CanSkipClientAuth implements oauth2.TokenEndpointHandler.
func (h *IssueHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest implements oauth2.TokenEndpointHandler.
func (h *IssueHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

// CanHandleAuthorizationDetails implements oauth2.AuthorizationDetailsTokenEndpointHandler. It accepts the RFC 9396
// 'authorization_details' parameter of a token exchange requesting an ID-JAG.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3.1
func (h *IssueHandler) CanHandleAuthorizationDetails(ctx context.Context, request oauth2.AccessRequester) bool {
	return rfc8693.IsIDJAGRequest(ctx, request, h.Config)
}

func (h *IssueHandler) claims(ctx context.Context, request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship, subject string, now, expires time.Time) (claims jwt.MapClaims) {
	claims = jwt.MapClaims{}

	if session, ok := request.GetSession().(Session); ok {
		maps.Copy(claims, session.IDJAGClaims(ctx, relationship))
	}

	delete(claims, consts.ClaimConfirmation)
	delete(claims, consts.ClaimActor)
	delete(claims, consts.ClaimAuthorizationDetails)
	delete(claims, consts.ClaimResource)
	delete(claims, consts.ClaimScope)

	for _, source := range slices.Backward(authenticationSources(request)) {
		if source.AuthTime != nil {
			claims[consts.ClaimAuthenticationTime] = source.AuthTime.Unix()
		}

		if source.AuthenticationContextClassReference != "" {
			claims[consts.ClaimAuthenticationContextClassReference] = source.AuthenticationContextClassReference
		}

		if len(source.AuthenticationMethodsReferences) != 0 {
			claims[consts.ClaimAuthenticationMethodsReference] = source.AuthenticationMethodsReferences
		}
	}

	claims[consts.ClaimIssuer] = h.Config.GetAccessTokenIssuer(ctx)
	claims[consts.ClaimSubject] = subject
	claims[consts.ClaimAudience] = relationship.Issuer
	claims[consts.ClaimClientIdentifier] = relationship.ClientID
	claims[consts.ClaimJWTID] = uuid.New().String()
	claims[consts.ClaimIssuedAt] = now.Unix()
	claims[consts.ClaimExpirationTime] = expires.Unix()

	if scopes := request.GetGrantedScopes(); len(scopes) != 0 {
		claims[consts.ClaimScope] = strings.Join(scopes, " ")
	}

	switch resources := request.GetGrantedResource(); len(resources) {
	case 0:
	case 1:
		claims[consts.ClaimResource] = resources[0]
	default:
		claims[consts.ClaimResource] = []string(resources)
	}

	if details := request.GetGrantedAuthorizationDetails(); len(details) != 0 {
		claims[consts.ClaimAuthorizationDetails] = details
	}

	if h.Config.GetDPoPEnabled(ctx) {
		if session, ok := request.GetSession().(oauth2.DPoPBoundSession); ok && session.GetDPoPJWKThumbprint() != "" {
			claims[consts.ClaimConfirmation] = map[string]any{consts.ClaimConfirmationJWKThumbprint: session.GetDPoPJWKThumbprint()}
		}
	}

	return claims
}

func authenticationSources(request oauth2.AccessRequester) (sources []*jwt.IDTokenClaims) {
	session := request.GetSession()

	switch request.GetRequestForm().Get(consts.FormParameterSubjectTokenType) {
	case consts.TokenTypeRFC8693IDToken, consts.TokenTypeRFC8693RefreshToken:
		if s, ok := session.(interface{ GetSubjectToken() map[string]any }); ok {
			if token := s.GetSubjectToken(); token != nil {
				source := &jwt.IDTokenClaims{}
				source.FromMap(token)

				sources = append(sources, source)
			}
		}
	}

	if s, ok := session.(interface{ IDTokenClaims() *jwt.IDTokenClaims }); ok {
		if source := s.IDTokenClaims(); source != nil {
			sources = append(sources, source)
		}
	}

	return sources
}

func grantAuthorizationDetails(request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship) {
	requested := request.GetRequestedAuthorizationDetails()
	if len(requested) == 0 {
		return
	}

	granted := oauth2.AuthorizationDetails{}

	for _, detail := range requested {
		if relationship.AuthorizationDetailsTypes == nil || slices.Contains(relationship.AuthorizationDetailsTypes, detail.Type) {
			granted = append(granted, detail)
		}
	}

	request.SetGrantedAuthorizationDetails(granted)
}

func (h *IssueHandler) relationship(ctx context.Context, request oauth2.AccessRequester) (relationship *oauth2.IDJAGRelationship, err error) {
	audiences := request.GetRequestedAudience()

	if len(audiences) != 1 {
		return nil, errorsx.WithStack(oauth2.ErrInvalidTarget.WithHintf("Exactly one '%s' is required when the '%s' is '%s'.", consts.FormParameterAudience, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693IDJAG))
	}

	relationship, err = h.Storage.GetIDJAGRelationship(ctx, request, audiences[0])

	switch {
	case errors.Is(err, oauth2.ErrNotFound):
		return nil, errorsx.WithStack(oauth2.ErrInvalidTarget.WithHintf("The audience '%s' is not permitted.", audiences[0]))
	case err != nil:
		var rfc *oauth2.RFC6749Error
		if errors.As(err, &rfc) {
			return nil, errorsx.WithStack(err)
		}

		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	case relationship == nil || relationship.Issuer == "" || relationship.ClientID == "":
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The relationship for audience '%s' has no issuer or client identifier.", audiences[0]))
	}

	return relationship, nil
}

var (
	_ oauth2.TokenEndpointHandler                     = (*IssueHandler)(nil)
	_ oauth2.AuthorizationDetailsTokenEndpointHandler = (*IssueHandler)(nil)
)
