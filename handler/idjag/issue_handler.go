// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/claimvalue"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	subjectIdentifierNameIDFormat = "nameid_format"
	nameIDFormatTransient         = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// IssueHandler issues an Identity Assertion JWT Authorization Grant for an RFC 8693 token exchange whose
// 'requested_token_type' is 'urn:ietf:params:oauth:token-type:id-jag'. It MUST be registered after the
// rfc8693.TokenExchangeGrantHandler and before the rfc8693.ActorTokenValidationHandler.
//
// The rfc8693.TokenExchangeGrantHandler refuses a request with an 'actor_token', as Section 4.3 defines no processing
// for it and the grant would not identify the actor.
//
// The granted scopes are the requested scopes the relationship permits. They have the meaning of the Resource
// Authorization Server rather than the OpenID Connect meaning, so no value requests identity claims. For a refresh
// token 'subject_token' the rfc8693.RefreshTokenTypeHandler also rejects any requested 'audience' or 'resource' outside
// the grant of the refresh token or the current registration of the client, and compares the requested scopes only when
// the 'audience' identifies this server (Section 4.3.3).
//
// The 'auth_time', 'acr' and 'amr' claims describe one authentication of the End-User, so they are taken together
// from a single source: the validated 'subject_token' when it is an ID token or a refresh token and carries any of
// them, otherwise the ID token claims of the session, otherwise IssueStorage.GetIDJAGClaims (Section 3.1). Those of any other
// 'subject_token' are not issued. For a refresh token 'subject_token' the rfc8693.RefreshTokenTypeHandler supplies
// them from the ID token claims of the session the refresh token was issued for (Section 4.3.3).
//
// It accepts the RFC 9396 'authorization_details' parameter and grants the requested details whose type the
// relationship permits. When the audience is this server the details are first validated by the local type handlers
// against the types the client may request. For another server they have that server's meaning, so the relationship
// alone decides, and the IdP needs no type handler for them (Section 4.3.3). For a refresh token 'subject_token' whose 'audience' identifies this server, the
// rfc8693.RefreshTokenTypeHandler first replaces the requested details with those the details granted to the refresh
// token assign, and rejects a request they do not justify.
//
// The 'cnf' claim carries the single binding recorded on the session, preferring a DPoP key over an X.509 certificate
// when both are recorded (Section 9.11). The 'jkt' member equals the validated DPoP proof key only when rfc9449.Handler
// is composed; with DPoP enabled and no rfc9449.Handler it may be the binding of the subject token. The 'x5t#S256'
// member is the certificate rfc8705.Handler verified, for a client whose certificate-bound access tokens are required
// or a subject token bound to the certificate. An issuer SHOULD NOT bind a grant to a DPoP key for a Resource
// Authorization Server unless it knows that server supports the 'jwt-dpop' grant type, as one which does not may accept
// the grant as a bearer assertion (draft-parecki-oauth-jwt-dpop-grant-02 Section 7.1).
//
// The relationship may require an Authentication Context Class Reference and a maximum authentication age. A grant
// whose 'acr' and 'auth_time' claims do not satisfy them is refused with insufficient_user_authentication, and the
// error response carries the requirements as 'acr_values' and 'max_age' as RFC 9470 defines them (Section 9.3).
//
// The 'iss' claim is the RFC 8414 issuer identifier of the authorization server, which MUST be configured (Section
// 3.1).
//
// The 'sub' claim is the subject identifier IssueStorage.GetIDJAGSubject returns for the Resource Authorization Server
// (Section 5.2). Claims such as 'email', 'aud_sub', 'tenant', 'aud_tenant' and 'sub_id' are supplied through
// IssueStorage.GetIDJAGClaims, which MUST supply 'tenant' when the issuer is multi-tenant (Section 6). A 'sub_id' claim using a transient SAML NameID Format is
// refused (Section 3.2.2).
//
// The IdP Authorization Server SHOULD record the audience, resource, scope and authenticated client of each Token
// Exchange request (Section 9.2), which the token endpoint calling NewAccessRequest and NewAccessResponse can do for a
// granted and a refused request alike. When granted, GetClient is the authenticated client, GetGrantedAudience is the
// issuer identifier of the Resource Authorization Server rather than any alias the client sent, and GetGrantedResource
// and GetGrantedScopes are what the grant carries. When refused, the request carries what was requested as
// GetRequestedAudience, GetRequestedResource and GetRequestedScopes, and GetClient once the client authenticated. The
// 'subject_token' and 'actor_token' form parameters should not be recorded, and the records kept only as long as
// security and audit require (Section 10).
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-3.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-5
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-6
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-9.2
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-9.3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-9.11.1.1
// See: https://datatracker.ietf.org/doc/html/rfc9470#section-3
type IssueHandler struct {
	Config   IssueConfig
	Strategy jwt.Strategy
	Storage  IssueStorage
}

// HandleTokenEndpointRequest resolves the relationship for the 'audience' and grants the permitted scopes and
// resources.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
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

	if len(relationship.Resources) != 0 && len(request.GetRequestedResource()) == 0 && !h.resourceOptional(ctx, request.GetClient()) {
		return errorsx.WithStack(oauth2.ErrInvalidTarget.WithHint("The 'resource' parameter is required for the requested audience."))
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

	request.GrantAudience(relationship.Issuer)

	return nil
}

func (h *IssueHandler) resourceOptional(ctx context.Context, client oauth2.Client) bool {
	if provider, ok := h.Config.(oauth2.IDJAGResourceOptionalProvider); ok && provider.GetIDJAGResourceOptional(ctx) {
		return true
	}

	c, ok := client.(oauth2.IDJAGResourceOptionalClient)

	return ok && c.GetIDJAGResourceOptional()
}

// PopulateTokenEndpointResponse issues the grant.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.4
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

	issuer := h.Config.GetIssuer(ctx)
	if issuer == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The authorization server issuer identifier is not configured."))
	}

	subject, err := h.subject(ctx, request, relationship)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	expires := rfc8693.CapToSubjectTokenExpiry(request, now.Add(h.Config.GetIDJAGLifespan(ctx))).Truncate(jwt.TimePrecision)

	if expires.Sub(now) < time.Second {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The subject token expires too soon to issue an Identity Assertion JWT Authorization Grant."))
	}

	// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
	if relationship.Issuer == issuer {
		if err = oauth2.ValidateAuthorizationDetails(ctx, h.Config, request, request.GetRequestedAuthorizationDetails()); err != nil {
			return err
		}
	}

	if err = h.grantAuthorizationDetails(ctx, request, relationship); err != nil {
		return err
	}

	claims, err := h.claims(ctx, request, relationship, issuer, subject, now, expires)
	if err != nil {
		return err
	}

	if isTransientSubjectIdentifier(claims) {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The 'sub_id' claim uses a transient SAML NameID Format."))
	}

	if err = requireAuthentication(relationship, claims, now, max(h.Config.GetJWTClockSkew(ctx), 0)); err != nil {
		return err
	}

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

// ValidatesAuthorizationDetailsTypes implements oauth2.AuthorizationDetailsTypeValidatingHandler. The requested
// authorization details of an ID-JAG request are validated locally only when the audience is this server, as for
// another server they have that server's meaning (Section 4.3.3).
func (h *IssueHandler) ValidatesAuthorizationDetailsTypes(ctx context.Context, request oauth2.AccessRequester) bool {
	return rfc8693.IsIDJAGRequest(ctx, request, h.Config)
}

// CanHandleAuthorizationDetails implements oauth2.AuthorizationDetailsTokenEndpointHandler. It accepts the RFC 9396
// 'authorization_details' parameter of a token exchange requesting an ID-JAG.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.1
func (h *IssueHandler) CanHandleAuthorizationDetails(ctx context.Context, request oauth2.AccessRequester) bool {
	return rfc8693.IsIDJAGRequest(ctx, request, h.Config)
}

func (h *IssueHandler) claims(ctx context.Context, request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship, issuer, subject string, now, expires time.Time) (claims jwt.MapClaims, err error) {
	extra, err := h.Storage.GetIDJAGClaims(ctx, request, relationship)
	if err != nil {
		var rfc *oauth2.RFC6749Error
		if errors.As(err, &rfc) {
			return nil, errorsx.WithStack(err)
		}

		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	claims = jwt.MapClaims{}

	maps.Copy(claims, extra)

	delete(claims, consts.ClaimConfirmation)
	delete(claims, consts.ClaimActor)
	delete(claims, consts.ClaimAuthorizationDetails)
	delete(claims, consts.ClaimResource)
	delete(claims, consts.ClaimScope)

	for _, source := range authenticationSources(request) {
		if source.AuthTime == nil && source.AuthenticationContextClassReference == "" && len(source.AuthenticationMethodsReferences) == 0 {
			continue
		}

		delete(claims, consts.ClaimAuthenticationTime)
		delete(claims, consts.ClaimAuthenticationContextClassReference)
		delete(claims, consts.ClaimAuthenticationMethodsReference)

		if source.AuthTime != nil {
			claims[consts.ClaimAuthenticationTime] = source.AuthTime.Unix()
		}

		if source.AuthenticationContextClassReference != "" {
			claims[consts.ClaimAuthenticationContextClassReference] = source.AuthenticationContextClassReference
		}

		if len(source.AuthenticationMethodsReferences) != 0 {
			claims[consts.ClaimAuthenticationMethodsReference] = source.AuthenticationMethodsReferences
		}

		break
	}

	claims[consts.ClaimIssuer] = issuer
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

	if member, value := h.confirmation(ctx, request.GetSession()); member != "" {
		claims[consts.ClaimConfirmation] = map[string]any{member: value}
	}

	return claims, nil
}

func (h *IssueHandler) confirmation(ctx context.Context, session oauth2.Session) (member, value string) {
	if h.Config.GetDPoPEnabled(ctx) {
		if bound, ok := session.(oauth2.DPoPBoundSession); ok && bound.GetDPoPJWKThumbprint() != "" {
			return consts.ClaimConfirmationJWKThumbprint, bound.GetDPoPJWKThumbprint()
		}
	}

	if h.Config.GetMTLSEnabled(ctx) {
		if bound, ok := session.(oauth2.MTLSBoundSession); ok && bound.GetClientCertificateSHA256Thumbprint() != "" {
			return consts.ClaimConfirmationX509SHA256Thumbprint, bound.GetClientCertificateSHA256Thumbprint()
		}
	}

	return "", ""
}

func isTransientSubjectIdentifier(claims map[string]any) bool {
	value := claims[consts.ClaimSubjectIdentifier]
	if value == nil {
		return false
	}

	var identifier map[string]any

	// The claim is serialized as JSON, so it is read as the issued grant will carry it.
	if encoded, err := json.Marshal(value); err == nil {
		_ = json.Unmarshal(encoded, &identifier)
	}

	format, _ := identifier[subjectIdentifierNameIDFormat].(string)

	return format == nameIDFormatTransient
}

func requireAuthentication(relationship *oauth2.IDJAGRelationship, claims jwt.MapClaims, now time.Time, skew time.Duration) (err error) {
	acr, _ := claims[consts.ClaimAuthenticationContextClassReference].(string)

	satisfied := len(relationship.ACRValues) == 0 || slices.Contains(relationship.ACRValues, acr)

	if relationship.MaxAge > 0 {
		authTime, ok := claimvalue.Time(claims[consts.ClaimAuthenticationTime])

		satisfied = satisfied && ok && !authTime.After(now.Add(skew)) && now.Sub(authTime) <= relationship.MaxAge
	}

	if satisfied {
		return nil
	}

	rfc := oauth2.ErrInsufficientUserAuthentication.WithHintf("The authentication of the subject does not meet the requirements for the audience '%s'.", relationship.Issuer)

	if len(relationship.ACRValues) != 0 {
		rfc = rfc.WithExtra(consts.FormParameterAuthenticationContextClassReferenceValues, strings.Join(relationship.ACRValues, " "))
	}

	if relationship.MaxAge > 0 {
		rfc = rfc.WithExtra(consts.FormParameterMaximumAge, int64(relationship.MaxAge/time.Second))
	}

	return errorsx.WithStack(rfc)
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

func (h *IssueHandler) grantAuthorizationDetails(ctx context.Context, request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship) (err error) {
	requested := request.GetRequestedAuthorizationDetails()
	if len(requested) == 0 {
		return nil
	}

	granted := oauth2.AuthorizationDetails{}

	for _, detail := range requested {
		if permitsAuthorizationDetailsType(relationship, detail.Type) {
			granted = append(granted, detail.Clone())
		}
	}

	if policy, ok := h.Storage.(IssueAuthorizationDetailsStorage); ok {
		if granted, err = policy.GetIDJAGAuthorizationDetails(ctx, request, relationship, granted); err != nil {
			var rfc *oauth2.RFC6749Error
			if errors.As(err, &rfc) {
				return errorsx.WithStack(err)
			}

			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		if granted == nil {
			granted = oauth2.AuthorizationDetails{}
		}

		for _, detail := range granted {
			if !permitsAuthorizationDetailsType(relationship, detail.Type) {
				return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The authorization details policy granted the type '%s' which the relationship with '%s' does not permit.", detail.Type, relationship.Issuer))
			}
		}
	}

	request.SetGrantedAuthorizationDetails(granted)

	return nil
}

func permitsAuthorizationDetailsType(relationship *oauth2.IDJAGRelationship, t string) bool {
	return relationship.AuthorizationDetailsTypes == nil || slices.Contains(relationship.AuthorizationDetailsTypes, t)
}

func (h *IssueHandler) subject(ctx context.Context, request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship) (subject string, err error) {
	if request.GetSession().GetSubject() == "" {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("The session has no subject to issue the grant for."))
	}

	subject, err = h.Storage.GetIDJAGSubject(ctx, request, relationship)

	switch {
	case errors.Is(err, oauth2.ErrNotFound):
		return "", errorsx.WithStack(oauth2.ErrAccessDenied.WithDebugf("The subject is not authorized for the audience '%s'.", relationship.Issuer))
	case err != nil:
		var rfc *oauth2.RFC6749Error
		if errors.As(err, &rfc) {
			return "", errorsx.WithStack(err)
		}

		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	case subject == "":
		return "", errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The subject identifier for the audience '%s' is empty.", relationship.Issuer))
	}

	return subject, nil
}

func (h *IssueHandler) relationship(ctx context.Context, request oauth2.AccessRequester) (relationship *oauth2.IDJAGRelationship, err error) {
	audiences := request.GetRequestedAudience()

	if len(audiences) != 1 {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Exactly one '%s' is required when the '%s' is '%s'.", consts.FormParameterAudience, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693IDJAG))
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

// GrantTypesSupported returns nil because the handler only augments another grant.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (h *IssueHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return nil
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (h *IssueHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns nil because the handler does not issue ID Tokens.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (h *IssueHandler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return nil
}

// RFC8693TokenTypesSupported returns the configured Identity Assertion JWT Authorization Grant token type identifier
// when it is issuable.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3
func (h *IssueHandler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return rfc8693.IssuableTokenTypes(ctx, h.Config, func(identifier string, _ oauth2.RFC8693TokenType) bool {
		return rfc8693.IsIDJAGRequestedTokenType(identifier)
	})
}

var (
	_ oauth2.TokenEndpointHandler                     = (*IssueHandler)(nil)
	_ oauth2.AuthorizationDetailsTokenEndpointHandler = (*IssueHandler)(nil)
)

// SigningAlgValuesSupported returns the JWS algorithms the handler can sign an ID-JAG with.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-7
func (h *IssueHandler) SigningAlgValuesSupported(ctx context.Context) (algs []string) {
	if h.Strategy == nil {
		return nil
	}

	return h.Strategy.SigningAlgValues(ctx)
}

// IdentityChainingRequestedTokenTypesSupported returns the configured Identity Assertion JWT Authorization Grant token
// type identifier when it is issuable, as the grant profiles Identity and Authorization Chaining Across Domains.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-3
func (h *IssueHandler) IdentityChainingRequestedTokenTypesSupported(ctx context.Context) (types []string) {
	return h.RFC8693TokenTypesSupported(ctx)
}

var (
	_ oauth2.IDJAGIssuingHandler     = (*IssueHandler)(nil)
	_ oauth2.IdentityChainingHandler = (*IssueHandler)(nil)
)
