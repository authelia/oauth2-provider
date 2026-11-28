// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
)

// WriteBearerAuthorizationChallenge sets the RFC 6750 Section 3 / RFC 9449 Section 7.1 'WWW-Authenticate' challenge
// for an endpoint acting as an OAuth 2.0 protected resource, and returns the error with its status corrected for that
// context. The caller writes the response body.
//
// The schemes passed to BearerAuthorizationChallenge are those of the 'Authorization' header values of r which carry
// a credential. A header value of another scheme such as Basic, of the DPoP scheme while DPoP is disabled, or without a
// token is not an access token, so a request with nothing else carries a challenge without error information (RFC 6750
// Section 3.1). An access token sent in the form-encoded body (RFC 6750 Section 2.2), or in the URI query (RFC 6750 Section 2.3) when
// GetAccessTokenURIQueryParameterEnabled permits it, is a credential of the Bearer scheme, so a request which included
// an access token by any method carries the error information and only a request with none carries a challenge without
// it (RFC 6750 Section 3 and Section 3.1). The 'access_token' parameter is read from the form the endpoint parsed and r
// is never parsed here, so an endpoint which only accepts the header leaves a parameter it ignored unreported. r may be
// nil, in which case the scheme used cannot be established and both the Bearer and DPoP challenges carry the error
// information.
//
// ErrInvalidDPoPProof, ErrUseDPoPNonce and ErrInsufficientUserAuthentication are HTTP 400 at the token endpoint but
// are returned as 401 here, as required at a protected resource. The 'acr_values' and 'max_age' members set on an
// insufficient_user_authentication error with WithExtra are carried as challenge parameters.
//
// When the Configurator implements ProtectedResourceMetadataURLProvider and r is not nil, the URL it returns for r is
// carried on every challenge as the RFC 9728 Section 5.1 'resource_metadata' parameter.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3, https://www.rfc-editor.org/rfc/rfc9449#section-7.1,
// https://www.rfc-editor.org/rfc/rfc9449#section-7.2, https://www.rfc-editor.org/rfc/rfc9470#section-3, and
// https://datatracker.ietf.org/doc/html/rfc9728#section-5.1
func (f *Fosite) WriteBearerAuthorizationChallenge(ctx context.Context, rw http.ResponseWriter, r *http.Request, err error) (rfc *RFC6749Error) {
	rfc, _ = f.writeBearerAuthorizationChallenge(ctx, rw, r, err)

	return rfc
}

func (f *Fosite) writeBearerAuthorizationChallenge(ctx context.Context, rw http.ResponseWriter, r *http.Request, err error) (rfc *RFC6749Error, bare bool) {
	rfc = ErrorToRFC6749Error(err)

	switch rfc.ErrorField {
	case errInvalidDPoPProofName, errUseDPoPNonceName, errInsufficientUserAuthenticationName:
		rfc = rfc.WithCode(http.StatusUnauthorized)
	}

	var schemes []string

	if r == nil {
		schemes = []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP}
	} else {
		schemes = presentedSchemes(authorizationHeaderSchemes(r), f.Config.GetDPoPEnabled(ctx))

		if len(schemes) == 0 && hasAccessTokenParameter(r, f.accessTokenURIQueryParameterEnabled(ctx)) {
			schemes = append(schemes, consts.AuthSchemeBearer)
		}
	}

	var resourceMetadata string

	if provider, ok := f.Config.(ProtectedResourceMetadataURLProvider); ok && r != nil {
		resourceMetadata = provider.GetProtectedResourceMetadataURL(ctx, r)
	}

	rw.Header().Set(consts.HeaderWWWAuthenticate, BearerAuthorizationChallengeWithResourceMetadata(ctx, f.Config, "", resourceMetadata, rfc, schemes...))

	// RFC 9449 Section 9: a resource server signaling that it requires a nonce must supply one, or the client has
	// nothing to retry with and the handshake cannot complete.
	if rfc.ErrorField == errUseDPoPNonceName && f.Config.GetDPoPEnabled(ctx) {
		if strategy := f.Config.GetDPoPStrategy(ctx); strategy != nil {
			if nonce, nerr := strategy.NewDPoPNonce(ctx); nerr == nil {
				rw.Header().Set(consts.HeaderDPoPNonce, nonce)
			}
		}
	}

	return rfc, len(schemes) == 0 && rfc.CodeField == http.StatusUnauthorized && rfc.ErrorField != errUseDPoPNonceName
}

func authorizationHeaderSchemes(r *http.Request) (schemes []string) {
	for _, value := range r.Header.Values(consts.HeaderAuthorization) {
		if scheme, token, _ := strings.Cut(value, " "); strings.TrimLeft(token, " ") != "" {
			schemes = append(schemes, scheme)
		}
	}

	return schemes
}

func writeBareAuthorizationChallenge(rw http.ResponseWriter) {
	rw.Header().Del(consts.HeaderContentType)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.WriteHeader(http.StatusUnauthorized)
}

// BearerAuthorizationChallengeConfigProvider is the configuration BearerAuthorizationChallenge composes the DPoP
// challenge from.
type BearerAuthorizationChallengeConfigProvider interface {
	// GetDPoPEnabled returns true if DPoP handling is enabled.
	GetDPoPEnabled(ctx context.Context) (enabled bool)

	// GetDPoPAllowedJWSAlgorithms returns the permitted asymmetric DPoP proof signing algorithms.
	GetDPoPAllowedJWSAlgorithms(ctx context.Context) (algs []string)
}

// ProtectedResourceMetadataURLProvider is optionally implemented by the Configurator to locate the protected resource
// metadata carried in the 'resource_metadata' parameter of the 'WWW-Authenticate' challenge. The URL should be derived
// from the configured resource identifiers, not from request headers such as Host. The error writers only carry the
// parameter when they are given the request being answered.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-5.1
type ProtectedResourceMetadataURLProvider interface {
	// GetProtectedResourceMetadataURL returns the URL of the protected resource metadata for the protected resource
	// r was made to, or an empty string to omit the parameter.
	GetProtectedResourceMetadataURL(ctx context.Context, r *http.Request) (location string)
}

// BearerAuthorizationChallenge returns the RFC 6750 Section 3 / RFC 9449 Section 7.1 'WWW-Authenticate' value for a
// protected resource rejecting a request with err. It neither sets headers nor corrects the status of err, so it suits
// callers that do not write a net/http response; see WriteBearerAuthorizationChallenge for one that does.
//
// schemes are the authentication schemes of the credentials the request presented, compared case-insensitively. Only
// Bearer, and DPoP when DPoP is enabled, present an access token; any other value is ignored. An access token sent in the form-encoded body or the URI query (RFC 6750 Section 2.2 and
// Section 2.3) is presented using the Bearer scheme. The value follows RFC 9449 Section 7.2:
//
//   - No scheme means the request carried no authentication information, and the challenges carry no error
//     parameters at all (Figure 17), which RFC 6750 Section 3.1 also requires. The nonce challenge is the sole
//     exception, because a client bootstrapping a nonce needs the code to know what to retry.
//   - One scheme means the scheme used is established, and only the corresponding challenge carries the error
//     information (Figure 18 for Bearer, Figure 16 for DPoP).
//   - More than one scheme means it cannot be established, and both challenges carry it (Figure 19).
//   - The 'algs' parameter is always offered on the DPoP challenge (SHOULD, Section 7.1).
//   - A 'scope' parameter is offered on an insufficient_scope challenge (MAY, RFC 6750 Section 3.1).
//   - The 'acr_values' and 'max_age' parameters are offered on an insufficient_user_authentication challenge (RFC 9470
//     Section 3).
//
// A non-empty realm is carried on every challenge (RFC 6750 Section 3). The value carries no 'resource_metadata'
// parameter; see BearerAuthorizationChallengeWithResourceMetadata for one that does.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3, https://www.rfc-editor.org/rfc/rfc9449#section-7.1, and
// https://www.rfc-editor.org/rfc/rfc9449#section-7.2, and https://www.rfc-editor.org/rfc/rfc9470#section-3
func BearerAuthorizationChallenge(ctx context.Context, config BearerAuthorizationChallengeConfigProvider, realm string, err error, schemes ...string) (value string) {
	return BearerAuthorizationChallengeWithResourceMetadata(ctx, config, realm, "", err, schemes...)
}

// BearerAuthorizationChallengeWithResourceMetadata returns the BearerAuthorizationChallenge value with a non-empty
// resourceMetadata, the URL of the protected resource metadata, carried on every challenge as the 'resource_metadata'
// parameter after the realm.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-5.1
func BearerAuthorizationChallengeWithResourceMetadata(ctx context.Context, config BearerAuthorizationChallengeConfigProvider, realm, resourceMetadata string, err error, schemes ...string) (value string) {
	rfc := ErrorToRFC6749Error(err)

	presented := presentedSchemes(schemes, config.GetDPoPEnabled(ctx))

	var realmParam string

	if realm != "" {
		realmParam = "realm=" + challengeQuotedString(realm)
	}

	var resourceMetadataParam string

	if resourceMetadata != "" {
		resourceMetadataParam = consts.ChallengeParameterResourceMetadata + "=" + challengeQuotedString(resourceMetadata)
	}

	var params []string

	if len(presented) != 0 || rfc.ErrorField == errUseDPoPNonceName {
		params = bearerChallengeErrorParams(rfc)
	}

	bearer := func(params ...string) string {
		return challengeScheme(consts.AuthSchemeBearer, append([]string{realmParam, resourceMetadataParam}, params...)...)
	}

	if !config.GetDPoPEnabled(ctx) {
		return bearer(params...)
	}

	var algs string

	if a := config.GetDPoPAllowedJWSAlgorithms(ctx); len(a) != 0 {
		algs = "algs=" + challengeQuotedString(strings.Join(a, " "))
	}

	dpop := func(params ...string) string {
		return challengeScheme(consts.AuthSchemeDPoP, append(append([]string{realmParam, resourceMetadataParam}, params...), algs)...)
	}

	switch {
	case rfc.ErrorField == errUseDPoPNonceName:
		// RFC 9449 Section 9 Figure 24: a nonce challenge names the DPoP scheme only. A nonce is meaningless under the
		// Bearer scheme, so advertising Bearer alongside it would invite a retry that can never succeed.
		return dpop(params...)
	case len(presented) > 1:
		return bearer(params...) + ", " + dpop(params...)
	case len(presented) == 1 && strings.EqualFold(presented[0], DPoPAccessToken):
		return bearer() + ", " + dpop(params...)
	case len(presented) == 1:
		return bearer(params...) + ", " + dpop()
	default:
		return bearer() + ", " + dpop()
	}
}

func hasAccessTokenParameter(r *http.Request, query bool) (has bool) {
	if query {
		return r.Form.Get(consts.FormParameterAccessToken) != ""
	}

	return r.PostForm.Get(consts.FormParameterAccessToken) != ""
}

func presentedSchemes(schemes []string, dpop bool) (presented []string) {
	for _, scheme := range schemes {
		if !strings.EqualFold(scheme, BearerAccessToken) && (!dpop || !strings.EqualFold(scheme, DPoPAccessToken)) {
			continue
		}

		if !slices.ContainsFunc(presented, func(s string) bool { return strings.EqualFold(s, scheme) }) {
			if presented = append(presented, scheme); len(presented) == 2 {
				break
			}
		}
	}

	return presented
}

// bearerChallengeErrorParams returns the error information challenge parameters for rfc.
func bearerChallengeErrorParams(rfc *RFC6749Error) (params []string) {
	params = append(params, "error="+challengeQuotedString(rfc.ErrorField))

	if rfc.DescriptionField != "" {
		params = append(params, "error_description="+challengeQuotedString(rfc.DescriptionField))
	}

	if rfc.ErrorField == errInsufficientScopeName && rfc.ScopeField != "" {
		params = append(params, "scope="+challengeQuotedString(rfc.ScopeField))
	}

	if rfc.ErrorField == errInsufficientUserAuthenticationName {
		params = append(params, authenticationRequirementParams(rfc)...)
	}

	return params
}

// authenticationRequirementParams returns the RFC 9470 Section 3 'acr_values' and 'max_age' challenge parameters from
// the error extras. An 'acr_values' slice is joined with spaces.
//
// See: https://www.rfc-editor.org/rfc/rfc9470#section-3
func authenticationRequirementParams(rfc *RFC6749Error) (params []string) {
	switch value := rfc.extra[consts.FormParameterAuthenticationContextClassReferenceValues].(type) {
	case string:
		if value != "" {
			params = append(params, "acr_values="+challengeQuotedString(value))
		}
	case []string:
		if len(value) != 0 {
			params = append(params, "acr_values="+challengeQuotedString(strings.Join(value, " ")))
		}
	}

	if value, ok := rfc.extra[consts.FormParameterMaximumAge]; ok && value != nil {
		params = append(params, "max_age="+challengeQuotedString(fmt.Sprint(value)))
	}

	return params
}

// challengeScheme formats a single 'WWW-Authenticate' challenge for scheme, omitting empty params.
func challengeScheme(scheme string, params ...string) (value string) {
	set := make([]string, 0, len(params))

	for _, param := range params {
		if param != "" {
			set = append(set, param)
		}
	}

	if len(set) == 0 {
		return scheme
	}

	return scheme + " " + strings.Join(set, ", ")
}

// challengeQuotedString formats value as a RFC 9110 Section 5.6.4 quoted-string, dropping the control characters it
// cannot carry.
//
// See: https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4
func challengeQuotedString(value string) string {
	value = strings.Map(func(c rune) rune {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return -1
		}

		return c
	}, value)

	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

// IsBearerCredentialError reports whether err is a rejection of a bearer credential presented to authorize a call,
// and so warrants a RFC 6750 Section 3 'WWW-Authenticate' challenge naming the Bearer and DPoP schemes.
//
// ErrRequestUnauthorized is deliberately excluded as it is a client authentication failure, where neither scheme was
// attempted. ErrInvalidRequest is excluded as it says nothing about how the caller authenticated.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3 and https://www.rfc-editor.org/rfc/rfc6749#section-5.2
func IsBearerCredentialError(err error) (is bool) {
	return errors.Is(err, ErrInvalidToken) ||
		errors.Is(err, ErrInsufficientScope) ||
		errors.Is(err, ErrInsufficientUserAuthentication) ||
		errors.Is(err, ErrInvalidDPoPProof) ||
		errors.Is(err, ErrUseDPoPNonce)
}
