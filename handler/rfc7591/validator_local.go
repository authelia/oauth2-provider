// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// LocalValidatorConfig is the configuration oauth2.ClientRegistrationValidator LocalValidator depends on.
type LocalValidatorConfig interface {
	oauth2.ScopeStrategyProvider
	oauth2.AudienceStrategyProvider
}

// LocalValidator is an oauth2.ClientRegistrationValidator that performs purely local checks against submitted
// client registration metadata: no network access is performed, so checks that require dereferencing a client
// supplied URI (such as the OpenID Connect 'sector_identifier_uri') are out of scope here.
type LocalValidator struct {
	config LocalValidatorConfig
}

// NewLocalValidator returns a new *LocalValidator.
func NewLocalValidator(config LocalValidatorConfig) (validator *LocalValidator) {
	return &LocalValidator{config: config}
}

// ValidateClientRegistrationMetadata validates the given metadata using purely local, network-free checks. client
// is nil on a client registration request, and the existing client on a client configuration request; neither is
// consulted by these checks, which validate the incoming metadata in isolation.
func (v *LocalValidator) ValidateClientRegistrationMetadata(ctx context.Context, client oauth2.Client, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if err = validateRedirectURIs(metadata); err != nil {
		return err
	}

	if err = validateApplicationType(metadata); err != nil {
		return err
	}

	if err = validateSubjectType(metadata); err != nil {
		return err
	}

	if err = validateJSONWebKeys(metadata); err != nil {
		return err
	}

	if err = validateGrantResponseTypeCoherence(metadata); err != nil {
		return err
	}

	if err = validateAlgorithms(metadata); err != nil {
		return err
	}

	if err = validateScopes(metadata); err != nil {
		return err
	}

	return nil
}

// validateRedirectURIs implements RFC 6749 Section 3.1.2: every redirect URI must parse, be absolute, and carry no
// fragment. It additionally enforces the OAuth 2.0 Security Best Current Practice scheme rules for the declared
// 'application_type': a 'web' client (the default when 'application_type' is absent) must use 'https' and must not
// target 'localhost', while a 'native' client may use a non-'https' scheme only for a loopback redirect
// (127.0.0.1 or [::1]) or a non-HTTP custom scheme.
//
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
// See: https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
func validateRedirectURIs(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	for _, raw := range metadata.RedirectURIs {
		var parsed *url.URL

		if parsed, err = url.Parse(raw); err != nil || !parsed.IsAbs() {
			return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHintf("The '%s' value '%s' must be an absolute URI.", consts.ClientMetadataRedirectURIs, raw))
		}

		if parsed.Fragment != "" {
			return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHintf("The '%s' value '%s' must not contain a fragment component.", consts.ClientMetadataRedirectURIs, raw))
		}

		if metadata.ApplicationType == consts.ApplicationTypeNative {
			if parsed.Scheme == consts.SchemeHTTPS {
				continue
			}

			if parsed.Scheme != consts.SchemeHTTP {
				// A non-HTTP custom scheme is permitted unconditionally for native clients.
				continue
			}

			if !isLoopbackHost(parsed.Hostname()) {
				return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHintf("The '%s' value '%s' must use the 'https' scheme, a loopback address (127.0.0.1 or [::1]), or a non-HTTP custom scheme for the 'native' '%s'.", consts.ClientMetadataRedirectURIs, raw, consts.ClientMetadataApplicationType))
			}

			continue
		}

		if parsed.Scheme != consts.SchemeHTTPS {
			return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHintf("The '%s' value '%s' must use the 'https' scheme.", consts.ClientMetadataRedirectURIs, raw))
		}

		if strings.EqualFold(parsed.Hostname(), "localhost") {
			return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHintf("The '%s' value '%s' must not target 'localhost'.", consts.ClientMetadataRedirectURIs, raw))
		}
	}

	return nil
}

// isLoopbackHost reports whether host is the literal loopback address 127.0.0.1 or ::1, as used by native
// application loopback redirect URIs.
//
// See: https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback)
}

// validateApplicationType implements the OpenID Connect Dynamic Client Registration 1.0 'application_type'
// metadata: the value must be absent, 'web', or 'native'.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
func validateApplicationType(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	switch metadata.ApplicationType {
	case "", consts.ApplicationTypeWeb, consts.ApplicationTypeNative:
		return nil
	default:
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' is not a recognized application type.", consts.ClientMetadataApplicationType, metadata.ApplicationType))
	}
}

// validateSubjectType implements the OpenID Connect Dynamic Client Registration 1.0 'subject_type' metadata: the
// value must be absent, 'public', or 'pairwise'.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
func validateSubjectType(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	switch metadata.SubjectType {
	case "", consts.SubjectTypePublic, consts.SubjectTypePairwise:
		return nil
	default:
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' is not a recognized subject type.", consts.ClientMetadataSubjectType, metadata.SubjectType))
	}
}

// validateJSONWebKeys implements OpenID Connect Dynamic Client Registration 1.0 Section 2: 'jwks' and 'jwks_uri'
// are mutually exclusive.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
func validateJSONWebKeys(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata.JSONWebKeys != nil && metadata.JSONWebKeysURI != "" {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' and '%s' parameters are mutually exclusive.", consts.ClientMetadataJSONWebKeys, consts.ClientMetadataJSONWebKeysURI))
	}

	return nil
}

// validateGrantResponseTypeCoherence checks that the declared 'grant_types' and 'response_types' are mutually
// coherent: a 'code' response type requires the 'authorization_code' grant, a 'token' or 'id_token' response type
// requires the 'implicit' grant, and the 'authorization_code' and 'implicit' grants each require at least one
// registered redirect URI.
func validateGrantResponseTypeCoherence(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	var responseTypeTokens []string

	for _, responseType := range metadata.ResponseTypes {
		responseTypeTokens = append(responseTypeTokens, strings.Fields(responseType)...)
	}

	hasGrantType := func(grantType string) bool {
		return slices.Contains(metadata.GrantTypes, grantType)
	}

	if slices.Contains(responseTypeTokens, consts.ResponseTypeAuthorizationCodeFlow) && !hasGrantType(consts.GrantTypeAuthorizationCode) {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' response type requires the '%s' grant type to be present in '%s'.", consts.ResponseTypeAuthorizationCodeFlow, consts.GrantTypeAuthorizationCode, consts.ClientMetadataGrantTypes))
	}

	if (slices.Contains(responseTypeTokens, consts.ResponseTypeImplicitFlowToken) || slices.Contains(responseTypeTokens, consts.ResponseTypeImplicitFlowIDToken)) && !hasGrantType(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("A '%s' or '%s' response type requires the '%s' grant type to be present in '%s'.", consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken, consts.GrantTypeImplicit, consts.ClientMetadataGrantTypes))
	}

	if hasGrantType(consts.GrantTypeAuthorizationCode) && len(metadata.RedirectURIs) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' grant type requires at least one '%s' value.", consts.GrantTypeAuthorizationCode, consts.ClientMetadataRedirectURIs))
	}

	if hasGrantType(consts.GrantTypeImplicit) && len(metadata.RedirectURIs) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' grant type requires at least one '%s' value.", consts.GrantTypeImplicit, consts.ClientMetadataRedirectURIs))
	}

	return nil
}

// signingOrEncryptionAlgorithm associates a client metadata algorithm field's value with the parameter name used
// in error hints.
type signingOrEncryptionAlgorithm struct {
	name  string
	value string
}

// validateAlgorithms checks the declared signing and encryption algorithm metadata: 'id_token_signed_response_alg'
// must not be 'none' (OpenID Connect Dynamic Client Registration 1.0 Section 2), and every non-empty signing or
// encryption algorithm value must be a syntactically valid, non-empty token (no embedded whitespace).
func validateAlgorithms(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata.IDTokenSignedResponseAlg == consts.JSONWebTokenAlgNone {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value must not be '%s'.", consts.ClientMetadataIDTokenSignedResponseAlg, consts.JSONWebTokenAlgNone))
	}

	algorithms := []signingOrEncryptionAlgorithm{
		{consts.ClientMetadataIDTokenSignedResponseAlg, metadata.IDTokenSignedResponseAlg},
		{consts.ClientMetadataIDTokenEncryptedResponseAlg, metadata.IDTokenEncryptedResponseAlg},
		{consts.ClientMetadataIDTokenEncryptedResponseEnc, metadata.IDTokenEncryptedResponseEnc},
		{consts.ClientMetadataUserinfoSignedResponseAlg, metadata.UserinfoSignedResponseAlg},
		{consts.ClientMetadataUserinfoEncryptedResponseAlg, metadata.UserinfoEncryptedResponseAlg},
		{consts.ClientMetadataUserinfoEncryptedResponseEnc, metadata.UserinfoEncryptedResponseEnc},
		{consts.ClientMetadataRequestObjectSigningAlg, metadata.RequestObjectSigningAlg},
		{consts.ClientMetadataRequestObjectEncryptionAlg, metadata.RequestObjectEncryptionAlg},
		{consts.ClientMetadataRequestObjectEncryptionEnc, metadata.RequestObjectEncryptionEnc},
		{consts.ClientMetadataTokenEndpointAuthAlg, metadata.TokenEndpointAuthSigningAlg},
	}

	for _, algorithm := range algorithms {
		if algorithm.value == "" {
			continue
		}

		if !isToken(algorithm.value) {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must be a non-empty token.", algorithm.name, algorithm.value))
		}
	}

	return nil
}

// isToken reports whether s is a non-empty token, i.e. it has no leading, trailing, or embedded whitespace.
func isToken(s string) bool {
	if s == "" {
		return false
	}

	return !strings.ContainsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
	})
}

// validateScopes implements a syntactic check of the 'scope' metadata: RFC 6749 Section 3.3 defines a scope token
// as one or more characters drawn from %x21 / %x23-5B / %x5D-7E, i.e. printable US-ASCII excluding space,
// double-quote ('"'), and backslash ('\'). This deliberately does not validate the declared scopes against
// config.GetScopeStrategy(ctx): at registration time there is nothing to match a self-contained needle against
// other than itself, which is always true and would not catch anything.
//
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
func validateScopes(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	for _, scope := range metadata.GetScopes() {
		if !isValidScopeToken(scope) {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' contains characters that are not permitted in a scope token.", consts.ClientMetadataScope, scope))
		}
	}

	return nil
}

// isValidScopeToken reports whether s is a syntactically valid RFC 6749 Section 3.3 scope-token: one or more
// characters in %x21 / %x23-5B / %x5D-7E.
func isValidScopeToken(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]

		switch {
		case c == 0x21:
		case c >= 0x23 && c <= 0x5B:
		case c >= 0x5D && c <= 0x7E:
		default:
			return false
		}
	}

	return true
}

var _ oauth2.ClientRegistrationValidator = (*LocalValidator)(nil)
