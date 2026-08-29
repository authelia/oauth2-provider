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
	oauth2.RFC7591ClientRegistrationGrantTypesProvider
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

// validators returns the configured oauth2.ClientRegistrationValidator values, falling back to a single
// LocalValidator when none are configured. The fallback is what makes registration safe out of the box, in the same
// way and for the same reason metadataStrategy defaults the metadata filter: without it an integrator who has never
// heard of this seam gets an endpoint that validates nothing at all, accepting a 'javascript:' redirect URI, a
// 'jwks' and 'jwks_uri' together, an 'id_token_signed_response_alg' of 'none', and grant and response types that
// contradict each other. Configuring validators explicitly replaces the default, including with an empty-but-non-nil
// slice for a deployment that genuinely wants no local validation.
//
// Network-dereferencing validators such as SectorIdentifierValidator are deliberately not included: they perform
// egress on a client supplied URI, which is a deployment decision rather than a safe default.
func validators(ctx context.Context, config Configurator) (validators []oauth2.ClientRegistrationValidator) {
	if validators = config.GetRFC7591ClientRegistrationValidators(ctx); validators != nil {
		return validators
	}

	return []oauth2.ClientRegistrationValidator{NewLocalValidator(config)}
}

// ValidateClientRegistrationMetadata validates the given metadata using purely local, network-free checks. client
// is nil on a client registration request, and the existing client on a client configuration request; neither is
// consulted by these checks, which validate the incoming metadata in isolation.
func (v *LocalValidator) ValidateClientRegistrationMetadata(ctx context.Context, client oauth2.Client, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if err = validateRedirectURIs(metadata); err != nil {
		return err
	}

	if err = validateURIs(metadata); err != nil {
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

	if err = validateGrantTypesPermitted(ctx, v.config, metadata); err != nil {
		return err
	}

	if err = validateAlgorithms(metadata); err != nil {
		return err
	}

	if err = validateScopes(metadata); err != nil {
		return err
	}

	if err = validateTLSClientAuth(metadata); err != nil {
		return err
	}

	return nil
}

// tlsClientAuthSubject associates an RFC 8705 Section 2.1.2 certificate subject metadata field's value with the
// parameter name used in error hints.
type tlsClientAuthSubject struct {
	name  string
	value string
}

// validateTLSClientAuth implements RFC 8705 Section 2.1.2: a client registering the 'tls_client_auth' method for any
// endpoint MUST register exactly one of the five certificate subject values, and Section 2.2.2: a client registering
// the 'self_signed_tls_client_auth' method MUST register its certificates through 'jwks' or 'jwks_uri'. Rejecting
// this at registration is what stops a client being created that can never authenticate; the same "exactly one"
// requirement is enforced again when the certificate is matched at the endpoint.
//
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-2.1.2
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-2.2.2
func validateTLSClientAuth(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	methods := []struct {
		name  string
		value string
	}{
		{consts.ClientMetadataTokenEndpointAuthMethod, metadata.TokenEndpointAuthMethod},
		{consts.ClientMetadataIntrospectionEndpointAuthMethod, metadata.IntrospectionEndpointAuthMethod},
		{consts.ClientMetadataRevocationEndpointAuthMethod, metadata.RevocationEndpointAuthMethod},
	}

	subjects := []tlsClientAuthSubject{
		{consts.ClientMetadataTLSClientAuthSubjectDN, metadata.TLSClientAuthSubjectDN},
		{consts.ClientMetadataTLSClientAuthSANDNS, metadata.TLSClientAuthSANDNS},
		{consts.ClientMetadataTLSClientAuthSANURI, metadata.TLSClientAuthSANURI},
		{consts.ClientMetadataTLSClientAuthSANIP, metadata.TLSClientAuthSANIP},
		{consts.ClientMetadataTLSClientAuthSANEmail, metadata.TLSClientAuthSANEmail},
	}

	var registered []string

	for _, subject := range subjects {
		if subject.value != "" {
			registered = append(registered, subject.name)
		}
	}

	var pki, selfSigned bool

	for _, method := range methods {
		switch method.value {
		case consts.ClientAuthMethodTLSClientAuth:
			pki = true
		case consts.ClientAuthMethodSelfSignedTLSClientAuth:
			selfSigned = true
		}
	}

	if pki && len(registered) != 1 {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' authentication method requires exactly one of the '%s', '%s', '%s', '%s', or '%s' values but %d were registered.", consts.ClientAuthMethodTLSClientAuth, consts.ClientMetadataTLSClientAuthSubjectDN, consts.ClientMetadataTLSClientAuthSANDNS, consts.ClientMetadataTLSClientAuthSANURI, consts.ClientMetadataTLSClientAuthSANIP, consts.ClientMetadataTLSClientAuthSANEmail, len(registered)))
	}

	// A subject value is only ever consulted for the 'tls_client_auth' method. Registering one without that method
	// is metadata that can have no effect, which is exactly what 'invalid_client_metadata' exists to report.
	if !pki && len(registered) != 0 {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value is only permitted when an endpoint authentication method is '%s'.", registered[0], consts.ClientAuthMethodTLSClientAuth))
	}

	if metadata.TLSClientAuthSANIP != "" && net.ParseIP(metadata.TLSClientAuthSANIP) == nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must be a valid IP address.", consts.ClientMetadataTLSClientAuthSANIP, metadata.TLSClientAuthSANIP))
	}

	if selfSigned && metadata.JSONWebKeys == nil && metadata.JSONWebKeysURI == "" {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' authentication method requires either the '%s' or '%s' value to be registered.", consts.ClientAuthMethodSelfSignedTLSClientAuth, consts.ClientMetadataJSONWebKeys, consts.ClientMetadataJSONWebKeysURI))
	}

	return nil
}

// validateRedirectURIs implements RFC 6749 Section 3.1.2: every redirect URI must parse, be absolute, and carry no
// fragment. It additionally enforces the OAuth 2.0 Security Best Current Practice scheme rules for the declared
// 'application_type': a 'web' client (the default when 'application_type' is absent) must use 'https' and must not
// target the loopback interface, while a 'native' client may use a non-'https' scheme only for a loopback redirect
// (127.0.0.1 or [::1]) or a private-use URI scheme of the reverse-DNS shape RFC 8252 Section 7.1 requires.
//
// OpenID Connect Dynamic Client Registration 1.0 Section 2 states that web clients "MUST NOT use localhost as the
// hostname", and in the same sentence defines the loopback URLs reserved for native clients as those using
// "localhost or the IP loopback literals 127.0.0.1 or [::1] as the hostname". The prohibition is therefore on the
// loopback interface, not on one spelling of it: a redirect to the resource owner's own machine is a host the web
// client does not control however it is written, so isLoopbackRedirect rejects the name and the literals alike.
//
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
// See: https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
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
				// A private-use URI scheme is permitted for native clients, but only in the reverse-DNS form RFC 8252
				// Section 7.1 requires.
				if !isPrivateUseURIScheme(parsed.Scheme) {
					return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHintf("The '%s' value '%s' must use a private-use URI scheme based on a domain name under the client's control, expressed in reverse order.", consts.ClientMetadataRedirectURIs, raw))
				}

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

		if isLoopbackRedirect(parsed.Hostname()) {
			return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHintf("The '%s' value '%s' must not target the loopback interface for the 'web' '%s'.", consts.ClientMetadataRedirectURIs, raw, consts.ClientMetadataApplicationType))
		}
	}

	return nil
}

// validateGrantTypesPermitted checks the registered 'grant_types' against the grant types the deployment permits a
// client to register for. RFC 7591 Section 2 permits the authorization server to reject requested metadata values
// with an error response, and every token endpoint authorization check in this library is a GetGrantTypes().Has
// call, so without this a registrant asserts its own authority.
//
// An empty policy permits any grant, which is the default; see GetRFC7591ClientRegistrationGrantTypes. An absent
// 'grant_types' is not checked either way: Section 2 makes that the authorization code grant, which
// validateGrantResponseTypeCoherence already applies.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-2
func validateGrantTypesPermitted(ctx context.Context, config LocalValidatorConfig, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	permitted := config.GetRFC7591ClientRegistrationGrantTypes(ctx)

	if len(permitted) == 0 {
		return nil
	}

	for _, grantType := range metadata.GrantTypes {
		if !slices.Contains(permitted, grantType) {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' is not permitted for registration.", consts.ClientMetadataGrantTypes, grantType))
		}
	}

	return nil
}

// validateURIs checks the client metadata URIs naming a location this authorization server requests itself:
// 'jwks_uri' and 'request_uris' are fetched, and 'backchannel_logout_uri' is issued a POST whose result reaches the
// caller. OpenID Connect Dynamic Client Registration 1.0 Section 2 and OpenID Connect Back-Channel Logout Section 2.2
// define each as an https URL. The scheme is what keeps a registrant from naming an internal service and reading the
// outcome through an error message or a delivery status.
//
// 'post_logout_redirect_uris' is a browser redirect target rather than something this server fetches, so only the
// absolute and fragment rules apply to it and a native client's private-use scheme stays registrable.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRegistration
func validateURIs(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if err = validateURI(consts.ClientMetadataJSONWebKeysURI, metadata.JSONWebKeysURI, true); err != nil {
		return err
	}

	if err = validateURI(consts.ClientMetadataBackChannelLogoutURI, metadata.BackChannelLogoutURI, true); err != nil {
		return err
	}

	if err = validateURIList(consts.ClientMetadataRequestURIs, metadata.RequestURIs, true); err != nil {
		return err
	}

	if err = validateURIList(consts.ClientMetadataPostLogoutRedirectURIs, metadata.PostLogoutRedirectURIs, false); err != nil {
		return err
	}

	return nil
}

// validateURIList applies validateURI to each member of a client metadata URI array. An empty member is rejected
// rather than skipped: omitting the parameter is how a client registers no value, so an empty string among the
// members is a malformed entry rather than an absent one.
func validateURIList(name string, values []string, secure bool) (err error) {
	for _, value := range values {
		if value == "" {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' values must not contain an empty value.", name))
		}

		if err = validateURI(name, value, secure); err != nil {
			return err
		}
	}

	return nil
}

// validateURI checks that value is an absolute URI with no fragment component, and when secure is set that it uses
// the 'https' scheme and carries a host. An empty value is not registered and is not checked; validateURIList rejects
// one appearing among the members of a URI array.
func validateURI(name, value string, secure bool) (err error) {
	if value == "" {
		return nil
	}

	var parsed *url.URL

	if parsed, err = url.Parse(value); err != nil || !parsed.IsAbs() {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must be an absolute URI.", name, value))
	}

	if parsed.Fragment != "" {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must not contain a fragment component.", name, value))
	}

	if secure {
		if parsed.Scheme != consts.SchemeHTTPS {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must use the 'https' scheme.", name, value))
		}

		// url.Parse reports 'https:', 'https:foo' and 'https:/path' as absolute, since a scheme alone satisfies that.
		// None names a host, so none is fetchable, and the scheme check above passes them.
		if parsed.Hostname() == "" {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must include a host component.", name, value))
		}
	}

	return nil
}

// isPrivateUseURIScheme reports whether scheme is a private-use URI scheme of the form RFC 8252 Section 7.1 requires
// of a native application: "apps MUST use a URI scheme based on a domain name under their control, expressed in
// reverse order", as recommended by RFC 7595 Section 3.8. It is therefore satisfied only by a domain-shaped, dotted
// scheme such as 'com.example.app'.
//
// The requirement is what makes a private-use scheme meaningfully the registrant's: a single-label scheme like
// 'myapp' is claimable by any other application on the device, and the shape check is also what keeps the browser
// pseudo-schemes ('javascript', 'data', 'file', ...) out of a client's registered redirect URIs, which the previous
// unconditional acceptance of every non-HTTP scheme did not.
//
// url.Parse has already lowercased the scheme and enforced RFC 3986's 'scheme' production, so only the domain shape
// is checked here: at least one dot, and every label non-empty, composed of unreserved DNS characters, and neither
// starting nor ending with a hyphen.
//
// See: https://datatracker.ietf.org/doc/html/rfc8252#section-7.1
// See: https://datatracker.ietf.org/doc/html/rfc7595#section-3.8
func isPrivateUseURIScheme(scheme string) bool {
	if !strings.Contains(scheme, ".") {
		return false
	}

	for _, label := range strings.Split(scheme, ".") {
		if len(label) == 0 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}

	return true
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

// isLoopbackRedirect reports whether host addresses the loopback interface, whether by the special-use 'localhost'
// name (RFC 6761 Section 6.3, which reserves 'localhost' and any name under '.localhost') or by any loopback IP
// address (127.0.0.0/8 or ::1).
//
// It is deliberately broader than isLoopbackHost. That function is an allow list: it gates the loopback redirect a
// native client may register, where RFC 8252 Section 7.3 names the two literals exactly and admitting no more than
// those is the conservative reading. This one is a deny list, where the conservative reading is the opposite: every
// host that reaches the resource owner's own machine must be caught, since anything missed is not a stricter rule
// but a way around the rule.
//
// See: https://datatracker.ietf.org/doc/html/rfc6761#section-6.3
func isLoopbackRedirect(host string) bool {
	// A trailing dot makes the name fully qualified and resolves identically.
	name := strings.ToLower(strings.TrimSuffix(host, "."))

	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}

	return false
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
//
// RFC 7591 Section 2 defaults an absent 'grant_types' to 'authorization_code' and an absent 'response_types' to
// 'code', which is exactly what oauth2.DefaultClient's GetGrantTypes and GetResponseTypes return at request time.
// The same defaults are applied here, otherwise omitting 'grant_types' is enough to register a client the rest of
// the provider then treats as an authorization code client while skipping the redirect URI requirement below. The
// defaults are evaluated only and never written back: the registered client and the registration response continue
// to carry exactly what was submitted.
//
// The 'response_types' default is applied only when 'grant_types' is absent as well, i.e. only as the other half of
// the same default pair. A client that declares 'grant_types' without 'response_types' - a 'client_credentials'
// client being the common case - has declared it will not use a redirection flow, and synthesizing a 'code'
// response type for it would reject the registration over a response type it never asked for.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-2
func validateGrantResponseTypeCoherence(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	grantTypes, responseTypes := metadata.GrantTypes, metadata.ResponseTypes

	if len(grantTypes) == 0 {
		grantTypes = []string{consts.GrantTypeAuthorizationCode}

		if len(responseTypes) == 0 {
			responseTypes = []string{consts.ResponseTypeAuthorizationCodeFlow}
		}
	}

	var responseTypeTokens []string

	for _, responseType := range responseTypes {
		responseTypeTokens = append(responseTypeTokens, strings.Fields(responseType)...)
	}

	hasGrantType := func(grantType string) bool {
		return slices.Contains(grantTypes, grantType)
	}

	if slices.Contains(responseTypeTokens, consts.ResponseTypeAuthorizationCodeFlow) && !hasGrantType(consts.GrantTypeAuthorizationCode) {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' response type requires the '%s' grant type to be present in '%s'.", consts.ResponseTypeAuthorizationCodeFlow, consts.GrantTypeAuthorizationCode, consts.ClientMetadataGrantTypes))
	}

	if (slices.Contains(responseTypeTokens, consts.ResponseTypeImplicitFlowToken) || slices.Contains(responseTypeTokens, consts.ResponseTypeImplicitFlowIDToken)) && !hasGrantType(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("A '%s' or '%s' response type requires the '%s' grant type to be present in '%s'.", consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken, consts.GrantTypeImplicit, consts.ClientMetadataGrantTypes))
	}

	if hasGrantType(consts.GrantTypeAuthorizationCode) && len(metadata.RedirectURIs) == 0 {
		// Naming the default explicitly: a client that never sent 'grant_types' has no way to connect the rejection
		// to a grant type it did not ask for.
		if len(metadata.GrantTypes) == 0 {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' grant type, which applies by default when '%s' is omitted, requires at least one '%s' value.", consts.GrantTypeAuthorizationCode, consts.ClientMetadataGrantTypes, consts.ClientMetadataRedirectURIs))
		}

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

// validateAlgorithms checks the declared signing and encryption algorithm metadata.
func validateAlgorithms(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	for _, algorithm := range []signingOrEncryptionAlgorithm{
		{consts.ClientMetadataIDTokenSignedResponseAlg, metadata.IDTokenSignedResponseAlg},
		{consts.ClientMetadataTokenEndpointAuthAlg, metadata.TokenEndpointAuthSigningAlg},
		{consts.ClientMetadataIntrospectionEndpointAuthAlg, metadata.IntrospectionEndpointAuthSigningAlg},
		{consts.ClientMetadataRevocationEndpointAuthAlg, metadata.RevocationEndpointAuthSigningAlg},
	} {
		if algorithm.value == consts.JSONWebTokenAlgNone {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value must not be '%s'.", algorithm.name, consts.JSONWebTokenAlgNone))
		}
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
		{consts.ClientMetadataIntrospectionEndpointAuthAlg, metadata.IntrospectionEndpointAuthSigningAlg},
		{consts.ClientMetadataRevocationEndpointAuthAlg, metadata.RevocationEndpointAuthSigningAlg},
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

var (
	_ oauth2.ClientRegistrationValidator = (*LocalValidator)(nil)
)
