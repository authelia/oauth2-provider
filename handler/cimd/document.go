// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package cimd resolves OAuth Client ID Metadata Documents.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03
package cimd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	memberClientID              = "client_id"
	memberClientSecret          = "client_secret"
	memberClientSecretExpiresAt = "client_secret_expires_at"
	memberAuthMethodsSupported  = "token_endpoint_auth_methods_supported"
	memberJSONWebKeys           = "jwks"
	memberSuffixAlgorithm       = "_alg"
)

var (
	errClientIDMismatch = errors.New("the client_id does not match the client identifier")

	knownMembers = buildKnownMembers()

	secretAuthMethods = []string{
		consts.ClientAuthMethodClientSecretBasic,
		consts.ClientAuthMethodClientSecretPost,
		consts.ClientAuthMethodClientSecretJWT,
	}

	secretKeyWrapAlgorithms = []string{"dir", "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW"}

	privateJWKParameters = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
)

func parseDocument(id string, body []byte) (metadata *oauth2.ClientRegistrationMetadata, err error) {
	var raw map[string]json.RawMessage

	decoder := json.NewDecoder(bytes.NewReader(body))

	if err = decoder.Decode(&raw); err != nil {
		return nil, errDocument("The Client ID Metadata Document is not a JSON object: %v.", err)
	}

	if raw == nil {
		return nil, errDocument("The Client ID Metadata Document is not a JSON object.")
	}

	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errDocument("The Client ID Metadata Document is followed by additional data.")
	}

	if err = validateRawDocument(id, raw); err != nil {
		return nil, err
	}

	metadata = &oauth2.ClientRegistrationMetadata{}

	if err = json.Unmarshal(body, metadata); err != nil {
		return nil, errDocument("The Client ID Metadata Document has a member of the wrong type: %v.", err)
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4.1
	if metadata.JSONWebKeys != nil && metadata.JSONWebKeysURI != "" {
		return nil, errDocument("The Client ID Metadata Document contains both the %q and %q members.", memberJSONWebKeys, consts.ClientMetadataJSONWebKeysURI)
	}

	if metadata.JSONWebKeys != nil {
		for i := range metadata.JSONWebKeys.Keys {
			if !metadata.JSONWebKeys.Keys[i].IsPublic() {
				return nil, errDocument("The Client ID Metadata Document 'jwks' member contains a key which is not public at index %d.", i)
			}
		}
	}

	if err = validateAuthMethods(metadata); err != nil {
		return nil, err
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-8
	if slices.Contains(metadata.AuthorizationGrantProfilesSupported, consts.GrantProfileIDJAG) && !hasIDJAGGrantTypes(metadata.GrantTypes) {
		return nil, errDocument("The Client ID Metadata Document %q member has the value %q which requires the %q and %q values in the %q member.", consts.ClientMetadataAuthorizationGrantProfilesSupported, consts.GrantProfileIDJAG, consts.GrantTypeOAuthTokenExchange, consts.GrantTypeOAuthJWTBearer, consts.ClientMetadataGrantTypes)
	}

	if err = validateURIs(metadata); err != nil {
		return nil, err
	}

	if err = validatePostLogoutRedirectURIs(metadata); err != nil {
		return nil, err
	}

	applyDefaults(metadata)

	return metadata, nil
}

func buildKnownMembers() (members []string) {
	members = []string{memberClientID, memberClientSecret, memberClientSecretExpiresAt, memberAuthMethodsSupported}

	t := reflect.TypeOf(oauth2.ClientRegistrationMetadata{})

	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")

		if name == "" || name == "-" {
			continue
		}

		members = append(members, name)
	}

	return members
}

func validateRawDocument(id string, raw map[string]json.RawMessage) (err error) {
	var clientID string

	// Go decodes member names case-insensitively, so a case variant of a known name is rejected.
	for member := range raw {
		for _, known := range knownMembers {
			if member != known && strings.EqualFold(member, known) {
				return errDocument("The Client ID Metadata Document member %q is a case variant of the member %q.", member, known)
			}
		}
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4
	if err = json.Unmarshal(raw[memberClientID], &clientID); err != nil || clientID != id {
		return errorsx.WithStack(oauth2.ErrInvalidClient.WithHint("The Client ID Metadata Document could not be used.").WithWrap(errClientIDMismatch).WithDebugf("The Client ID Metadata Document 'client_id' does not match the URL %q it was fetched from.", id))
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4.1
	for _, member := range []string{memberClientSecret, memberClientSecretExpiresAt} {
		if _, ok := raw[member]; ok {
			return errDocument("The Client ID Metadata Document contains the %q member which is not permitted.", member)
		}
	}

	for member, value := range raw {
		if len(member) < len(memberSuffixAlgorithm) || !strings.EqualFold(member[len(member)-len(memberSuffixAlgorithm):], memberSuffixAlgorithm) {
			continue
		}

		var alg string

		if err = json.Unmarshal(value, &alg); err != nil {
			continue
		}

		if isSecretAlgorithm(alg) {
			return errDocument("The Client ID Metadata Document member %q has the value %q which requires a client secret.", member, alg)
		}
	}

	if value, ok := raw[memberJSONWebKeys]; ok {
		if err = validateRawJSONWebKeys(value); err != nil {
			return err
		}
	}

	if value, ok := raw[memberAuthMethodsSupported]; ok {
		if err = validateRawAuthMethodsSupported(value, raw[consts.ClientMetadataTokenEndpointAuthMethod]); err != nil {
			return err
		}
	}

	return nil
}

// validateRawAuthMethodsSupported requires 'token_endpoint_auth_methods_supported' to be an array of strings with no
// method based on a shared symmetric secret, which includes 'token_endpoint_auth_method' when both are present.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-5
func validateRawAuthMethodsSupported(value, single json.RawMessage) (err error) {
	var methods []string

	if err = json.Unmarshal(value, &methods); err != nil || methods == nil {
		return errDocument("The Client ID Metadata Document %q member is not an array of strings.", memberAuthMethodsSupported)
	}

	for _, method := range methods {
		if slices.ContainsFunc(secretAuthMethods, func(m string) bool { return strings.EqualFold(m, method) }) {
			return errDocument("The Client ID Metadata Document member %q has the value %q which requires a client secret.", memberAuthMethodsSupported, method)
		}
	}

	if single == nil {
		return nil
	}

	var method string

	if err = json.Unmarshal(single, &method); err == nil && !slices.Contains(methods, method) {
		return errDocument("The Client ID Metadata Document member %q has the value %q which is not included in the %q member.", consts.ClientMetadataTokenEndpointAuthMethod, method, memberAuthMethodsSupported)
	}

	return nil
}

func authMethodsSupported(metadata *oauth2.ClientRegistrationMetadata) (methods []string, ok bool) {
	var value any

	if value, ok = metadata.Extra[memberAuthMethodsSupported]; !ok {
		return nil, false
	}

	switch values := value.(type) {
	case []string:
		return values, true
	case []any:
		for _, v := range values {
			if method, isString := v.(string); isString {
				methods = append(methods, method)
			}
		}

		return methods, true
	default:
		return nil, true
	}
}

func validateRawJSONWebKeys(value json.RawMessage) (err error) {
	var set struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}

	if err = json.Unmarshal(value, &set); err != nil {
		return errDocument("The Client ID Metadata Document 'jwks' member is not a JSON Web Key Set: %v.", err)
	}

	for i, key := range set.Keys {
		for name, value := range key {
			if strings.EqualFold(name, "kty") {
				var kty string

				_ = json.Unmarshal(value, &kty)

				if strings.EqualFold(kty, "oct") {
					return errDocument("The Client ID Metadata Document 'jwks' member contains a symmetric key at index %d.", i)
				}
			}

			for _, parameter := range privateJWKParameters {
				if strings.EqualFold(name, parameter) {
					return errDocument("The Client ID Metadata Document 'jwks' member contains private key material at index %d.", i)
				}
			}
		}
	}

	return nil
}

func isSecretAlgorithm(alg string) (secret bool) {
	upper := strings.ToUpper(alg)

	return strings.HasPrefix(upper, "HS") || strings.HasPrefix(upper, "PBES2-") || slices.ContainsFunc(secretKeyWrapAlgorithms, func(w string) bool { return strings.EqualFold(w, alg) })
}

func validateAuthMethods(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	methods := []struct {
		name  string
		value string
	}{
		{consts.ClientMetadataTokenEndpointAuthMethod, metadata.TokenEndpointAuthMethod},
		{consts.ClientMetadataIntrospectionEndpointAuthMethod, metadata.IntrospectionEndpointAuthMethod},
		{consts.ClientMetadataRevocationEndpointAuthMethod, metadata.RevocationEndpointAuthMethod},
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4.1
	for _, method := range methods {
		if slices.ContainsFunc(secretAuthMethods, func(m string) bool { return strings.EqualFold(m, method.value) }) {
			return errDocument("The Client ID Metadata Document member %q has the value %q which requires a client secret.", method.name, method.value)
		}
	}

	return nil
}

// validateAuthKeys requires the 'jwks' or 'jwks_uri' member when the token endpoint authentication method is
// 'private_key_jwt'.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-5
func validateAuthKeys(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata.TokenEndpointAuthMethod == consts.ClientAuthMethodPrivateKeyJWT && metadata.JSONWebKeys == nil && metadata.JSONWebKeysURI == "" {
		return errDocument("The Client ID Metadata Document %q member has the value %q which requires the %q or %q member.", consts.ClientMetadataTokenEndpointAuthMethod, consts.ClientAuthMethodPrivateKeyJWT, memberJSONWebKeys, consts.ClientMetadataJSONWebKeysURI)
	}

	return nil
}

func validateURIs(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	uris := []struct {
		name   string
		values []string
	}{
		{"client_uri", []string{metadata.ClientURI}},
		{"logo_uri", []string{metadata.LogoURI}},
		{"tos_uri", []string{metadata.TOSURI}},
		{"policy_uri", []string{metadata.PolicyURI}},
		{"jwks_uri", []string{metadata.JSONWebKeysURI}},
		{"sector_identifier_uri", []string{metadata.SectorIdentifierURI}},
		{"initiate_login_uri", []string{metadata.InitiateLoginURI}},
		{"backchannel_logout_uri", []string{metadata.BackChannelLogoutURI}},
		{"request_uris", metadata.RequestURIs},
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.7
	for _, uri := range uris {
		for _, value := range uri.values {
			if value == "" {
				continue
			}

			parsed, perr := url.Parse(value)

			if perr != nil || parsed.Scheme != consts.SchemeHTTPS || parsed.Hostname() == "" {
				return errDocument("The Client ID Metadata Document member %q has the value %q which is not an 'https' URL.", uri.name, value)
			}
		}
	}

	return nil
}

// validatePostLogoutRedirectURIs requires each 'post_logout_redirect_uris' value to be an absolute URI without a
// fragment that uses the 'https' scheme with a host, the 'http' scheme with a loopback IP literal, or a private-use URI
// scheme in reverse domain name form.
//
// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata
// See: https://datatracker.ietf.org/doc/html/rfc8252#section-7
func validatePostLogoutRedirectURIs(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	for _, value := range metadata.PostLogoutRedirectURIs {
		parsed, perr := url.Parse(value)

		if perr != nil || !parsed.IsAbs() || parsed.Fragment != "" || !isPermittedPostLogoutRedirectURI(parsed) {
			return errDocument("The Client ID Metadata Document member %q has the value %q which is not a permitted redirect URI.", consts.ClientMetadataPostLogoutRedirectURIs, value)
		}
	}

	return nil
}

func isPermittedPostLogoutRedirectURI(uri *url.URL) bool {
	switch uri.Scheme {
	case consts.SchemeHTTPS:
		return uri.Hostname() != ""
	case consts.SchemeHTTP:
		ip := net.ParseIP(uri.Hostname())

		return ip != nil && ip.IsLoopback()
	default:
		return isPrivateUseURIScheme(uri.Scheme)
	}
}

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

func applyDefaults(metadata *oauth2.ClientRegistrationMetadata) {
	if metadata.TokenEndpointAuthMethod == "" {
		metadata.TokenEndpointAuthMethod = consts.ClientAuthMethodNone
	}

	// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
	if len(metadata.GrantTypes) == 0 {
		metadata.GrantTypes = []string{consts.GrantTypeAuthorizationCode}
	}

	if len(metadata.ResponseTypes) == 0 && slices.Contains(metadata.GrantTypes, consts.GrantTypeAuthorizationCode) {
		metadata.ResponseTypes = []string{consts.ResponseTypeAuthorizationCodeFlow}
	}
}

func hasIDJAGGrantTypes(grantTypes []string) (has bool) {
	return slices.Contains(grantTypes, consts.GrantTypeOAuthTokenExchange) && slices.Contains(grantTypes, consts.GrantTypeOAuthJWTBearer)
}

func errDocument(debug string, args ...any) (err error) {
	return errorsx.WithStack(oauth2.ErrInvalidClient.WithHint("The Client ID Metadata Document could not be used.").WithDebugf(debug, args...))
}
