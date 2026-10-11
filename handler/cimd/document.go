// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package cimd resolves OAuth Client ID Metadata Documents.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02
package cimd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
	memberJSONWebKeys           = "jwks"
	memberSuffixAlgorithm       = "_alg"
)

var (
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

	if err = validateURIs(metadata); err != nil {
		return nil, err
	}

	applyDefaults(metadata)

	return metadata, nil
}

func buildKnownMembers() (members []string) {
	members = []string{memberClientID, memberClientSecret, memberClientSecretExpiresAt}

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

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-4
	if err = json.Unmarshal(raw[memberClientID], &clientID); err != nil || clientID != id {
		return errDocument("The Client ID Metadata Document 'client_id' does not match the URL %q it was fetched from.", id)
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-4.1
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

	return nil
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

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-4.1
	for _, method := range methods {
		if slices.ContainsFunc(secretAuthMethods, func(m string) bool { return strings.EqualFold(m, method.value) }) {
			return errDocument("The Client ID Metadata Document member %q has the value %q which requires a client secret.", method.name, method.value)
		}
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

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.6
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

func errDocument(debug string, args ...any) (err error) {
	return errorsx.WithStack(oauth2.ErrInvalidClient.WithHint("The Client ID Metadata Document could not be used.").WithDebugf(debug, args...))
}
