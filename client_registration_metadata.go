// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

// ClientRegistrationMetadata is the client metadata wire format used by OAuth 2.0 Dynamic Client Registration
// Protocol (RFC 7591), OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592), and OpenID Connect
// Dynamic Client Registration 1.0. It is the union of every client metadata parameter defined by those
// specifications together with the values this codebase already models on its own client interfaces (see
// client.go). Any parameter not recognized by one of the typed fields below is preserved in Extra so it survives a
// decode/encode round trip.
type ClientRegistrationMetadata struct {
	// RFC 7591 Section 2 (OAuth 2.0 Dynamic Client Registration Protocol) client metadata.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc7591#section-2

	RedirectURIs            []string            `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string            `json:"grant_types,omitempty"`
	ResponseTypes           []string            `json:"response_types,omitempty"`
	ClientName              string              `json:"client_name,omitempty"`
	ClientURI               string              `json:"client_uri,omitempty"`
	LogoURI                 string              `json:"logo_uri,omitempty"`
	Scope                   string              `json:"scope,omitempty"`
	Contacts                []string            `json:"contacts,omitempty"`
	TOSURI                  string              `json:"tos_uri,omitempty"`
	PolicyURI               string              `json:"policy_uri,omitempty"`
	JSONWebKeysURI          string              `json:"jwks_uri,omitempty"`
	JSONWebKeys             *jose.JSONWebKeySet `json:"jwks,omitempty"`
	SoftwareID              string              `json:"software_id,omitempty"`
	SoftwareStatement       string              `json:"software_statement,omitempty"`
	SoftwareVersion         string              `json:"software_version,omitempty"`

	// OpenID Connect Dynamic Client Registration 1.0 Section 2 client metadata.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

	ApplicationType              string   `json:"application_type,omitempty"`
	SectorIdentifierURI          string   `json:"sector_identifier_uri,omitempty"`
	SubjectType                  string   `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg     string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg  string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string   `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoSignedResponseAlg    string   `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg string   `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc string   `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      string   `json:"request_object_signing_alg,omitempty"`
	RequestObjectEncryptionAlg   string   `json:"request_object_encryption_alg,omitempty"`
	RequestObjectEncryptionEnc   string   `json:"request_object_encryption_enc,omitempty"`
	TokenEndpointAuthSigningAlg  string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	DefaultMaxAge                *int64   `json:"default_max_age,omitempty"`
	RequireAuthTime              bool     `json:"require_auth_time,omitempty"`
	DefaultACRValues             []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI             string   `json:"initiate_login_uri,omitempty"`
	RequestURIs                  []string `json:"request_uris,omitempty"`

	// RFC 9101 Section 10.5 (JWT-Secured Authorization Request) client metadata.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9101#section-10.5

	RequireSignedRequestObject bool `json:"require_signed_request_object,omitempty"`

	// OpenID Connect RP-Initiated Logout 1.0 and OpenID Connect Back-Channel Logout 1.0 client metadata.
	//
	// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata
	// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#ClientMetadata

	PostLogoutRedirectURIs           []string `json:"post_logout_redirect_uris,omitempty"`
	BackChannelLogoutURI             string   `json:"backchannel_logout_uri,omitempty"`
	BackChannelLogoutSessionRequired bool     `json:"backchannel_logout_session_required,omitempty"`

	// RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens) client metadata.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8705#section-2.1.2
	// See: https://datatracker.ietf.org/doc/html/rfc8705#section-3.4

	TLSClientAuthSubjectDN                string `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANDNS                   string `json:"tls_client_auth_san_dns,omitempty"`
	TLSClientAuthSANURI                   string `json:"tls_client_auth_san_uri,omitempty"`
	TLSClientAuthSANIP                    string `json:"tls_client_auth_san_ip,omitempty"`
	TLSClientAuthSANEmail                 string `json:"tls_client_auth_san_email,omitempty"`
	TLSClientCertificateBoundAccessTokens bool   `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// Values this codebase already models on its own client interfaces (see client.go).

	IDTokenSignedResponseKeyID          string   `json:"id_token_signed_response_kid,omitempty"`
	IDTokenEncryptedResponseKeyID       string   `json:"id_token_encrypted_response_kid,omitempty"`
	UserinfoSignedResponseKeyID         string   `json:"userinfo_signed_response_kid,omitempty"`
	UserinfoEncryptedResponseKeyID      string   `json:"userinfo_encrypted_response_kid,omitempty"`
	RequestObjectSigningKeyID           string   `json:"request_object_signing_kid,omitempty"`
	RequestObjectEncryptionKeyID        string   `json:"request_object_encryption_kid,omitempty"`
	AuthorizationSignedResponseKeyID    string   `json:"authorization_signed_response_kid,omitempty"`
	AuthorizationSignedResponseAlg      string   `json:"authorization_signed_response_alg,omitempty"`
	AuthorizationEncryptedResponseKeyID string   `json:"authorization_encrypted_response_kid,omitempty"`
	AuthorizationEncryptedResponseAlg   string   `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc   string   `json:"authorization_encrypted_response_enc,omitempty"`
	IntrospectionSignedResponseKeyID    string   `json:"introspection_signed_response_kid,omitempty"`
	IntrospectionSignedResponseAlg      string   `json:"introspection_signed_response_alg,omitempty"`
	IntrospectionEncryptedResponseKeyID string   `json:"introspection_encrypted_response_kid,omitempty"`
	IntrospectionEncryptedResponseAlg   string   `json:"introspection_encrypted_response_alg,omitempty"`
	IntrospectionEncryptedResponseEnc   string   `json:"introspection_encrypted_response_enc,omitempty"`
	AccessTokenSignedResponseKeyID      string   `json:"access_token_signed_response_kid,omitempty"`
	AccessTokenSignedResponseAlg        string   `json:"access_token_signed_response_alg,omitempty"`
	AccessTokenEncryptedResponseKeyID   string   `json:"access_token_encrypted_response_kid,omitempty"`
	AccessTokenEncryptedResponseAlg     string   `json:"access_token_encrypted_response_alg,omitempty"`
	AccessTokenEncryptedResponseEnc     string   `json:"access_token_encrypted_response_enc,omitempty"`
	IntrospectionEndpointAuthMethod     string   `json:"introspection_endpoint_auth_method,omitempty"`
	IntrospectionEndpointAuthSigningAlg string   `json:"introspection_endpoint_auth_signing_alg,omitempty"`
	RevocationEndpointAuthMethod        string   `json:"revocation_endpoint_auth_method,omitempty"`
	RevocationEndpointAuthSigningAlg    string   `json:"revocation_endpoint_auth_signing_alg,omitempty"`
	RequirePushedAuthorizationRequests  bool     `json:"require_pushed_authorization_requests,omitempty"`
	DPoPBoundAccessTokens               bool     `json:"dpop_bound_access_tokens,omitempty"`
	ResponseModes                       []string `json:"response_modes,omitempty"`
	Audience                            []string `json:"audience,omitempty"`

	// Extra holds every unregistered client metadata parameter so it survives a registration round trip.
	Extra map[string]any `json:"-"`
}

// GetScopes returns the 'scope' value as space-delimited Arguments.
func (m *ClientRegistrationMetadata) GetScopes() (scopes Arguments) {
	if len(m.Scope) == 0 {
		return nil
	}

	return Arguments(strings.Fields(m.Scope))
}

type clientRegistrationMetadataAlias ClientRegistrationMetadata

// UnmarshalJSON decodes the registered client metadata parameters into their typed fields and preserves every
// unregistered parameter in Extra so it survives a registration round trip.
func (m *ClientRegistrationMetadata) UnmarshalJSON(data []byte) (err error) {
	alias := &clientRegistrationMetadataAlias{}

	if err = json.Unmarshal(data, alias); err != nil {
		return err
	}

	*m = ClientRegistrationMetadata(*alias)

	all := map[string]any{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	if err = decoder.Decode(&all); err != nil {
		return err
	}

	for _, name := range clientRegistrationMetadataFieldNames() {
		delete(all, name)
	}

	if len(all) != 0 {
		m.Extra = all
	} else {
		m.Extra = nil
	}

	return nil
}

// MarshalJSON encodes the registered parameters and merges the unregistered parameters held in Extra. A value in
// Extra never overwrites a registered parameter.
func (m *ClientRegistrationMetadata) MarshalJSON() (data []byte, err error) {
	if data, err = json.Marshal((*clientRegistrationMetadataAlias)(m)); err != nil {
		return nil, err
	}

	if len(m.Extra) == 0 {
		return data, nil
	}

	merged := map[string]any{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	if err = decoder.Decode(&merged); err != nil {
		return nil, err
	}

	for key, value := range m.Extra {
		if _, ok := merged[key]; ok {
			continue
		}

		merged[key] = value
	}

	return json.Marshal(merged)
}

var (
	clientRegistrationMetadataNames     []string
	clientRegistrationMetadataNamesOnce sync.Once
)

// clientRegistrationMetadataFieldNames returns the JSON names of every registered parameter, derived from the struct
// tags so a newly added field cannot be silently duplicated into Extra.
func clientRegistrationMetadataFieldNames() []string {
	clientRegistrationMetadataNamesOnce.Do(func() {
		t := reflect.TypeOf(ClientRegistrationMetadata{})

		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")

			if name == "" || name == "-" {
				continue
			}

			clientRegistrationMetadataNames = append(clientRegistrationMetadataNames, name)
		}
	})

	return clientRegistrationMetadataNames
}
