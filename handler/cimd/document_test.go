// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

const testClientID = "https://client.example.com/metadata.json"

func TestParseDocumentAccepts(t *testing.T) {
	t.Run("ShouldApplyDefaultsToMinimalDocument", func(t *testing.T) {
		metadata, err := parseDocument(testClientID, document(`"redirect_uris":["https://client.example.com/cb"]`))

		require.NoError(t, err)

		assert.Equal(t, "none", metadata.TokenEndpointAuthMethod)
		assert.Equal(t, []string{"authorization_code"}, metadata.GrantTypes)
		assert.Equal(t, []string{"code"}, metadata.ResponseTypes)
		assert.Equal(t, []string{"https://client.example.com/cb"}, metadata.RedirectURIs)
		assert.Equal(t, testClientID, metadata.Extra["client_id"])
	})

	t.Run("ShouldNotDefaultResponseTypesWithoutAuthorizationCodeGrant", func(t *testing.T) {
		metadata, err := parseDocument(testClientID, document(`"grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://client.example.com/jwks.json"`))

		require.NoError(t, err)

		assert.Equal(t, "private_key_jwt", metadata.TokenEndpointAuthMethod)
		assert.Equal(t, []string{"client_credentials"}, metadata.GrantTypes)
		assert.Empty(t, metadata.ResponseTypes)
	})

	t.Run("ShouldAcceptPublicJWKS", func(t *testing.T) {
		_, err := parseDocument(testClientID, document(`"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`))

		require.NoError(t, err)
	})

	t.Run("ShouldAcceptAsymmetricKeyWrap", func(t *testing.T) {
		_, err := parseDocument(testClientID, document(`"id_token_encrypted_response_alg":"ECDH-ES+A256KW","id_token_signed_response_alg":"ES256"`))

		require.NoError(t, err)
	})

	t.Run("ShouldAcceptLocalizedMemberWithUppercaseLanguageTag", func(t *testing.T) {
		metadata, err := parseDocument(testClientID, document(`"client_name#ja-Jpan-JP":"クライアント名"`))

		require.NoError(t, err)

		assert.Contains(t, metadata.Extra, "client_name#ja-Jpan-JP")
	})

	t.Run("ShouldAcceptNativeRedirectScheme", func(t *testing.T) {
		_, err := parseDocument(testClientID, document(`"redirect_uris":["com.example.app:/cb","http://127.0.0.1/cb"],"post_logout_redirect_uris":["com.example.app:/out"]`))

		require.NoError(t, err)
	})
}

func TestParseDocumentRejects(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"ShouldRejectEmptyBody", ``},
		{"ShouldRejectInvalidJSON", `{"client_id":`},
		{"ShouldRejectNull", `null`},
		{"ShouldRejectArray", `[{"client_id":"` + testClientID + `"}]`},
		{"ShouldRejectString", `"` + testClientID + `"`},
		{"ShouldRejectTrailingData", string(document(`"client_name":"a"`)) + `{}`},
		{"ShouldRejectMissingClientID", `{"client_name":"a"}`},
		{"ShouldRejectNullClientID", `{"client_id":null}`},
		{"ShouldRejectNumericClientID", `{"client_id":1}`},
		{"ShouldRejectMismatchedClientID", `{"client_id":"https://client.example.com/other.json"}`},
		{"ShouldRejectClientIDWithDefaultPort", `{"client_id":"https://client.example.com:443/metadata.json"}`},
		{"ShouldRejectClientIDWithDifferentCase", `{"client_id":"https://CLIENT.example.com/metadata.json"}`},
		{"ShouldRejectClientSecret", string(document(`"client_secret":"s"`))},
		{"ShouldRejectClientSecretExpiresAt", string(document(`"client_secret_expires_at":0`))},
		{"ShouldRejectClientSecretBasic", string(document(`"token_endpoint_auth_method":"client_secret_basic"`))},
		{"ShouldRejectClientSecretPost", string(document(`"token_endpoint_auth_method":"client_secret_post"`))},
		{"ShouldRejectClientSecretJWT", string(document(`"token_endpoint_auth_method":"client_secret_jwt"`))},
		{"ShouldRejectIntrospectionClientSecretBasic", string(document(`"introspection_endpoint_auth_method":"client_secret_basic"`))},
		{"ShouldRejectRevocationClientSecretPost", string(document(`"revocation_endpoint_auth_method":"client_secret_post"`))},
		{"ShouldRejectHMACSigningAlg", string(document(`"id_token_signed_response_alg":"HS256"`))},
		{"ShouldRejectHMACRequestObjectAlg", string(document(`"request_object_signing_alg":"HS512"`))},
		{"ShouldRejectDirectEncryptionAlg", string(document(`"id_token_encrypted_response_alg":"dir"`))},
		{"ShouldRejectSymmetricKeyWrap", string(document(`"userinfo_encrypted_response_alg":"A256KW"`))},
		{"ShouldRejectSymmetricGCMKeyWrap", string(document(`"userinfo_encrypted_response_alg":"A128GCMKW"`))},
		{"ShouldRejectPasswordBasedAlg", string(document(`"request_object_encryption_alg":"PBES2-HS256+A128KW"`))},
		{"ShouldRejectUnregisteredSecretAlg", string(document(`"example_signed_response_alg":"HS256"`))},
		{"ShouldRejectSymmetricJWK", string(document(`"jwks":{"keys":[{"kty":"oct","k":"AAAA"}]}`))},
		{"ShouldRejectPrivateECJWK", string(document(`"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}]}`))},
		{"ShouldRejectPrivateRSAParameter", string(document(`"jwks":{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","p":"AQAB"}]}`))},
		{"ShouldRejectMalformedJWKS", string(document(`"jwks":"keys"`))},
		{"ShouldRejectHTTPJWKSURI", string(document(`"jwks_uri":"http://client.example.com/jwks.json"`))},
		{"ShouldRejectJavascriptLogoURI", string(document(`"logo_uri":"javascript:alert(1)"`))},
		{"ShouldRejectHTTPClientURI", string(document(`"client_uri":"http://client.example.com"`))},
		{"ShouldRejectHTTPPolicyURI", string(document(`"policy_uri":"http://client.example.com/policy"`))},
		{"ShouldRejectHTTPTOSURI", string(document(`"tos_uri":"http://client.example.com/tos"`))},
		{"ShouldRejectHTTPSectorIdentifierURI", string(document(`"sector_identifier_uri":"http://client.example.com/sector.json"`))},
		{"ShouldRejectHTTPInitiateLoginURI", string(document(`"initiate_login_uri":"http://client.example.com/login"`))},
		{"ShouldRejectHTTPBackChannelLogoutURI", string(document(`"backchannel_logout_uri":"http://client.example.com/logout"`))},
		{"ShouldRejectHTTPRequestURI", string(document(`"request_uris":["https://client.example.com/a","http://client.example.com/b"]`))},
		{"ShouldRejectHostlessURI", string(document(`"logo_uri":"https:///logo.png"`))},
		{"ShouldRejectUppercaseAlgMember", string(document(`"ID_TOKEN_SIGNED_RESPONSE_ALG":"HS256"`))},
		{"ShouldRejectMixedCaseEncryptionAlgMember", string(document(`"Request_Object_Encryption_Alg":"dir"`))},
		{"ShouldRejectUnregisteredUppercaseAlgSuffix", string(document(`"example_signed_response_ALG":"HS256"`))},
		{"ShouldRejectLowercaseHMACValue", string(document(`"id_token_signed_response_alg":"hs256"`))},
		{"ShouldRejectMixedCaseSecretAuthMethod", string(document(`"token_endpoint_auth_method":"Client_Secret_Basic"`))},
		{"ShouldRejectUppercaseJWKSMemberWithSymmetricKey", string(document(`"JWKS":{"keys":[{"kty":"oct","k":"AAAA"}]}`))},
		{"ShouldRejectUppercaseJWKParameterNames", string(document(`"jwks":{"keys":[{"KTY":"oct","K":"AAAA"}]}`))},
		{"ShouldRejectUppercasePrivateECParameter", string(document(`"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","D":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}]}`))},
		{"ShouldRejectMixedCaseClientSecret", string(document(`"Client_Secret":"s"`))},
		{"ShouldRejectUppercaseClientSecretExpiresAt", string(document(`"CLIENT_SECRET_EXPIRES_AT":0`))},
		{"ShouldRejectMixedCaseRedirectURIs", string(document(`"Redirect_URIs":["https://client.example.com/cb"]`))},
		{"ShouldRejectMixedCaseClientIDMember", `{"Client_ID":"` + testClientID + `"}`},
		{"ShouldRejectLongSFoldedMemberName", string(document(`"jwkſ":{"keys":[]}`))},
		{"ShouldRejectWrongTypedMember", string(document(`"redirect_uris":"https://client.example.com/cb"`))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := parseDocument(testClientID, []byte(tc.body))

			require.ErrorIs(t, err, oauth2.ErrInvalidClient)
			assert.Nil(t, metadata)
		})
	}
}

func TestParseDocumentErrorsDoNotLeakIntoTheHint(t *testing.T) {
	_, err := parseDocument(testClientID, document(`"client_secret":"super-secret-value"`))

	require.Error(t, err)

	rfc := oauth2.ErrorToRFC6749Error(err)

	assert.False(t, strings.Contains(rfc.HintField, "super-secret-value"))
	assert.False(t, strings.Contains(rfc.DebugField, "super-secret-value"))
}

func document(members string) []byte {
	if members == "" {
		return []byte(fmt.Sprintf(`{"client_id":%q}`, testClientID))
	}

	return []byte(fmt.Sprintf(`{"client_id":%q,%s}`, testClientID, members))
}
