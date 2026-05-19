// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testClient struct {
	id                  string
	secret              []byte
	secretNotPlainText  bool
	secretNotDefined    bool
	kid, alg            string
	encKID, encAlg, enc string
	csigned             bool
	jwks                *jose.JSONWebKeySet
	jwksURI             string
}

func (r *testClient) GetID() string {
	return r.id
}

func (r *testClient) GetClientSecretPlainText() (secret []byte, ok bool, err error) {
	if r.secretNotDefined {
		return nil, false, nil
	}

	if r.secretNotPlainText {
		return nil, true, nil
	}

	if r.secret != nil {
		return r.secret, true, nil
	}

	return nil, true, fmt.Errorf("not supported")
}

func (r *testClient) GetSigningKeyID() (kid string) {
	return r.kid
}

func (r *testClient) GetSigningAlg() (alg string) {
	return r.alg
}

func (r *testClient) GetEncryptionKeyID() (kid string) {
	return r.encKID
}

func (r *testClient) GetEncryptionAlg() (alg string) {
	return r.encAlg
}

func (r *testClient) GetEncryptionEnc() (enc string) {
	return r.enc
}

func (r *testClient) IsClientSigned() (is bool) {
	return r.csigned
}

func (r *testClient) GetJSONWebKeys() (jwks *jose.JSONWebKeySet) {
	return r.jwks
}

func (r *testClient) GetJSONWebKeysURI() (uri string) {
	return r.jwksURI
}

type stubBase struct {
	id      string
	jwks    *jose.JSONWebKeySet
	jwksURI string
}

func (s *stubBase) GetID() string                                   { return s.id }
func (s *stubBase) GetClientSecretPlainText() ([]byte, bool, error) { return nil, false, nil }
func (s *stubBase) GetJSONWebKeys() *jose.JSONWebKeySet             { return s.jwks }
func (s *stubBase) GetJSONWebKeysURI() string                       { return s.jwksURI }

type stubJARClient struct {
	stubBase
	sigKID, sigAlg, encKID, encAlg, encEnc string
}

func (s *stubJARClient) GetRequestObjectSigningKeyID() string    { return s.sigKID }
func (s *stubJARClient) GetRequestObjectSigningAlg() string      { return s.sigAlg }
func (s *stubJARClient) GetRequestObjectEncryptionKeyID() string { return s.encKID }
func (s *stubJARClient) GetRequestObjectEncryptionAlg() string   { return s.encAlg }
func (s *stubJARClient) GetRequestObjectEncryptionEnc() string   { return s.encEnc }

type stubIDTokenClient struct {
	stubBase
	sigKID, sigAlg, encKID, encAlg, encEnc string
}

func (s *stubIDTokenClient) GetIDTokenSignedResponseKeyID() string    { return s.sigKID }
func (s *stubIDTokenClient) GetIDTokenSignedResponseAlg() string      { return s.sigAlg }
func (s *stubIDTokenClient) GetIDTokenEncryptedResponseKeyID() string { return s.encKID }
func (s *stubIDTokenClient) GetIDTokenEncryptedResponseAlg() string   { return s.encAlg }
func (s *stubIDTokenClient) GetIDTokenEncryptedResponseEnc() string   { return s.encEnc }

type stubJARMClient struct {
	stubBase
	sigKID, sigAlg, encKID, encAlg, encEnc string
}

func (s *stubJARMClient) GetAuthorizationSignedResponseKeyID() string    { return s.sigKID }
func (s *stubJARMClient) GetAuthorizationSignedResponseAlg() string      { return s.sigAlg }
func (s *stubJARMClient) GetAuthorizationEncryptedResponseKeyID() string { return s.encKID }
func (s *stubJARMClient) GetAuthorizationEncryptedResponseAlg() string   { return s.encAlg }
func (s *stubJARMClient) GetAuthorizationEncryptedResponseEnc() string   { return s.encEnc }

type stubUserInfoClient struct {
	stubBase
	sigKID, sigAlg, encKID, encAlg, encEnc string
}

func (s *stubUserInfoClient) GetUserinfoSignedResponseKeyID() string    { return s.sigKID }
func (s *stubUserInfoClient) GetUserinfoSignedResponseAlg() string      { return s.sigAlg }
func (s *stubUserInfoClient) GetUserinfoEncryptedResponseKeyID() string { return s.encKID }
func (s *stubUserInfoClient) GetUserinfoEncryptedResponseAlg() string   { return s.encAlg }
func (s *stubUserInfoClient) GetUserinfoEncryptedResponseEnc() string   { return s.encEnc }

type stubJWTProfileAccessTokenClient struct {
	stubBase
	sigKID, sigAlg, encKID, encAlg, encEnc string
	enable                                 bool
}

func (s *stubJWTProfileAccessTokenClient) GetAccessTokenSignedResponseKeyID() string {
	return s.sigKID
}

func (s *stubJWTProfileAccessTokenClient) GetAccessTokenSignedResponseAlg() string {
	return s.sigAlg
}

func (s *stubJWTProfileAccessTokenClient) GetAccessTokenEncryptedResponseKeyID() string {
	return s.encKID
}

func (s *stubJWTProfileAccessTokenClient) GetAccessTokenEncryptedResponseAlg() string {
	return s.encAlg
}

func (s *stubJWTProfileAccessTokenClient) GetAccessTokenEncryptedResponseEnc() string {
	return s.encEnc
}

func (s *stubJWTProfileAccessTokenClient) GetEnableJWTProfileOAuthAccessTokens() bool {
	return s.enable
}

type stubIntrospectionClient struct {
	stubBase
	sigKID, sigAlg, encKID, encAlg, encEnc string
}

func (s *stubIntrospectionClient) GetIntrospectionSignedResponseKeyID() string    { return s.sigKID }
func (s *stubIntrospectionClient) GetIntrospectionSignedResponseAlg() string      { return s.sigAlg }
func (s *stubIntrospectionClient) GetIntrospectionEncryptedResponseKeyID() string { return s.encKID }
func (s *stubIntrospectionClient) GetIntrospectionEncryptedResponseAlg() string   { return s.encAlg }
func (s *stubIntrospectionClient) GetIntrospectionEncryptedResponseEnc() string   { return s.encEnc }

func TestNewClient(t *testing.T) {
	testCases := []struct {
		name        string
		constructor func(any) Client
		client      any
		expectedID  string
		sigKID      string
		sigAlg      string
		encKID      string
		encAlg      string
		encEnc      string
		signed      bool
		nilOut      bool
	}{
		{
			name:        "ShouldReturnNilForUnsupportedTypeJAR",
			constructor: NewJARClient,
			client:      struct{}{},
			nilOut:      true,
		},
		{
			name:        "ShouldDecorateJARClient",
			constructor: NewJARClient,
			client: &stubJARClient{
				stubBase: stubBase{id: "abc"},
				sigKID:   "sig-kid",
				sigAlg:   "RS256",
				encKID:   "enc-kid",
				encAlg:   string(jose.RSA_OAEP_256),
				encEnc:   string(jose.A128CBC_HS256),
			},
			expectedID: "abc",
			sigKID:     "sig-kid",
			sigAlg:     "RS256",
			encKID:     "enc-kid",
			encAlg:     string(jose.RSA_OAEP_256),
			encEnc:     string(jose.A128CBC_HS256),
			signed:     true,
		},
		{
			name:        "ShouldReturnNilForUnsupportedTypeIDToken",
			constructor: NewIDTokenClient,
			client:      struct{}{},
			nilOut:      true,
		},
		{
			name:        "ShouldDecorateIDTokenClient",
			constructor: NewIDTokenClient,
			client: &stubIDTokenClient{
				stubBase: stubBase{id: "abc"},
				sigKID:   "id-sig-kid",
				sigAlg:   "RS256",
				encKID:   "id-enc-kid",
				encAlg:   string(jose.RSA_OAEP_256),
				encEnc:   string(jose.A128CBC_HS256),
			},
			expectedID: "abc",
			sigKID:     "id-sig-kid",
			sigAlg:     "RS256",
			encKID:     "id-enc-kid",
			encAlg:     string(jose.RSA_OAEP_256),
			encEnc:     string(jose.A128CBC_HS256),
		},
		{
			name:        "ShouldReturnNilForUnsupportedTypeJARM",
			constructor: NewJARMClient,
			client:      struct{}{},
			nilOut:      true,
		},
		{
			name:        "ShouldDecorateJARMClient",
			constructor: NewJARMClient,
			client: &stubJARMClient{
				stubBase: stubBase{id: "abc"},
				sigKID:   "jarm-sig-kid",
				sigAlg:   "ES256",
				encKID:   "jarm-enc-kid",
				encAlg:   string(jose.ECDH_ES_A128KW),
				encEnc:   string(jose.A128GCM),
			},
			expectedID: "abc",
			sigKID:     "jarm-sig-kid",
			sigAlg:     "ES256",
			encKID:     "jarm-enc-kid",
			encAlg:     string(jose.ECDH_ES_A128KW),
			encEnc:     string(jose.A128GCM),
		},
		{
			name:        "ShouldReturnNilForUnsupportedTypeUserInfo",
			constructor: NewUserInfoClient,
			client:      struct{}{},
			nilOut:      true,
		},
		{
			name:        "ShouldDecorateUserInfoClient",
			constructor: NewUserInfoClient,
			client: &stubUserInfoClient{
				stubBase: stubBase{id: "abc"},
				sigKID:   "ui-sig-kid",
				sigAlg:   "RS256",
				encKID:   "ui-enc-kid",
				encAlg:   string(jose.RSA_OAEP_256),
				encEnc:   string(jose.A128CBC_HS256),
			},
			expectedID: "abc",
			sigKID:     "ui-sig-kid",
			sigAlg:     "RS256",
			encKID:     "ui-enc-kid",
			encAlg:     string(jose.RSA_OAEP_256),
			encEnc:     string(jose.A128CBC_HS256),
		},
		{
			name:        "ShouldReturnNilForUnsupportedTypeJWTProfileAccessToken",
			constructor: NewJWTProfileAccessTokenClient,
			client:      struct{}{},
			nilOut:      true,
		},
		{
			name:        "ShouldDecorateJWTProfileAccessTokenClient",
			constructor: NewJWTProfileAccessTokenClient,
			client: &stubJWTProfileAccessTokenClient{
				stubBase: stubBase{id: "abc"},
				sigKID:   "at-sig-kid",
				sigAlg:   "RS256",
				encKID:   "at-enc-kid",
				encAlg:   string(jose.RSA_OAEP_256),
				encEnc:   string(jose.A128CBC_HS256),
				enable:   true,
			},
			expectedID: "abc",
			sigKID:     "at-sig-kid",
			sigAlg:     "RS256",
			encKID:     "at-enc-kid",
			encAlg:     string(jose.RSA_OAEP_256),
			encEnc:     string(jose.A128CBC_HS256),
		},
		{
			name:        "ShouldReturnNilForUnsupportedTypeIntrospection",
			constructor: NewIntrospectionClient,
			client:      struct{}{},
			nilOut:      true,
		},
		{
			name:        "ShouldDecorateIntrospectionClient",
			constructor: NewIntrospectionClient,
			client: &stubIntrospectionClient{
				stubBase: stubBase{id: "abc"},
				sigKID:   "ix-sig-kid",
				sigAlg:   "RS256",
				encKID:   "ix-enc-kid",
				encAlg:   string(jose.RSA_OAEP_256),
				encEnc:   string(jose.A128CBC_HS256),
			},
			expectedID: "abc",
			sigKID:     "ix-sig-kid",
			sigAlg:     "RS256",
			encKID:     "ix-enc-kid",
			encAlg:     string(jose.RSA_OAEP_256),
			encEnc:     string(jose.A128CBC_HS256),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.constructor(tc.client)

			if tc.nilOut {
				assert.Nil(t, c)

				return
			}

			require.NotNil(t, c)

			assert.Equal(t, tc.expectedID, c.GetID())
			assert.Equal(t, tc.sigKID, c.GetSigningKeyID())
			assert.Equal(t, tc.sigAlg, c.GetSigningAlg())
			assert.Equal(t, tc.encKID, c.GetEncryptionKeyID())
			assert.Equal(t, tc.encAlg, c.GetEncryptionAlg())
			assert.Equal(t, tc.encEnc, c.GetEncryptionEnc())
			assert.Equal(t, tc.signed, c.IsClientSigned())
		})
	}
}

func TestNewStatelessJWTProfileIntrospectionClient(t *testing.T) {
	introspection := &stubIntrospectionClient{
		stubBase: stubBase{id: "ix"},
		sigKID:   "ix-sig-kid",
		sigAlg:   "RS256",
	}

	jwtProfile := &stubJWTProfileAccessTokenClient{
		stubBase: stubBase{id: "at"},
		sigKID:   "at-sig-kid",
		sigAlg:   "RS256",
	}

	testCases := []struct {
		name        string
		client      any
		nilOut      bool
		expectedKID string
		expectedID  string
	}{
		{
			name:   "ShouldReturnNilForUnsupportedType",
			client: struct{}{},
			nilOut: true,
		},
		{
			name:        "ShouldPreferIntrospectionClient",
			client:      introspection,
			expectedKID: "ix-sig-kid",
			expectedID:  "ix",
		},
		{
			name:        "ShouldFallbackToJWTProfileAccessTokenClient",
			client:      jwtProfile,
			expectedKID: "at-sig-kid",
			expectedID:  "at",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewStatelessJWTProfileIntrospectionClient(tc.client)

			if tc.nilOut {
				assert.Nil(t, c)

				return
			}

			require.NotNil(t, c)
			assert.Equal(t, tc.expectedID, c.GetID())
			assert.Equal(t, tc.expectedKID, c.GetSigningKeyID())
			assert.False(t, c.IsClientSigned())
		})
	}
}
