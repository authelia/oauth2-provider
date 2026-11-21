// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestIntrospectionJWTResponseNegotiation(t *testing.T) {
	const (
		secret       = "foobarfoobarfoobarfoobarfoobar12"
		accept       = "application/token-introspection+jwt"
		contentJSON  = consts.ContentTypeApplicationJSON
		contentJWT   = consts.ContentTypeApplicationTokenIntrospectionJWT
		caller       = "rs"
		introspected = "active-token"
	)

	key := gen.MustRSAKey()

	testCases := []struct {
		name     string
		alg      string
		accept   string
		token    string
		noSigner bool
		content  string
		active   bool
		headerA  string
	}{
		{name: "ShouldReturnJSONWithoutARequestOrRegistration", token: introspected, content: contentJSON, active: true},
		{name: "ShouldReturnJSONForAnInactiveTokenWithoutARequestOrRegistration", token: "unknown", content: contentJSON},
		{name: "ShouldReturnAJWTForTheAcceptHeaderDefaultingToRS256", accept: accept, token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldReturnAJWTForAnAcceptListWithParameters", accept: "application/json;q=0.5, " + accept + ";q=1", token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldReturnAJWTForARegisteredAlgorithm", alg: "RS256", token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldReturnAJWTForARegisteredAlgorithmWhenJSONIsAccepted", alg: "RS256", accept: contentJSON, token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldSignAnInactiveResponseForTheAcceptHeader", accept: accept, token: "unknown", content: contentJWT, headerA: "RS256"},
		{name: "ShouldSignAnInactiveResponseForARegisteredAlgorithm", alg: "RS256", token: "unknown", content: contentJWT, headerA: "RS256"},
		{name: "ShouldNotTreatARefusedMediaTypeAsARequest", accept: accept + ";q=0", token: introspected, content: contentJSON, active: true},
		{name: "ShouldNotTreatARefusalWithADecimalZeroAsARequest", accept: accept + ";q=0.0", token: introspected, content: contentJSON, active: true},
		{name: "ShouldNotTreatARefusalWithALongDecimalZeroAsARequest", accept: accept + ";q=0.000", token: introspected, content: contentJSON, active: true},
		{name: "ShouldNotTreatAnUppercaseRefusalAsARequest", accept: accept + ";Q=0", token: introspected, content: contentJSON, active: true},
		{name: "ShouldTreatALowQualityAsARequest", accept: accept + ";q=0.001", token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldTreatAMalformedQualityAsARequest", accept: accept + ";q=high", token: introspected, content: contentJWT, active: true, headerA: "RS256"},
		{name: "ShouldReturnJSONForTheAcceptHeaderWithoutASigner", accept: accept, noSigner: true, token: introspected, content: contentJSON, active: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients[caller] = &DefaultRegisteredClient{
				DefaultClient:                  &DefaultClient{ID: caller, ClientSecret: NewPlainTextClientSecret(secret)},
				IntrospectionSignedResponseAlg: tc.alg,
			}

			config := &Config{
				Issuer:                     "https://as.example.com",
				TokenIntrospectionHandlers: TokenIntrospectionHandlers{&fixedIntrospector{token: introspected}},
			}

			if !tc.noSigner {
				config.IntrospectionJWTResponseStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
			}

			provider := &Fosite{Store: store, Config: config}

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {tc.token}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.SetBasicAuth(caller, secret)

			if tc.accept != "" {
				r.Header.Set("Accept", tc.accept)
			}

			ctx := context.Background()
			recorder := httptest.NewRecorder()

			responder, err := provider.NewIntrospectionRequest(ctx, r, &DefaultSession{})
			if err != nil {
				provider.WriteIntrospectionError(ctx, recorder, err)
			} else {
				provider.WriteIntrospectionResponse(ctx, recorder, responder)
			}

			require.Equal(t, http.StatusOK, recorder.Code)
			assert.Contains(t, recorder.Header().Get(consts.HeaderContentType), tc.content)

			var body map[string]any

			if tc.content == contentJSON {
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
				assert.Equal(t, tc.active, body["active"])

				return
			}

			signed, err := jose.ParseSignedCompact(recorder.Body.String(), []jose.SignatureAlgorithm{jose.RS256})
			require.NoError(t, err)
			require.Len(t, signed.Signatures, 1)

			assert.Equal(t, tc.headerA, signed.Signatures[0].Header.Algorithm)

			payload, err := signed.Verify(&key.PublicKey)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(payload, &body))

			// RFC 9701 Section 5.
			assert.Equal(t, "https://as.example.com", body[consts.ClaimIssuer])
			assert.NotEmpty(t, body[consts.ClaimIssuedAt])
			assert.Contains(t, body[consts.ClaimAudience], caller)

			introspection, ok := body["token_introspection"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, tc.active, introspection["active"])

			if !tc.active {
				assert.Len(t, introspection, 1, "an inactive response MUST NOT include other members")
			}
		})
	}
}

func TestIntrospectionStrategyServerError(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobarfoobar12"

	testCases := []struct {
		name     string
		failure  error
		code     int
		contains string
	}{
		{name: "ShouldReportAServerError", failure: ErrServerError.WithDebug("the store failed"), code: http.StatusInternalServerError, contains: "server_error"},
		{name: "ShouldReportAWrappedServerError", failure: errorsx.WithStack(ErrServerError), code: http.StatusInternalServerError, contains: "server_error"},
		{name: "ShouldAnswerARejectionAsInactive", failure: ErrRequestUnauthorized, code: http.StatusOK, contains: `"active":false`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients["rs"] = &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "rs", ClientSecret: NewPlainTextClientSecret(secret)}}

			provider := &Fosite{Store: store, Config: &Config{TokenIntrospectionHandlers: TokenIntrospectionHandlers{&fixedIntrospector{failure: tc.failure}}}}

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {"token"}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.SetBasicAuth("rs", secret)

			ctx := context.Background()
			recorder := httptest.NewRecorder()

			_, err := provider.NewIntrospectionRequest(ctx, r, &DefaultSession{})
			require.Error(t, err)

			provider.WriteIntrospectionError(ctx, recorder, err)

			assert.Equal(t, tc.code, recorder.Code)
			assert.Contains(t, recorder.Body.String(), tc.contains)
		})
	}
}

func TestIntrospectionServerErrorIsNotReportedAsInactive(t *testing.T) {
	recorder := httptest.NewRecorder()

	(&Fosite{Config: &Config{}}).WriteIntrospectionError(context.Background(), recorder, ErrServerError.WithHint("Failed to generate the response."))

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), `"active"`)
	assert.Contains(t, recorder.Body.String(), "server_error")
}

type fixedIntrospector struct {
	token   string
	failure error
}

func (i *fixedIntrospector) IntrospectToken(_ context.Context, token string, _ TokenUse, request AccessRequester, _ []string) (TokenUse, error) {
	if i.failure != nil {
		return "", i.failure
	}

	if token != i.token {
		return "", ErrUnknownRequest
	}

	request.SetSession(&DefaultSession{Subject: "peter"})

	return AccessToken, nil
}

func TestIntrospectionJWTResponseEncoding(t *testing.T) {
	const (
		secret       = "foobarfoobarfoobarfoobarfoobar12"
		accept       = "application/token-introspection+jwt"
		caller       = "rs"
		introspected = "active-token"
		issuer       = "https://as.example.com"
	)

	rsaKey := gen.MustRSAKey()
	ecKey := gen.MustES256Key()
	encryptionKey := gen.MustRSAKey()

	issuerKeys := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: rsaKey, KeyID: "rs256", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature},
		{Key: ecKey, KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
	}}

	clientKeys := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &encryptionKey.PublicKey, KeyID: "enc", Algorithm: string(jose.RSA_OAEP_256), Use: consts.JSONWebTokenUseEncryption},
	}}

	sum := sha256.Sum256([]byte(secret))
	a128kw := sum[:16]

	verifyRS256 := func(t *testing.T, raw string) map[string]any {
		return verifyIntrospectionJWS(t, raw, jose.RS256, "rs256", &rsaKey.PublicKey)
	}

	testCases := []struct {
		name   string
		client func(c *DefaultRegisteredClient)
		accept string
		token  string
		code   int
		verify func(t *testing.T, body string) (payload map[string]any)
	}{
		{
			name:   "ShouldSignWithRS256",
			client: func(c *DefaultRegisteredClient) { c.IntrospectionSignedResponseAlg = string(jose.RS256) },
			verify: verifyRS256,
		},
		{
			name:   "ShouldSignWithES256",
			client: func(c *DefaultRegisteredClient) { c.IntrospectionSignedResponseAlg = string(jose.ES256) },
			verify: func(t *testing.T, body string) map[string]any {
				return verifyIntrospectionJWS(t, body, jose.ES256, "es256", &ecKey.PublicKey)
			},
		},
		{
			name:   "ShouldSignWithTheClientSecret",
			client: func(c *DefaultRegisteredClient) { c.IntrospectionSignedResponseAlg = string(jose.HS256) },
			verify: func(t *testing.T, body string) map[string]any {
				return verifyIntrospectionJWS(t, body, jose.HS256, "", []byte(secret))
			},
		},
		{
			name: "ShouldSignThenEncrypt",
			client: func(c *DefaultRegisteredClient) {
				c.IntrospectionSignedResponseAlg = string(jose.RS256)
				c.IntrospectionEncryptedResponseAlg = string(jose.RSA_OAEP_256)
				c.JSONWebKeys = clientKeys
			},
			verify: func(t *testing.T, body string) map[string]any {
				return verifyRS256(t, decryptIntrospectionJWE(t, body, jose.RSA_OAEP_256, jose.A128CBC_HS256, "enc", encryptionKey))
			},
		},
		{
			name:   "ShouldSignThenEncryptForTheAcceptHeader",
			accept: accept,
			client: func(c *DefaultRegisteredClient) {
				c.IntrospectionEncryptedResponseAlg = string(jose.RSA_OAEP_256)
				c.JSONWebKeys = clientKeys
			},
			verify: func(t *testing.T, body string) map[string]any {
				return verifyRS256(t, decryptIntrospectionJWE(t, body, jose.RSA_OAEP_256, jose.A128CBC_HS256, "enc", encryptionKey))
			},
		},
		{
			name: "ShouldSignThenEncryptWithTheRegisteredContentEncryption",
			client: func(c *DefaultRegisteredClient) {
				c.IntrospectionSignedResponseAlg = string(jose.RS256)
				c.IntrospectionEncryptedResponseAlg = string(jose.RSA_OAEP_256)
				c.IntrospectionEncryptedResponseEnc = string(jose.A256GCM)
				c.JSONWebKeys = clientKeys
			},
			verify: func(t *testing.T, body string) map[string]any {
				return verifyRS256(t, decryptIntrospectionJWE(t, body, jose.RSA_OAEP_256, jose.A256GCM, "enc", encryptionKey))
			},
		},
		{
			name: "ShouldSignThenEncryptWithTheClientSecret",
			client: func(c *DefaultRegisteredClient) {
				c.IntrospectionSignedResponseAlg = string(jose.HS256)
				c.IntrospectionEncryptedResponseAlg = string(jose.A128KW)
			},
			verify: func(t *testing.T, body string) map[string]any {
				return verifyIntrospectionJWS(t, decryptIntrospectionJWE(t, body, jose.A128KW, jose.A128CBC_HS256, "", a128kw), jose.HS256, "", []byte(secret))
			},
		},
		{
			name:  "ShouldSignThenEncryptAnInactiveResponse",
			token: "unknown",
			client: func(c *DefaultRegisteredClient) {
				c.IntrospectionSignedResponseAlg = string(jose.RS256)
				c.IntrospectionEncryptedResponseAlg = string(jose.RSA_OAEP_256)
				c.JSONWebKeys = clientKeys
			},
			verify: func(t *testing.T, body string) map[string]any {
				return verifyRS256(t, decryptIntrospectionJWE(t, body, jose.RSA_OAEP_256, jose.A128CBC_HS256, "enc", encryptionKey))
			},
		},
		{
			name: "ShouldFailWithoutAnEncryptionKey",
			client: func(c *DefaultRegisteredClient) {
				c.IntrospectionSignedResponseAlg = string(jose.RS256)
				c.IntrospectionEncryptedResponseAlg = string(jose.RSA_OAEP_256)
			},
			code: http.StatusInternalServerError,
		},
		{
			name: "ShouldFailForRSA1_5",
			client: func(c *DefaultRegisteredClient) {
				c.IntrospectionSignedResponseAlg = string(jose.RS256)
				c.IntrospectionEncryptedResponseAlg = string(jose.RSA1_5)
				c.JSONWebKeys = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: &encryptionKey.PublicKey, KeyID: "enc", Algorithm: string(jose.RSA1_5), Use: consts.JSONWebTokenUseEncryption},
				}}
			},
			code: http.StatusInternalServerError,
		},
		{
			name:   "ShouldFailForAnAlgorithmTheServerHasNoKeyFor",
			client: func(c *DefaultRegisteredClient) { c.IntrospectionSignedResponseAlg = string(jose.PS256) },
			code:   http.StatusInternalServerError,
		},
		{
			name:   "ShouldFailToSignWithAShortClientSecret",
			client: func(c *DefaultRegisteredClient) { c.IntrospectionSignedResponseAlg = string(jose.HS512) },
			code:   http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: caller, ClientSecret: NewPlainTextClientSecret(secret)}}
			tc.client(client)

			store := storage.NewMemoryStore()
			store.Clients[caller] = client

			config := &Config{
				Issuer:                     issuer,
				TokenIntrospectionHandlers: TokenIntrospectionHandlers{&fixedIntrospector{token: introspected}},
			}

			config.IntrospectionJWTResponseStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(issuerKeys)}

			provider := &Fosite{Store: store, Config: config}

			token := tc.token
			if token == "" {
				token = introspected
			}

			r := httptest.NewRequest(http.MethodPost, issuer+"/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {token}}.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			r.SetBasicAuth(caller, secret)

			if tc.accept != "" {
				r.Header.Set(consts.HeaderAccept, tc.accept)
			}

			ctx := context.Background()
			recorder := httptest.NewRecorder()

			if responder, err := provider.NewIntrospectionRequest(ctx, r, &DefaultSession{}); err != nil {
				provider.WriteIntrospectionError(ctx, recorder, err)
			} else {
				provider.WriteIntrospectionResponse(ctx, recorder, responder)
			}

			assert.Equal(t, consts.CacheControlNoStore, recorder.Header().Get(consts.HeaderCacheControl))

			if tc.code != 0 {
				assert.Equal(t, tc.code, recorder.Code)
				assert.Contains(t, recorder.Header().Get(consts.HeaderContentType), consts.ContentTypeApplicationJSON)
				assert.Contains(t, recorder.Body.String(), "server_error")
				assert.NotContains(t, recorder.Body.String(), "peter")

				return
			}

			require.Equal(t, http.StatusOK, recorder.Code)
			assert.Contains(t, recorder.Header().Get(consts.HeaderContentType), consts.ContentTypeApplicationTokenIntrospectionJWT)

			payload := tc.verify(t, recorder.Body.String())

			// RFC 9701 Section 5.
			assert.Equal(t, issuer, payload[consts.ClaimIssuer])
			assert.Equal(t, []any{caller}, payload[consts.ClaimAudience])
			assert.NotEmpty(t, payload[consts.ClaimIssuedAt])
			assert.NotEmpty(t, payload[consts.ClaimJWTID])

			introspection, ok := payload[consts.ClaimTokenIntrospection].(map[string]any)
			require.True(t, ok)

			if token == introspected {
				assert.Equal(t, true, introspection[consts.ClaimActive])
				assert.Equal(t, "peter", introspection[consts.ClaimSubject])
			} else {
				assert.Equal(t, map[string]any{consts.ClaimActive: false}, introspection)
			}
		})
	}
}

// verifyIntrospectionJWS verifies an RFC 9701 Section 5 response JWS and returns its payload.
func verifyIntrospectionJWS(t *testing.T, raw string, alg jose.SignatureAlgorithm, kid string, key any) (payload map[string]any) {
	t.Helper()

	signed, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{alg})
	require.NoError(t, err)
	require.Len(t, signed.Signatures, 1)

	header := signed.Signatures[0].Header

	assert.Equal(t, string(alg), header.Algorithm)
	assert.Equal(t, kid, header.KeyID)
	assert.Equal(t, consts.JSONWebTokenTypeTokenIntrospection, header.ExtraHeaders[jose.HeaderType])

	data, err := signed.Verify(key)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &payload))

	return payload
}

// decryptIntrospectionJWE decrypts an RFC 9701 Section 5 signed then encrypted response, which RFC 7519 Section 5.2
// requires to declare the nested JWT with the 'cty' header, and returns the JWS it carries.
func decryptIntrospectionJWE(t *testing.T, raw string, alg jose.KeyAlgorithm, enc jose.ContentEncryption, kid string, key any) (jws string) {
	t.Helper()

	encrypted, err := jose.ParseEncryptedCompact(raw, []jose.KeyAlgorithm{alg}, []jose.ContentEncryption{enc})
	require.NoError(t, err)

	assert.Equal(t, string(alg), encrypted.Header.Algorithm)
	assert.Equal(t, kid, encrypted.Header.KeyID)
	assert.Equal(t, string(enc), encrypted.Header.ExtraHeaders[jose.HeaderKey("enc")])
	assert.Equal(t, "JWT", encrypted.Header.ExtraHeaders[jose.HeaderContentType])

	plaintext, err := encrypted.Decrypt(key)
	require.NoError(t, err)

	return string(plaintext)
}
