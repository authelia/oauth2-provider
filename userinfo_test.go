// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestNewUserinfoRequest(t *testing.T) {
	testCases := []struct {
		name      string
		method    string
		header    string
		body      url.Values
		noToken   bool
		introErr  error
		use       TokenUse
		granted   []string
		resource  []string
		clientID  string
		clientErr error
		code      int
		errCode   string
		challenge string
	}{
		{name: "ShouldAcceptGET", method: http.MethodGet, granted: []string{consts.ScopeOpenID}},
		{name: "ShouldAcceptPOST", method: http.MethodPost, granted: []string{consts.ScopeOpenID}},
		{name: "ShouldAcceptFormBodyToken", method: http.MethodPost, header: "-", body: url.Values{consts.FormParameterAccessToken: {userinfoToken}}, granted: []string{consts.ScopeOpenID}},
		{name: "ShouldAcceptResourceUserinfoEndpoint", method: http.MethodGet, granted: []string{consts.ScopeOpenID}, resource: []string{userinfoURL}},
		{name: "ShouldAcceptResourceIssuer", method: http.MethodGet, granted: []string{consts.ScopeOpenID}, resource: []string{userinfoIssuer}},
		{name: "ShouldRejectMethod", method: http.MethodPut, noToken: true, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectMissingToken", method: http.MethodGet, header: "-", noToken: true, code: http.StatusUnauthorized, errCode: "invalid_token", challenge: `Bearer`},
		{name: "ShouldRejectDPoPSchemeWhenDisabled", method: http.MethodGet, header: "DPoP " + userinfoToken, noToken: true, code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldRejectTokenInHeaderAndBody", method: http.MethodPost, body: url.Values{consts.FormParameterAccessToken: {userinfoToken}}, noToken: true, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectUnknownToken", method: http.MethodGet, introErr: ErrTokenExpired, code: http.StatusUnauthorized, errCode: "invalid_token", challenge: `Bearer error="invalid_token"`},
		{name: "ShouldRejectUnknownFormBodyToken", method: http.MethodPost, header: "-", body: url.Values{consts.FormParameterAccessToken: {userinfoToken}}, introErr: ErrTokenExpired, code: http.StatusUnauthorized, errCode: "invalid_token", challenge: `Bearer error="invalid_token"`},
		{name: "ShouldRejectRefreshToken", method: http.MethodGet, use: RefreshToken, granted: []string{consts.ScopeOpenID}, code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldRejectMissingOpenIDScope", method: http.MethodGet, granted: []string{"profile"}, code: http.StatusForbidden, errCode: "insufficient_scope", challenge: `Bearer error="insufficient_scope"`},
		{name: "ShouldRejectOtherResource", method: http.MethodGet, granted: []string{consts.ScopeOpenID}, resource: []string{"https://api.example.com"}, code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldRejectUnregisteredClient", method: http.MethodGet, granted: []string{consts.ScopeOpenID}, clientID: "deleted", code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldRejectRepeatedFormBodyToken", method: http.MethodPost, header: "-", body: url.Values{consts.FormParameterAccessToken: {userinfoToken, userinfoToken}}, noToken: true, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldPreserveAnIntrospectionServerError", method: http.MethodGet, introErr: ErrServerError, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldPreserveAnIntrospectionTemporaryFailure", method: http.MethodGet, introErr: ErrTemporarilyUnavailable, code: http.StatusServiceUnavailable, errCode: "temporarily_unavailable"},
		{name: "ShouldReportAPlainIntrospectionFailureAsAServerError", method: http.MethodGet, introErr: errors.New("the backend failed"), code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldPreserveAClientLookupServerError", method: http.MethodGet, granted: []string{consts.ScopeOpenID}, clientErr: ErrServerError, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldPreserveAClientLookupTemporaryFailure", method: http.MethodGet, granted: []string{consts.ScopeOpenID}, clientErr: ErrTemporarilyUnavailable, code: http.StatusServiceUnavailable, errCode: "temporarily_unavailable"},
		{name: "ShouldReportAPlainClientLookupFailureAsAServerError", method: http.MethodGet, granted: []string{consts.ScopeOpenID}, clientErr: errors.New("the store failed"), code: http.StatusInternalServerError, errCode: "server_error"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			introspector := mock.NewMockTokenIntrospector(ctrl)
			provider, registered := newUserinfoProvider(introspector, nil)

			if tc.clientErr != nil {
				provider.Store = &userinfoFailingClientStore{MemoryStore: provider.Store.(*storage.MemoryStore), err: tc.clientErr}
			}

			var r *http.Request

			if tc.body != nil {
				r = httptest.NewRequest(tc.method, userinfoURL, strings.NewReader(tc.body.Encode()))
				r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			} else {
				r = httptest.NewRequest(tc.method, userinfoURL, nil)
			}

			switch tc.header {
			case "":
				r.Header.Set(consts.HeaderAuthorization, "Bearer "+userinfoToken)
			case "-":
			default:
				r.Header.Set(consts.HeaderAuthorization, tc.header)
			}

			if !tc.noToken {
				introspector.EXPECT().IntrospectToken(gomock.Any(), userinfoToken, gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ string, _ TokenUse, requester AccessRequester, _ []string) (TokenUse, error) {
						assert.Equal(t, true, ctx.Value(SkipStatelessIntrospectionContextKey))

						if tc.introErr != nil {
							return "", tc.introErr
						}

						ar := requester.(*AccessRequest)
						ar.GrantedScope = tc.granted
						ar.GrantedResource = tc.resource

						id := tc.clientID
						if id == "" {
							id = userinfoClientID
						}

						ar.Client = &DefaultClient{ID: id}

						return cmpUse(tc.use), nil
					})
			}

			requester, err := provider.NewUserinfoRequest(context.Background(), r, &DefaultSession{})
			require.NotNil(t, requester)

			if tc.code == 0 {
				require.NoError(t, err)
				assert.Equal(t, registered, requester.GetClient())
				assert.NotNil(t, requester.GetAccessRequester())

				return
			}

			require.Error(t, err)

			rw := httptest.NewRecorder()
			provider.WriteUserinfoError(context.Background(), rw, requester, err)

			assert.Equal(t, tc.code, rw.Code)
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
			assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))

			var body map[string]any

			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
			assert.Equal(t, tc.errCode, body["error"])

			if tc.challenge != "" {
				assert.True(t, strings.HasPrefix(rw.Header().Get(consts.HeaderWWWAuthenticate), tc.challenge), rw.Header().Get(consts.HeaderWWWAuthenticate))
			}

			switch tc.errCode {
			case "invalid_request", "server_error", "temporarily_unavailable":
				assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
			case "insufficient_scope":
				assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `scope="openid"`)
			}

			if tc.challenge == "Bearer" {
				assert.Equal(t, "Bearer", rw.Header().Get(consts.HeaderWWWAuthenticate))
			}
		})
	}
}

func TestWriteUserinfoResponse(t *testing.T) {
	signingKey := gen.MustRSAKey()
	encryptionKey := gen.MustRSAKey()

	claims := &UserinfoClaims{
		Subject:       "pairwise-sub",
		Email:         "john@example.com",
		EmailVerified: new(true),
		Extra:         map[string]any{"groups": []any{"admin"}},
	}

	testCases := []struct {
		name        string
		client      func(c *DefaultRegisteredClient)
		claims      *UserinfoClaims
		code        int
		contentType string
		verify      func(t *testing.T, body string)
	}{
		{
			name:        "ShouldWriteJSON",
			claims:      claims,
			code:        http.StatusOK,
			contentType: consts.ContentTypeApplicationJSON,
			verify: func(t *testing.T, body string) {
				var values map[string]any

				require.NoError(t, json.Unmarshal([]byte(body), &values))
				assert.Equal(t, map[string]any{"sub": "pairwise-sub", "email": "john@example.com", "email_verified": true, "groups": []any{"admin"}}, values)
			},
		},
		{
			name:        "ShouldWriteJSONWhenSigningAlgNone",
			client:      func(c *DefaultRegisteredClient) { c.UserinfoSignedResponseAlg = consts.JSONWebTokenAlgNone },
			claims:      claims,
			code:        http.StatusOK,
			contentType: consts.ContentTypeApplicationJSON,
		},
		{
			name:        "ShouldWriteSignedJWT",
			client:      func(c *DefaultRegisteredClient) { c.UserinfoSignedResponseAlg = string(jose.RS256) },
			claims:      claims,
			code:        http.StatusOK,
			contentType: consts.ContentTypeApplicationJWT,
			verify: func(t *testing.T, body string) {
				assertUserinfoJWTClaims(t, verifyUserinfoJWS(t, body, signingKey))
			},
		},
		{
			name: "ShouldWriteSignedAndEncryptedJWT",
			client: func(c *DefaultRegisteredClient) {
				c.UserinfoSignedResponseAlg = string(jose.RS256)
				c.UserinfoEncryptedResponseAlg = string(jose.RSA_OAEP_256)
				c.JSONWebKeys = userinfoEncryptionJWKS(encryptionKey)
			},
			claims:      claims,
			code:        http.StatusOK,
			contentType: consts.ContentTypeApplicationJWT,
			verify: func(t *testing.T, body string) {
				plaintext := decryptUserinfoJWE(t, body, encryptionKey)

				assertUserinfoJWTClaims(t, verifyUserinfoJWS(t, string(plaintext), signingKey))
			},
		},
		{
			name: "ShouldWriteEncryptedOnlyJWT",
			client: func(c *DefaultRegisteredClient) {
				c.UserinfoEncryptedResponseAlg = string(jose.RSA_OAEP_256)
				c.JSONWebKeys = userinfoEncryptionJWKS(encryptionKey)
			},
			claims:      claims,
			code:        http.StatusOK,
			contentType: consts.ContentTypeApplicationJWT,
			verify: func(t *testing.T, body string) {
				var values map[string]any

				require.NoError(t, json.Unmarshal(decryptUserinfoJWE(t, body, encryptionKey), &values))
				assertUserinfoJWTClaims(t, values)
			},
		},
		{
			name: "ShouldSignWithTheClientSecret",
			client: func(c *DefaultRegisteredClient) {
				c.ClientSecret = NewPlainTextClientSecret(userinfoClientSecret)
				c.ClientSecretExpiresAt = time.Now().Add(time.Hour)
				c.UserinfoSignedResponseAlg = string(jose.HS256)
			},
			claims:      claims,
			code:        http.StatusOK,
			contentType: consts.ContentTypeApplicationJWT,
			verify: func(t *testing.T, body string) {
				jws, err := jose.ParseSignedCompact(body, []jose.SignatureAlgorithm{jose.HS256})
				require.NoError(t, err)

				payload, err := jws.Verify([]byte(userinfoClientSecret))
				require.NoError(t, err)

				var values map[string]any

				require.NoError(t, json.Unmarshal(payload, &values))
				assertUserinfoJWTClaims(t, values)
			},
		},
		{
			name: "ShouldRejectAnExpiredClientSecret",
			client: func(c *DefaultRegisteredClient) {
				c.ClientSecret = NewPlainTextClientSecret(userinfoClientSecret)
				c.ClientSecretExpiresAt = time.Now().Add(-time.Hour)
				c.UserinfoSignedResponseAlg = string(jose.HS256)
			},
			claims: claims,
			code:   http.StatusInternalServerError,
		},
		{
			name: "ShouldRejectAnExpiredClientSecretForEncryptionOnly",
			client: func(c *DefaultRegisteredClient) {
				c.ClientSecret = NewPlainTextClientSecret(userinfoClientSecret)
				c.ClientSecretExpiresAt = time.Now().Add(-time.Hour)
				c.UserinfoEncryptedResponseAlg = string(jose.A128KW)
			},
			claims: claims,
			code:   http.StatusInternalServerError,
		},
		{
			name:   "ShouldRejectMissingSubject",
			claims: &UserinfoClaims{Email: "john@example.com"},
			code:   http.StatusInternalServerError,
		},
		{
			name: "ShouldRejectNilClaims",
			code: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, registered := newUserinfoProvider(nil, signingKey)

			if tc.client != nil {
				tc.client(registered)
			}

			requester := &UserinfoRequest{
				AccessRequester: &AccessRequest{Request: Request{Client: registered, Session: &DefaultSession{}}},
				Client:          registered,
			}

			rw := httptest.NewRecorder()
			provider.WriteUserinfoResponse(context.Background(), rw, requester, tc.claims)

			assert.Equal(t, tc.code, rw.Code)
			assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))

			if tc.contentType != "" {
				assert.Equal(t, tc.contentType, rw.Header().Get(consts.HeaderContentType))
			}

			if tc.verify != nil {
				tc.verify(t, rw.Body.String())
			}
		})
	}
}

func TestWriteUserinfoResponseShouldRejectUnresolvedRequest(t *testing.T) {
	provider, _ := newUserinfoProvider(nil, nil)

	rw := httptest.NewRecorder()
	provider.WriteUserinfoResponse(context.Background(), rw, &UserinfoRequest{}, &UserinfoClaims{Subject: "sub"})

	assert.Equal(t, http.StatusInternalServerError, rw.Code)
}

func TestUserinfoClaims(t *testing.T) {
	updated := time.Unix(1700000000, 0).UTC()

	claims := &UserinfoClaims{
		Subject:             "sub",
		Name:                "John Doe",
		GivenName:           "John",
		FamilyName:          "Doe",
		MiddleName:          "Q",
		Nickname:            "jd",
		PreferredUsername:   "john",
		Profile:             "https://example.com/john",
		Picture:             "https://example.com/john.png",
		Website:             "https://john.example.com",
		Email:               "john@example.com",
		EmailVerified:       new(false),
		Gender:              "male",
		Birthdate:           "1970-01-01",
		Zoneinfo:            "Europe/Paris",
		Locale:              "en-US",
		PhoneNumber:         "+1 555 0100",
		PhoneNumberVerified: new(true),
		Address:             &UserinfoAddressClaim{Locality: "Paris", Country: "FR"},
		UpdatedAt:           updated,
		Extra:               map[string]any{"groups": []any{"admin"}, "name": "ignored"},
	}

	values := claims.ToMap()

	assert.Equal(t, "John Doe", values["name"])
	assert.Equal(t, false, values["email_verified"])
	assert.Equal(t, int64(1700000000), values["updated_at"])
	assert.Equal(t, map[string]any{"locality": "Paris", "country": "FR"}, values["address"])

	t.Run("ShouldRoundTrip", func(t *testing.T) {
		var decoded UserinfoClaims

		decoded.FromMap(values)

		expected := *claims
		expected.Extra = map[string]any{"groups": []any{"admin"}}

		assert.Equal(t, expected, decoded)
	})

	t.Run("ShouldRoundTripJSON", func(t *testing.T) {
		data, err := json.Marshal(values)
		require.NoError(t, err)

		var raw map[string]any

		require.NoError(t, json.Unmarshal(data, &raw))

		var decoded UserinfoClaims

		decoded.FromMap(raw)

		assert.Equal(t, updated, decoded.UpdatedAt)
		assert.Equal(t, &UserinfoAddressClaim{Locality: "Paris", Country: "FR"}, decoded.Address)
	})

	t.Run("ShouldOmitZeroValues", func(t *testing.T) {
		assert.Equal(t, map[string]any{"sub": "sub"}, (&UserinfoClaims{Subject: "sub", Address: &UserinfoAddressClaim{}}).ToMap())
	})

	t.Run("ShouldDropWrongTypes", func(t *testing.T) {
		var decoded UserinfoClaims

		decoded.FromMap(map[string]any{"sub": 1, "email_verified": "true", "updated_at": "now", "custom": 1})

		assert.Equal(t, UserinfoClaims{Extra: map[string]any{"custom": 1}}, decoded)
	})
}

const (
	userinfoIssuer   = "https://auth.example.com"
	userinfoURL      = "https://auth.example.com/userinfo"
	userinfoToken    = "userinfo-token"
	userinfoClientID = "userinfo-client"

	userinfoClientSecret = "foobarfoobarfoobarfoobarfoobar12"
)

type userinfoFailingClientStore struct {
	*storage.MemoryStore

	err error
}

func (s *userinfoFailingClientStore) GetClient(_ context.Context, _ string) (Client, error) {
	return nil, s.err
}

func newUserinfoProvider(introspector TokenIntrospector, key *rsa.PrivateKey) (provider *Fosite, registered *DefaultRegisteredClient) {
	store := storage.NewMemoryStore()

	registered = &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: userinfoClientID}}
	store.Clients[userinfoClientID] = registered

	config := &Config{
		Issuer:       userinfoIssuer,
		EndpointURLs: EndpointURLs{UserInfo: userinfoURL},
	}

	if introspector != nil {
		config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{introspector}
	}

	if key != nil {
		config.JWTStrategy = &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: key, KeyID: "rs256", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature},
			}}),
		}
	}

	return &Fosite{Store: store, Config: config}, registered
}

func userinfoEncryptionJWKS(key *rsa.PrivateKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: "enc", Algorithm: string(jose.RSA_OAEP_256), Use: consts.JSONWebTokenUseEncryption},
	}}
}

func verifyUserinfoJWS(t *testing.T, token string, key *rsa.PrivateKey) (values map[string]any) {
	t.Helper()

	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	payload, err := jws.Verify(&key.PublicKey)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(payload, &values))

	return values
}

func decryptUserinfoJWE(t *testing.T, token string, key *rsa.PrivateKey) (plaintext []byte) {
	t.Helper()

	jwe, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.RSA_OAEP_256}, []jose.ContentEncryption{jose.A128CBC_HS256})
	require.NoError(t, err)

	assert.Equal(t, "enc", jwe.Header.KeyID)

	plaintext, err = jwe.Decrypt(key)
	require.NoError(t, err)

	return plaintext
}

func assertUserinfoJWTClaims(t *testing.T, values map[string]any) {
	t.Helper()

	assert.Equal(t, "pairwise-sub", values["sub"])
	assert.Equal(t, userinfoIssuer, values["iss"])
	assert.Equal(t, []any{userinfoClientID}, values["aud"])
	assert.Equal(t, "john@example.com", values["email"])
	assert.NotEmpty(t, values["jti"])
	assert.NotEmpty(t, values["iat"])
}

//nolint:gocyclo
func TestNewUserinfoRequestDPoP(t *testing.T) {
	type proofs func(t *testing.T, f *userinfoDPoPFixture) []string

	valid := func(t *testing.T, f *userinfoDPoPFixture) []string {
		return []string{f.proof(t, nil)}
	}

	testCases := []struct {
		name     string
		target   string
		method   string
		scheme   string
		formBody bool
		unbound  bool
		enforce  bool
		nonce    bool
		replay   bool
		proofs   proofs

		code      int
		errCode   string
		challenge string
		hint      string
	}{
		{name: "ShouldAcceptBoundTokenGET", method: http.MethodGet, scheme: "DPoP", proofs: valid},
		{name: "ShouldAcceptBoundTokenPOST", method: http.MethodPost, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{jwt.ClaimHTTPMethod: http.MethodPost})}
		}},
		{name: "ShouldAcceptLowerCaseScheme", method: http.MethodGet, scheme: "dpop", proofs: valid},
		{name: "ShouldAcceptConfiguredEndpointHTUBehindProxy", target: "http://internal.local:8080/userinfo", method: http.MethodGet, scheme: "DPoP", proofs: valid},
		{name: "ShouldAcceptNormalizedHTU", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{jwt.ClaimHTTPURI: "HTTPS://AUTH.EXAMPLE.COM:443/userinfo?ignored=1#fragment"})}
		}},
		{name: "ShouldAcceptValidNonce", method: http.MethodGet, scheme: "DPoP", nonce: true, proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{consts.ClaimNonce: f.nonce(t)})}
		}},
		{name: "ShouldAcceptUnboundBearerTokenWhenNotEnforced", method: http.MethodGet, scheme: "Bearer", unbound: true},
		{name: "ShouldRejectUnboundBearerTokenWhenEnforced", method: http.MethodGet, scheme: "Bearer", unbound: true, enforce: true,
			code: http.StatusUnauthorized, errCode: "invalid_token", challenge: `Bearer error="invalid_token"`, hint: "not bound to a DPoP key"},
		{name: "ShouldRejectUnboundTokenUnderDPoPScheme", method: http.MethodGet, scheme: "DPoP", unbound: true, proofs: valid,
			code: http.StatusUnauthorized, errCode: "invalid_token", challenge: `DPoP error="invalid_token"`, hint: "not bound to a DPoP key"},
		{name: "ShouldRejectBoundTokenUnderBearerScheme", method: http.MethodGet, scheme: "Bearer", proofs: valid,
			code: http.StatusUnauthorized, errCode: "invalid_token", challenge: `Bearer error="invalid_token"`, hint: "not presented using the DPoP authentication scheme"},
		{name: "ShouldRejectBoundTokenInFormBody", method: http.MethodPost, formBody: true, proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{jwt.ClaimHTTPMethod: http.MethodPost})}
		}, code: http.StatusUnauthorized, errCode: "invalid_token", hint: "not presented using the DPoP authentication scheme"},
		{name: "ShouldRejectMissingProof", method: http.MethodGet, scheme: "DPoP",
			code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "none was provided"},
		{name: "ShouldRejectMultipleProofs", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, nil), f.proof(t, nil)}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`},
		{name: "ShouldRejectMalformedProof", method: http.MethodGet, scheme: "DPoP", proofs: func(*testing.T, *userinfoDPoPFixture) []string {
			return []string{"not-a-jwt"}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`},
		{name: "ShouldRejectProofFromOtherKey", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.sign(t, f.other, jose.ES256, nil)}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "does not match the key the access token is bound to"},
		{name: "ShouldRejectDisallowedAlgorithm", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.sign(t, f.rsa, jose.RS256, nil)}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`},
		{name: "ShouldRejectMissingATH", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{consts.ClaimDPoPAccessTokenHash: nil})}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "missing the required 'ath' claim"},
		{name: "ShouldRejectATHForOtherToken", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{consts.ClaimDPoPAccessTokenHash: userinfoATH("other-token")})}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "'ath' claim does not match the access token"},
		{name: "ShouldRejectHTMMismatch", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{jwt.ClaimHTTPMethod: http.MethodPost})}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "'htm' claim 'POST' does not match the request method 'GET'"},
		{name: "ShouldRejectHTUForOtherEndpoint", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{jwt.ClaimHTTPURI: userinfoIssuer + "/token"})}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "'htu' claim"},
		{name: "ShouldRejectExpiredProof", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{jwt.ClaimIssuedAt: time.Now().Add(-time.Hour).Unix()})}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "'iat' claim is outside of the acceptable time window"},
		{name: "ShouldRejectFutureProof", method: http.MethodGet, scheme: "DPoP", proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{jwt.ClaimIssuedAt: time.Now().Add(time.Hour).Unix()})}
		}, code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "'iat' claim is outside of the acceptable time window"},
		{name: "ShouldRejectReplayedProof", method: http.MethodGet, scheme: "DPoP", replay: true, proofs: valid,
			code: http.StatusUnauthorized, errCode: "invalid_dpop_proof", challenge: `DPoP error="invalid_dpop_proof"`, hint: "already been used"},
		{name: "ShouldRequestNonceWhenMissing", method: http.MethodGet, scheme: "DPoP", nonce: true, proofs: valid,
			code: http.StatusUnauthorized, errCode: "use_dpop_nonce", challenge: `DPoP error="use_dpop_nonce"`},
		{name: "ShouldRequestNonceWhenUnknown", method: http.MethodGet, scheme: "DPoP", nonce: true, proofs: func(t *testing.T, f *userinfoDPoPFixture) []string {
			return []string{f.proof(t, map[string]any{consts.ClaimNonce: "unknown-nonce"})}
		}, code: http.StatusUnauthorized, errCode: "use_dpop_nonce", challenge: `DPoP error="use_dpop_nonce"`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			introspector := mock.NewMockTokenIntrospector(ctrl)
			provider, registered := newUserinfoProvider(introspector, nil)

			config := provider.Config.(*Config)
			config.DPoPEnabled = true
			config.DPoPEnforce = tc.enforce
			config.DPoPNonceRequired = tc.nonce
			config.DPoPAllowedJWSAlgorithms = []string{string(jose.ES256)}
			config.DPoPStrategy = rfc9449.NewDefaultStrategy(config, provider.Store.(*storage.MemoryStore))

			f := newUserinfoDPoPFixture(t, config)

			var jkt string

			if !tc.unbound {
				jkt = f.jkt
			}

			requests := 1
			if tc.replay {
				requests = 2
			}

			introspector.EXPECT().IntrospectToken(gomock.Any(), userinfoToken, gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ string, _ TokenUse, requester AccessRequester, _ []string) (TokenUse, error) {
					ar := requester.(*AccessRequest)
					ar.GrantedScope = []string{consts.ScopeOpenID}
					ar.Client = &DefaultClient{ID: userinfoClientID}
					ar.Session = &DefaultSession{JWKThumbprint: jkt}

					return AccessToken, nil
				}).Times(requests)

			var headers []string

			if tc.proofs != nil {
				headers = tc.proofs(t, f)
			}

			newRequest := func() *http.Request {
				target := tc.target
				if target == "" {
					target = userinfoURL
				}

				var r *http.Request

				if tc.formBody {
					r = httptest.NewRequest(tc.method, target, strings.NewReader(url.Values{consts.FormParameterAccessToken: {userinfoToken}}.Encode()))
					r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
				} else {
					r = httptest.NewRequest(tc.method, target, nil)
					r.Header.Set(consts.HeaderAuthorization, tc.scheme+" "+userinfoToken)
				}

				for _, header := range headers {
					r.Header.Add(consts.HeaderDPoP, header)
				}

				return r
			}

			if tc.replay {
				_, err := provider.NewUserinfoRequest(context.Background(), newRequest(), &DefaultSession{})
				require.NoError(t, err)
			}

			requester, err := provider.NewUserinfoRequest(context.Background(), newRequest(), &DefaultSession{})
			require.NotNil(t, requester)

			rw := httptest.NewRecorder()

			if tc.code == 0 {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.Equal(t, registered, requester.GetClient())

				provider.WriteUserinfoResponse(context.Background(), rw, requester, &UserinfoClaims{Subject: "sub"})

				assert.Equal(t, http.StatusOK, rw.Code)

				if tc.nonce && !tc.unbound {
					issued := rw.Header().Get(consts.HeaderDPoPNonce)

					require.NotEmpty(t, issued)
					assert.NotEqual(t, f.issued, issued)
					assert.NoError(t, config.DPoPStrategy.ValidateDPoPNonce(context.Background(), issued))
				} else {
					assert.Empty(t, rw.Header().Get(consts.HeaderDPoPNonce))
				}

				return
			}

			require.Error(t, err)

			if tc.hint != "" {
				assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.hint)
			}

			provider.WriteUserinfoError(context.Background(), rw, requester, err)

			assert.Equal(t, tc.code, rw.Code)
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))

			var body map[string]any

			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
			assert.Equal(t, tc.errCode, body["error"])

			challenge := rw.Header().Get(consts.HeaderWWWAuthenticate)

			require.NotEmpty(t, challenge)
			assert.Contains(t, challenge, `algs="ES256"`)

			if tc.challenge != "" {
				assert.Contains(t, challenge, tc.challenge)
			}

			if tc.errCode == "use_dpop_nonce" {
				assert.True(t, strings.HasPrefix(challenge, "DPoP "), challenge)
				assert.NotContains(t, challenge, "Bearer")

				issued := rw.Header().Get(consts.HeaderDPoPNonce)

				require.NotEmpty(t, issued)
				assert.NoError(t, config.DPoPStrategy.ValidateDPoPNonce(context.Background(), issued))
			} else {
				assert.Empty(t, rw.Header().Get(consts.HeaderDPoPNonce))
			}

			// RFC 9449 Section 7.2: only the challenge for the scheme the request used carries the error.
			switch {
			case tc.formBody:
			case strings.EqualFold(tc.scheme, "DPoP"):
				assert.NotContains(t, challenge, `Bearer error=`)
			default:
				assert.NotContains(t, challenge, `DPoP error=`)
			}
		})
	}
}

type userinfoDPoPFixture struct {
	key, other, rsa *jose.JSONWebKey
	jkt             string
	issued          string
	strategy        DPoPStrategy
	jti             int
}

func newUserinfoDPoPFixture(t *testing.T, config *Config) *userinfoDPoPFixture {
	t.Helper()

	newKey := func() *jose.JSONWebKey {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		return &jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}
	}

	f := &userinfoDPoPFixture{
		key:      newKey(),
		other:    newKey(),
		rsa:      &jose.JSONWebKey{Key: gen.MustRSAKey(), Algorithm: string(jose.RS256)},
		strategy: config.DPoPStrategy,
	}

	var err error

	f.jkt, err = jwt.ThumbprintJWK(f.key)
	require.NoError(t, err)

	return f
}

// nonce returns a nonce issued by the server, as a client would receive in a DPoP-Nonce header.
func (f *userinfoDPoPFixture) nonce(t *testing.T) string {
	t.Helper()

	var err error

	f.issued, err = f.strategy.NewDPoPNonce(context.Background())
	require.NoError(t, err)

	return f.issued
}

// proof returns a proof for a GET to the UserInfo endpoint signed by the bound key. A nil override removes the claim.
func (f *userinfoDPoPFixture) proof(t *testing.T, overrides map[string]any) string {
	return f.sign(t, f.key, jose.ES256, overrides)
}

func (f *userinfoDPoPFixture) sign(t *testing.T, key *jose.JSONWebKey, alg jose.SignatureAlgorithm, overrides map[string]any) string {
	t.Helper()

	f.jti++

	claims := map[string]any{
		jwt.ClaimJWTID:                  fmt.Sprintf("userinfo-proof-%d", f.jti),
		jwt.ClaimHTTPMethod:             http.MethodGet,
		jwt.ClaimHTTPURI:                userinfoURL,
		jwt.ClaimIssuedAt:               time.Now().Unix(),
		consts.ClaimDPoPAccessTokenHash: userinfoATH(userinfoToken),
	}

	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	require.NoError(t, err)

	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return raw
}

func userinfoATH(token string) string {
	sum := sha256.Sum256([]byte(token))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
