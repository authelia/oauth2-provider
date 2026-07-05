// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// introspectionJWTTestClient is a minimal IntrospectionJWTResponseClient used to exercise the signed
// introspection response code paths.
type introspectionJWTTestClient struct {
	*DefaultClient

	alg, kid       string
	encAlg, encKid string
	encEnc         string
}

func (c *introspectionJWTTestClient) GetIntrospectionSignedResponseKeyID() string {
	return c.kid
}

func (c *introspectionJWTTestClient) GetIntrospectionSignedResponseAlg() string {
	return c.alg
}

func (c *introspectionJWTTestClient) GetIntrospectionEncryptedResponseKeyID() string {
	return c.encKid
}

func (c *introspectionJWTTestClient) GetIntrospectionEncryptedResponseAlg() string {
	return c.encAlg
}

func (c *introspectionJWTTestClient) GetIntrospectionEncryptedResponseEnc() string {
	return c.encEnc
}

// stubIntrospectionStrategy is a jwt.Strategy stub used to drive the signed introspection response
// code paths without setting up a real signing key.
type stubIntrospectionStrategy struct {
	token  string
	err    error
	claims jwt.MapClaims
}

func (s *stubIntrospectionStrategy) Encode(_ context.Context, claims jwt.Claims, _ ...jwt.StrategyOpt) (string, string, error) {
	if mc, ok := claims.(jwt.MapClaims); ok {
		s.claims = mc
	}

	return s.token, "", s.err
}

func (s *stubIntrospectionStrategy) Decrypt(_ context.Context, _ string, _ ...jwt.StrategyOpt) (string, string, *jose.JSONWebEncryption, error) {
	return "", "", nil, nil
}

func (s *stubIntrospectionStrategy) Decode(_ context.Context, _ string, _ ...jwt.StrategyOpt) (*jwt.Token, error) {
	return nil, nil
}

func (s *stubIntrospectionStrategy) Validate(_ context.Context, _ *jwt.Token, _ ...jwt.StrategyOpt) error {
	return nil
}

func TestWriteIntrospectionError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected string
		code     int
		body     string
		headers  http.Header
	}{
		{
			name: "ShouldNotWriteForNilError",
		},
		{
			name:     "ShouldWriteUnauthorizedForErrRequestUnauthorized",
			err:      errorsx.WithStack(ErrRequestUnauthorized),
			expected: "The request could not be authorized. Check that you provided valid credentials in the right format.",
			code:     http.StatusUnauthorized,
			body:     `{"error":"request_unauthorized","error_description":"The request could not be authorized. Check that you provided valid credentials in the right format."}`,
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name:     "ShouldWriteBadRequestForErrInvalidRequest",
			err:      errorsx.WithStack(ErrInvalidRequest),
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
			code:     http.StatusBadRequest,
			body:     `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified."}`,
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name:     "ShouldWriteInactiveForGenericError",
			err:      errors.New("some other error"),
			expected: "some other error",
			code:     http.StatusOK,
			body:     "{\"active\":false}\n",
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name:     "ShouldWriteInactiveForErrInactiveToken",
			err:      errorsx.WithStack(ErrInactiveToken.WithWrap(ErrRequestUnauthorized)),
			expected: "Token is inactive because it is malformed, expired or otherwise invalid. Token validation failed.",
			code:     http.StatusOK,
			body:     "{\"active\":false}\n",
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: new(Config)}
			rw := httptest.NewRecorder()

			provider.WriteIntrospectionError(context.Background(), rw, tc.err)

			if tc.err == nil {
				assert.Equal(t, http.StatusOK, rw.Code)
				assert.Empty(t, rw.Body.String())
				assert.Empty(t, rw.Header())

				return
			}

			actual := ErrorToDebugRFC6749Error(tc.err)
			assert.EqualError(t, actual, tc.expected)

			assert.Equal(t, tc.code, rw.Code)
			assert.Equal(t, tc.body, rw.Body.String())
			assert.Equal(t, tc.headers, rw.Header())
		})
	}
}

func TestWriteIntrospectionResponse(t *testing.T) {
	testCases := []struct {
		name     string
		response *IntrospectionResponse
	}{
		{
			name: "ShouldWriteInactiveResponseWithMock",
			response: &IntrospectionResponse{
				AccessRequester: NewAccessRequest(nil),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := new(Fosite)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			rw := mock.NewMockResponseWriter(ctrl)
			rw.EXPECT().Write(gomock.Any()).AnyTimes()
			rw.EXPECT().Header().AnyTimes().Return(http.Header{})
			rw.EXPECT().WriteHeader(http.StatusOK)

			provider.WriteIntrospectionResponse(context.Background(), rw, tc.response)
		})
	}
}

func TestWriteIntrospectionResponseBody(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(ires *IntrospectionResponse)
		active   bool
		hasExp   bool
		hasExtra bool
	}{
		{
			name: "ShouldSucceedForNotExpiredAccessToken",
			setup: func(ires *IntrospectionResponse) {
				ires.Active = true
				ires.TokenUse = AccessToken
				session := &DefaultSession{}
				session.SetExpiresAt(ires.TokenUse, time.Now().Add(time.Hour*2))
				ires.AccessRequester = NewAccessRequest(session)
			},
			active: true,
			hasExp: true,
		},
		{
			name: "ShouldSucceedForExpiredAccessToken",
			setup: func(ires *IntrospectionResponse) {
				ires.Active = false
				ires.TokenUse = AccessToken
				session := &DefaultSession{}
				session.SetExpiresAt(ires.TokenUse, time.Now().Add(-time.Hour*2))
				ires.AccessRequester = NewAccessRequest(session)
			},
		},
		{
			name: "ShouldSucceedForExpirationTimeNotSetAccessToken",
			setup: func(ires *IntrospectionResponse) {
				ires.Active = true
				ires.TokenUse = AccessToken
				session := &DefaultSession{}
				session.SetExpiresAt(ires.TokenUse, time.Time{})
				ires.AccessRequester = NewAccessRequest(session)
			},
			active: true,
		},
		{
			name: "ShouldOutputExtraClaims",
			setup: func(ires *IntrospectionResponse) {
				ires.Active = true
				ires.TokenUse = AccessToken
				session := &DefaultSession{}
				session.GetExtraClaims()["extra"] = "foobar"
				// We try to set these, but they should be ignored.
				for _, field := range []string{consts.ClaimExpirationTime, consts.ClaimClientIdentifier, consts.ClaimScope, consts.ClaimIssuedAt, consts.ClaimSubject, consts.ClaimAudience, consts.ClaimUsername} {
					session.GetExtraClaims()[field] = "invalid"
				}
				session.SetExpiresAt(ires.TokenUse, time.Time{})
				ires.AccessRequester = NewAccessRequest(session)
			},
			active:   true,
			hasExtra: true,
		},
		{
			name: "ShouldSucceedForNotExpiredRefreshToken",
			setup: func(ires *IntrospectionResponse) {
				ires.Active = true
				ires.TokenUse = RefreshToken
				session := &DefaultSession{}
				session.SetExpiresAt(ires.TokenUse, time.Now().Add(time.Hour*2))
				ires.AccessRequester = NewAccessRequest(session)
			},
			active: true,
			hasExp: true,
		},
		{
			name: "ShouldNotLeakAccessTokenExpWhenIntrospectingRefreshToken",
			setup: func(ires *IntrospectionResponse) {
				ires.Active = true
				ires.TokenUse = RefreshToken
				session := &DefaultSession{}
				// Only the access token expiry is set, the refresh token has none.
				// The introspection response must reflect the refresh token, not leak the access token expiry.
				session.SetExpiresAt(AccessToken, time.Now().Add(time.Hour*2))
				ires.AccessRequester = NewAccessRequest(session)
			},
			active: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := new(Fosite)
			ires := &IntrospectionResponse{}
			rw := httptest.NewRecorder()

			tc.setup(ires)
			provider.WriteIntrospectionResponse(context.Background(), rw, ires)

			var params struct {
				Active   bool   `json:"active"`
				Exp      *int64 `json:"exp"`
				Iat      *int64 `json:"iat"`
				Extra    string `json:"extra"`
				ClientId string `json:"client_id"`
				Scope    string `json:"scope"`
				Subject  string `json:"sub"`
				Audience string `json:"aud"`
				Username string `json:"username"`
			}

			assert.Equal(t, http.StatusOK, rw.Code)
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
			assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
			assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))

			require.NoError(t, json.NewDecoder(rw.Body).Decode(&params))
			assert.Equal(t, tc.active, params.Active)

			if !tc.active {
				return
			}

			assert.NotNil(t, params.Iat)

			if tc.hasExp {
				assert.NotNil(t, params.Exp)
			} else {
				assert.Nil(t, params.Exp)
			}

			if tc.hasExtra {
				assert.Equal(t, "foobar", params.Extra)
			} else {
				assert.Empty(t, params.Extra)
			}

			assert.NotEqual(t, "invalid", params.Exp)
			assert.NotEqual(t, "invalid", params.ClientId)
			assert.NotEqual(t, "invalid", params.Scope)
			assert.NotEqual(t, "invalid", params.Iat)
			assert.NotEqual(t, "invalid", params.Subject)
			assert.NotEqual(t, "invalid", params.Audience)
			assert.NotEqual(t, "invalid", params.Username)
		})
	}
}

func TestWriteIntrospectionResponseBodyExpiryMatchesTokenUse(t *testing.T) {
	accessExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
	refreshExpiry := time.Now().Add(time.Hour * 24).Truncate(time.Second)

	testCases := []struct {
		name     string
		tokenUse TokenUse
		expected int64
	}{
		{
			name:     "ShouldReturnAccessTokenExpiryForAccessTokenIntrospection",
			tokenUse: AccessToken,
			expected: accessExpiry.Unix(),
		},
		{
			name:     "ShouldReturnRefreshTokenExpiryForRefreshTokenIntrospection",
			tokenUse: RefreshToken,
			expected: refreshExpiry.Unix(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := new(Fosite)

			session := &DefaultSession{}
			session.SetExpiresAt(AccessToken, accessExpiry)
			session.SetExpiresAt(RefreshToken, refreshExpiry)

			ires := &IntrospectionResponse{
				Active:          true,
				TokenUse:        tc.tokenUse,
				AccessRequester: NewAccessRequest(session),
			}

			rw := httptest.NewRecorder()
			provider.WriteIntrospectionResponse(context.Background(), rw, ires)

			var params struct {
				Exp *int64 `json:"exp"`
			}

			require.NoError(t, json.NewDecoder(rw.Body).Decode(&params))
			require.NotNil(t, params.Exp)
			assert.Equal(t, tc.expected, *params.Exp)
		})
	}
}

func TestWriteIntrospectionResponseBodyPopulatesClaims(t *testing.T) {
	testCases := []struct {
		name  string
		setup func() *IntrospectionResponse
		check func(t *testing.T, params map[string]any)
	}{
		{
			name: "ShouldReturnInactiveOnlyWhenNotActive",
			setup: func() *IntrospectionResponse {
				return &IntrospectionResponse{
					Active:          false,
					AccessRequester: NewAccessRequest(&DefaultSession{Subject: "alice", Username: "alice@example"}),
				}
			},
			check: func(t *testing.T, params map[string]any) {
				assert.Equal(t, false, params[consts.ClaimActive])
				assert.NotContains(t, params, consts.ClaimSubject)
				assert.NotContains(t, params, consts.ClaimUsername)
				assert.NotContains(t, params, consts.ClaimClientIdentifier)
				assert.NotContains(t, params, consts.ClaimScope)
				assert.NotContains(t, params, consts.ClaimAudience)
			},
		},
		{
			name: "ShouldPopulateAllStandardClaims",
			setup: func() *IntrospectionResponse {
				session := &DefaultSession{
					Subject:  "user-123",
					Username: "alice@example.com",
				}

				ar := NewAccessRequest(session)
				ar.Client = &DefaultClient{ID: "client-id"}
				ar.GrantedScope = Arguments{"openid", "profile"}
				ar.GrantedAudience = Arguments{"aud-1", "aud-2"}

				return &IntrospectionResponse{
					Active:          true,
					TokenUse:        AccessToken,
					AccessRequester: ar,
				}
			},
			check: func(t *testing.T, params map[string]any) {
				assert.Equal(t, true, params[consts.ClaimActive])
				assert.Equal(t, "client-id", params[consts.ClaimClientIdentifier])
				assert.Equal(t, "openid profile", params[consts.ClaimScope])
				assert.Equal(t, "user-123", params[consts.ClaimSubject])
				assert.Equal(t, "alice@example.com", params[consts.ClaimUsername])
				assert.ElementsMatch(t, []any{"aud-1", "aud-2"}, params[consts.ClaimAudience])
				assert.Contains(t, params, consts.ClaimIssuedAt)
			},
		},
		{
			name: "ShouldNotPopulateOptionalClaimsWhenUnset",
			setup: func() *IntrospectionResponse {
				ar := NewAccessRequest(&DefaultSession{})
				ar.Client = &DefaultClient{}

				return &IntrospectionResponse{
					Active:          true,
					TokenUse:        AccessToken,
					AccessRequester: ar,
				}
			},
			check: func(t *testing.T, params map[string]any) {
				assert.Equal(t, true, params[consts.ClaimActive])
				assert.NotContains(t, params, consts.ClaimClientIdentifier)
				assert.NotContains(t, params, consts.ClaimScope)
				assert.NotContains(t, params, consts.ClaimSubject)
				assert.NotContains(t, params, consts.ClaimUsername)
				assert.NotContains(t, params, consts.ClaimAudience)
				assert.NotContains(t, params, consts.ClaimExpirationTime)
			},
		},
		{
			name: "ShouldOmitIssuedAtWhenRequestedAtIsZero",
			setup: func() *IntrospectionResponse {
				ar := NewAccessRequest(&DefaultSession{})
				ar.SetRequestedAt(time.Time{})

				return &IntrospectionResponse{
					Active:          true,
					TokenUse:        AccessToken,
					AccessRequester: ar,
				}
			},
			check: func(t *testing.T, params map[string]any) {
				assert.Equal(t, true, params[consts.ClaimActive])
				assert.NotContains(t, params, consts.ClaimIssuedAt)
			},
		},
		{
			name: "ShouldPopulateCnfWhenDPoPBound",
			setup: func() *IntrospectionResponse {
				session := &DefaultSession{Subject: "user-123"}
				session.SetDPoPJWKThumbprint("test-jkt")

				ar := NewAccessRequest(session)
				ar.Client = &DefaultClient{ID: "client-id"}

				return &IntrospectionResponse{
					Active:          true,
					TokenUse:        AccessToken,
					AccessRequester: ar,
				}
			},
			check: func(t *testing.T, params map[string]any) {
				assert.Equal(t, true, params[consts.ClaimActive])
				cnf, ok := params[jwt.ClaimConfirmation].(map[string]any)
				require.True(t, ok, "expected cnf claim to be present and a map, got %#v", params[jwt.ClaimConfirmation])
				assert.Equal(t, "test-jkt", cnf[jwt.ClaimConfirmationJWKThumbprint])
			},
		},
		{
			name: "ShouldNotPopulateCnfWhenNotDPoPBound",
			setup: func() *IntrospectionResponse {
				ar := NewAccessRequest(&DefaultSession{Subject: "user-123"})
				ar.Client = &DefaultClient{ID: "client-id"}

				return &IntrospectionResponse{
					Active:          true,
					TokenUse:        AccessToken,
					AccessRequester: ar,
				}
			},
			check: func(t *testing.T, params map[string]any) {
				assert.Equal(t, true, params[consts.ClaimActive])
				assert.NotContains(t, params, jwt.ClaimConfirmation)
			},
		},
		{
			name: "ShouldNotAllowExtraClaimsToForgeCnf",
			setup: func() *IntrospectionResponse {
				// A session that is not DPoP-bound but happens to carry an extra claim literally named "cnf" must
				// not be able to smuggle an unvalidated confirmation claim into the introspection response.
				session := &DefaultSession{Subject: "user-123"}
				session.GetExtraClaims()[jwt.ClaimConfirmation] = map[string]any{jwt.ClaimConfirmationJWKThumbprint: "forged-jkt"}

				ar := NewAccessRequest(session)
				ar.Client = &DefaultClient{ID: "client-id"}

				return &IntrospectionResponse{
					Active:          true,
					TokenUse:        AccessToken,
					AccessRequester: ar,
				}
			},
			check: func(t *testing.T, params map[string]any) {
				assert.Equal(t, true, params[consts.ClaimActive])
				assert.NotContains(t, params, jwt.ClaimConfirmation)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := new(Fosite)
			rw := httptest.NewRecorder()

			provider.WriteIntrospectionResponse(context.Background(), rw, tc.setup())

			assert.Equal(t, http.StatusOK, rw.Code)

			params := map[string]any{}
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&params))

			tc.check(t, params)
		})
	}
}

func TestWriteIntrospectionResponseJWT(t *testing.T) {
	testCases := []struct {
		name        string
		alg         string
		kid         string
		strategy    *stubIntrospectionStrategy
		active      bool
		expectCode  int
		contentType string
		body        string
		checkClaims func(t *testing.T, claims jwt.MapClaims)
	}{
		{
			name:        "ShouldWriteSignedIntrospectionJWTWithAlg",
			alg:         "RS256",
			strategy:    &stubIntrospectionStrategy{token: "signed.jwt.token"},
			active:      true,
			expectCode:  http.StatusOK,
			contentType: consts.ContentTypeApplicationTokenIntrospectionJWT,
			body:        "signed.jwt.token",
			checkClaims: func(t *testing.T, claims jwt.MapClaims) {
				assert.Equal(t, "https://issuer.example.com", claims[consts.ClaimIssuer])
				assert.Contains(t, claims, consts.ClaimJWTID)
				assert.Contains(t, claims, consts.ClaimIssuedAt)

				intro, ok := claims[consts.ClaimTokenIntrospection].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, true, intro[consts.ClaimActive])
				assert.Equal(t, "jwt-client", intro[consts.ClaimClientIdentifier])
				assert.Equal(t, []string{"jwt-client"}, claims[consts.ClaimAudience])
			},
		},
		{
			name:        "ShouldWriteSignedIntrospectionJWTWithKidOnly",
			kid:         "key-id-1",
			strategy:    &stubIntrospectionStrategy{token: "signed-with-kid"},
			active:      true,
			expectCode:  http.StatusOK,
			contentType: consts.ContentTypeApplicationTokenIntrospectionJWT,
			body:        "signed-with-kid",
		},
		{
			name:        "ShouldWriteInactiveSignedJWT",
			alg:         "RS256",
			strategy:    &stubIntrospectionStrategy{token: "inactive.jwt"},
			active:      false,
			expectCode:  http.StatusOK,
			contentType: consts.ContentTypeApplicationTokenIntrospectionJWT,
			body:        "inactive.jwt",
			checkClaims: func(t *testing.T, claims jwt.MapClaims) {
				intro, ok := claims[consts.ClaimTokenIntrospection].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, false, intro[consts.ClaimActive])
			},
		},
		{
			name:        "ShouldFallbackToJSONWhenAlgIsNone",
			alg:         jwt.JSONWebTokenAlgNone,
			strategy:    &stubIntrospectionStrategy{token: "should-not-be-used"},
			active:      true,
			expectCode:  http.StatusOK,
			contentType: consts.ContentTypeApplicationJSON,
		},
		{
			name:        "ShouldFallbackToJSONWhenAlgIsNoneWithKid",
			alg:         jwt.JSONWebTokenAlgNone,
			kid:         "key-id-2",
			strategy:    &stubIntrospectionStrategy{token: "should-not-be-used"},
			active:      true,
			expectCode:  http.StatusOK,
			contentType: consts.ContentTypeApplicationJSON,
		},
		{
			name:        "ShouldWriteInactiveWhenStrategyIsNil",
			alg:         "RS256",
			strategy:    nil,
			active:      true,
			expectCode:  http.StatusOK,
			contentType: consts.ContentTypeApplicationJSON,
			body:        "{\"active\":false}\n",
		},
		{
			name:        "ShouldWriteInactiveWhenStrategyEncodeErrors",
			alg:         "RS256",
			strategy:    &stubIntrospectionStrategy{err: errors.New("signing failed")},
			active:      true,
			expectCode:  http.StatusOK,
			contentType: consts.ContentTypeApplicationJSON,
			body:        "{\"active\":false}\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{IntrospectionIssuer: "https://issuer.example.com"}
			if tc.strategy != nil {
				config.IntrospectionJWTResponseStrategy = tc.strategy
			}

			provider := &Fosite{Config: config}

			client := &introspectionJWTTestClient{
				DefaultClient: &DefaultClient{ID: "jwt-client"},
				alg:           tc.alg,
				kid:           tc.kid,
			}

			session := &DefaultSession{Subject: "subject"}
			session.SetExpiresAt(AccessToken, time.Now().Add(time.Hour))

			ar := NewAccessRequest(session)
			ar.Client = client
			ar.GrantedScope = Arguments{"read"}

			ires := &IntrospectionResponse{
				Client:          client,
				Active:          tc.active,
				TokenUse:        AccessToken,
				AccessRequester: ar,
			}

			rw := httptest.NewRecorder()
			provider.WriteIntrospectionResponse(context.Background(), rw, ires)

			assert.Equal(t, tc.expectCode, rw.Code)
			assert.Equal(t, tc.contentType, rw.Header().Get(consts.HeaderContentType))
			assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
			assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))

			if tc.body != "" {
				assert.Equal(t, tc.body, rw.Body.String())
			}

			if tc.checkClaims != nil {
				require.NotNil(t, tc.strategy)
				tc.checkClaims(t, tc.strategy.claims)
			}
		})
	}
}
