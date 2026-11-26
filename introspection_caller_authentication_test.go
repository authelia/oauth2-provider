// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestIntrospectionCallerAuthenticationFailureIsNotAnInactiveToken(t *testing.T) {
	const (
		endpoint  = "https://as.example.com/introspect"
		challenge = `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons."`
	)

	stores := []struct {
		name string
		new  func() (introspectionCallerTestStore, *storage.MemoryStore)
	}{
		{"MemoryStore", func() (introspectionCallerTestStore, *storage.MemoryStore) {
			s := storage.NewMemoryStore()

			return s, s
		}},
		{"HydratingMemoryStore", func() (introspectionCallerTestStore, *storage.MemoryStore) {
			s := storage.NewHydratingMemoryStore()

			return s, s.MemoryStore
		}},
	}

	testCases := []struct {
		name       string
		credential string
		token      string
		code       int
		challenge  string
		body       string
	}{
		// RFC 7662 Section 2.3: an invalid bearer credential is answered with HTTP 401 as described in RFC 6750 Section 3.
		{name: "ShouldChallengeARevokedRefreshTokenCredential", credential: "refresh-revoked", token: "access-active", code: http.StatusUnauthorized, challenge: challenge},
		{name: "ShouldChallengeAnActiveRefreshTokenCredential", credential: "refresh-active", token: "access-active", code: http.StatusUnauthorized, challenge: challenge},
		{name: "ShouldChallengeAnExpiredAccessTokenCredential", credential: "access-expired", token: "access-active", code: http.StatusUnauthorized, challenge: challenge},
		{name: "ShouldChallengeAnUnknownCredential", credential: "unknown", token: "access-active", code: http.StatusUnauthorized, challenge: challenge},
		{name: "ShouldChallengeARevokedRefreshTokenCredentialForAnInactiveToken", credential: "refresh-revoked", token: "refresh-revoked-other", code: http.StatusUnauthorized, challenge: challenge},
		// RFC 7662 Section 2.2: a properly authorized query for an inactive token is answered with 'active' set to false.
		{name: "ShouldAnswerAnActiveToken", credential: "access-credential", token: "access-active", code: http.StatusOK, body: `"active":true`},
		{name: "ShouldAnswerARevokedRefreshTokenAsInactive", credential: "access-credential", token: "refresh-revoked", code: http.StatusOK, body: "{\"active\":false}\n"},
		{name: "ShouldAnswerAnExpiredAccessTokenAsInactive", credential: "access-credential", token: "access-expired", code: http.StatusOK, body: "{\"active\":false}\n"},
		{name: "ShouldAnswerAnUnknownTokenAsInactive", credential: "access-credential", token: "unknown", code: http.StatusOK, body: "{\"active\":false}\n"},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ctx := context.Background()

					store, memory := sc.new()

					config := &Config{GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo"), AccessTokenLifespan: time.Hour, RefreshTokenLifespan: time.Hour}
					strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

					config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{
						&hoauth2.CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config},
					}

					provider := &Fosite{Store: memory, Config: config}

					client := &DefaultClient{ID: "rs"}
					memory.Clients[client.ID] = client

					request := func(id string, expires time.Time) *Request {
						r := NewRequest()
						r.ID = id
						r.Client = client
						r.GrantedAudience = Arguments{endpoint}
						r.GrantedScope = Arguments{"authelia:oauth2:token_introspection"}
						r.Session = &DefaultSession{Subject: "user", ExpiresAt: map[TokenType]time.Time{AccessToken: expires, RefreshToken: expires}}

						return r
					}

					access := func(id string, expires time.Time) string {
						r := request(id, expires)

						token, signature, err := strategy.GenerateAccessToken(ctx, r)
						require.NoError(t, err)
						require.NoError(t, store.CreateAccessTokenSession(ctx, signature, r))

						return token
					}

					refresh := func(id string, revoke bool) string {
						r := request(id, time.Now().Add(time.Hour))

						token, signature, err := strategy.GenerateRefreshToken(ctx, r)
						require.NoError(t, err)
						require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, "", r))

						if revoke {
							require.NoError(t, store.RevokeRefreshToken(ctx, id))
						}

						return token
					}

					tokens := map[string]string{
						"access-credential":     access("access-credential", time.Now().Add(time.Hour)),
						"access-active":         access("access-active", time.Now().Add(time.Hour)),
						"access-expired":        access("access-expired", time.Now().Add(-time.Hour)),
						"refresh-active":        refresh("refresh-active", false),
						"refresh-revoked":       refresh("refresh-revoked", true),
						"refresh-revoked-other": refresh("refresh-revoked-other", true),
						"unknown":               "authelia_at_unknown.signature",
					}

					r := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(url.Values{consts.FormParameterToken: {tokens[tc.token]}}.Encode()))
					r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
					r.Header.Set(consts.HeaderAuthorization, "Bearer "+tokens[tc.credential])

					rw := httptest.NewRecorder()

					responder, err := provider.NewIntrospectionRequest(ctx, r, &DefaultSession{})
					if err != nil {
						provider.WriteIntrospectionError(ctx, rw, err)
					} else {
						provider.WriteIntrospectionResponse(ctx, rw, responder)
					}

					assert.Equal(t, tc.code, rw.Code)
					assert.Equal(t, tc.challenge, rw.Header().Get(consts.HeaderWWWAuthenticate))

					switch {
					case tc.challenge != "":
						assert.JSONEq(t, `{"error":"invalid_token","error_description":"The access token provided is expired, revoked, malformed, or invalid for other reasons. HTTP Authorization header missing, malformed, or credentials used are invalid."}`, rw.Body.String())
					case strings.HasPrefix(tc.body, "{"):
						assert.Equal(t, tc.body, rw.Body.String())
					default:
						assert.Contains(t, rw.Body.String(), tc.body)
					}
				})
			}
		})
	}
}

type introspectionCallerTestStore interface {
	hoauth2.CoreStorage

	RevokeRefreshToken(ctx context.Context, requestID string) (err error)
}
