// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
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
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestWriteIntrospectionErrorClassification(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		code     int
		contains string
	}{
		{name: "ShouldReportTemporarilyUnavailable", err: errorsx.WithStack(ErrTemporarilyUnavailable), code: http.StatusServiceUnavailable, contains: `"error":"temporarily_unavailable"`},
		{name: "ShouldReportTemporarilyUnavailableWrappingAnInactiveToken", err: errorsx.WithStack(ErrTemporarilyUnavailable.WithWrap(ErrInactiveToken)), code: http.StatusServiceUnavailable, contains: `"error":"temporarily_unavailable"`},
		{name: "ShouldReportMisconfiguration", err: errorsx.WithStack(ErrMisconfiguration), code: http.StatusInternalServerError, contains: `"error":"misconfiguration"`},
		{name: "ShouldReportServerError", err: errorsx.WithStack(ErrServerError), code: http.StatusInternalServerError, contains: `"error":"server_error"`},
		{name: "ShouldReportTooManyRequests", err: errorsx.WithStack(ErrTooManyRequests), code: http.StatusTooManyRequests, contains: `"error":"too_many_requests"`},
		// RFC 7662 Section 2.3: an inactive or otherwise invalid token is not an error response.
		{name: "ShouldAnswerInactiveForErrInactiveToken", err: errorsx.WithStack(ErrInactiveToken), code: http.StatusOK, contains: `{"active":false}`},
		{name: "ShouldAnswerInactiveForErrNotFound", err: errorsx.WithStack(ErrNotFound), code: http.StatusOK, contains: `{"active":false}`},
		{name: "ShouldAnswerInactiveForErrTokenSignatureMismatch", err: errorsx.WithStack(ErrTokenSignatureMismatch), code: http.StatusOK, contains: `{"active":false}`},
		{name: "ShouldAnswerInactiveForErrInvalidTokenFormat", err: errorsx.WithStack(ErrInvalidTokenFormat), code: http.StatusOK, contains: `{"active":false}`},
		{name: "ShouldAnswerInactiveForErrUnknownRequest", err: errorsx.WithStack(ErrUnknownRequest), code: http.StatusOK, contains: `{"active":false}`},
		{name: "ShouldAnswerInactiveForErrInvalidGrant", err: errorsx.WithStack(ErrInvalidGrant), code: http.StatusOK, contains: `{"active":false}`},
		{name: "ShouldAnswerInactiveForErrAccessDenied", err: errorsx.WithStack(ErrAccessDenied), code: http.StatusOK, contains: `{"active":false}`},
		{name: "ShouldAnswerInactiveForErrInactiveTokenWrappingTemporarilyUnavailable", err: errorsx.WithStack(ErrInactiveToken.WithWrap(ErrTemporarilyUnavailable)), code: http.StatusOK, contains: `{"active":false}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()

			(&Fosite{Config: &Config{}}).WriteIntrospectionError(context.Background(), rw, tc.err)

			assert.Equal(t, tc.code, rw.Code)
			assert.Contains(t, rw.Body.String(), tc.contains)
			assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))

			if tc.code != http.StatusOK {
				assert.NotContains(t, rw.Body.String(), `"active"`)
			}
		})
	}
}

func TestIntrospectionBearerCallerRejection(t *testing.T) {
	const (
		endpoint = "https://as.example.com/introspect"
		failed   = `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons."`
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
		name         string
		credential   string
		transmission string
		unregistered bool
		lookup       error
		enforce      bool
		disabled     bool
		code         int
		challenge    string
		contains     string
	}{
		{name: "ShouldAnswerARegisteredCaller", credential: "caller", code: http.StatusOK, contains: `"active":true`},
		{name: "ShouldAnswerARegisteredCallerUsingTheFormBody", credential: "caller", transmission: "body", code: http.StatusOK, contains: `"active":true`},
		// RFC 7662 Section 2.3: a bearer token which is invalid for the request is answered as described in RFC 6750 Section 3.
		{name: "ShouldChallengeACredentialOfAnUnregisteredClient", credential: "caller", unregistered: true, code: http.StatusUnauthorized, challenge: failed, contains: `"error":"invalid_token"`},
		{name: "ShouldChallengeACredentialOfAnUnregisteredClientInTheFormBody", credential: "caller", transmission: "body", unregistered: true, code: http.StatusUnauthorized, challenge: failed, contains: `"error":"invalid_token"`},
		{name: "ShouldChallengeACredentialOfAClientNotPermitted", credential: "caller", enforce: true, code: http.StatusUnauthorized, challenge: failed, contains: `"error":"invalid_token"`},
		{name: "ShouldChallengeAnUnknownCredentialInTheHeader", credential: "unknown", code: http.StatusUnauthorized, challenge: failed, contains: `"error":"invalid_token"`},
		{name: "ShouldChallengeAnUnknownCredentialInTheFormBody", credential: "unknown", transmission: "body", code: http.StatusUnauthorized, challenge: failed, contains: `"error":"invalid_token"`},
		{name: "ShouldChallengeAnExpiredCredentialInTheFormBody", credential: "expired", transmission: "body", code: http.StatusUnauthorized, challenge: failed, contains: `"error":"invalid_token"`},
		// RFC 6750 Section 3.1: a request lacking any authentication information carries no error information.
		{name: "ShouldChallengeWithoutErrorWhenNoCredentialIsPresented", transmission: "none", disabled: true, code: http.StatusUnauthorized, challenge: `Bearer`, contains: `"error":"invalid_token"`},
		{name: "ShouldReportAnUnavailableClientStore", credential: "caller", lookup: errorsx.WithStack(ErrTemporarilyUnavailable), code: http.StatusServiceUnavailable, contains: `"error":"temporarily_unavailable"`},
		{name: "ShouldReportAnUnavailableClientStoreForAFormBodyCredential", credential: "caller", transmission: "body", lookup: errorsx.WithStack(ErrTemporarilyUnavailable), code: http.StatusServiceUnavailable, contains: `"error":"temporarily_unavailable"`},
		{name: "ShouldReportAClientStoreServerError", credential: "caller", lookup: errorsx.WithStack(ErrServerError), code: http.StatusInternalServerError, contains: `"error":"server_error"`},
		{name: "ShouldReportAPlainClientStoreFailureAsAServerError", credential: "caller", lookup: errors.New("the store failed"), code: http.StatusInternalServerError, contains: `"error":"server_error"`},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ctx := context.Background()

					store, memory := sc.new()

					config := &Config{
						GlobalSecret:                            []byte("foofoofoofoofoofoofoofoofoofoofoo"),
						AccessTokenLifespan:                     time.Hour,
						EnforceIntrospectionPermission:          tc.enforce,
						IntrospectionEndpointClientAuthDisabled: tc.disabled,
					}

					strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

					config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{
						&hoauth2.CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config},
					}

					provider := &Fosite{Store: memory, Config: config}

					client := &DefaultClient{ID: "rs"}
					memory.Clients[client.ID] = client

					access := func(id string, expires time.Time) string {
						r := NewRequest()
						r.ID = id
						r.Client = client
						r.GrantedAudience = Arguments{endpoint}
						r.GrantedScope = Arguments{"authelia:oauth2:token_introspection"}
						r.Session = &DefaultSession{Subject: "user", ExpiresAt: map[TokenType]time.Time{AccessToken: expires}}

						token, signature, err := strategy.GenerateAccessToken(ctx, r)
						require.NoError(t, err)
						require.NoError(t, store.CreateAccessTokenSession(ctx, signature, r))

						return token
					}

					tokens := map[string]string{
						"caller":       access("caller", time.Now().Add(time.Hour)),
						"expired":      access("expired", time.Now().Add(-time.Hour)),
						"introspected": access("introspected", time.Now().Add(time.Hour)),
						"unknown":      "authelia_at_unknown.signature",
					}

					if tc.unregistered {
						delete(memory.Clients, client.ID)
					}

					if tc.lookup != nil {
						provider.Store = &userinfoFailingClientStore{MemoryStore: memory, err: tc.lookup}
					}

					form := url.Values{consts.FormParameterToken: {tokens["introspected"]}}

					if tc.transmission == "body" {
						form.Set(consts.FormParameterAccessToken, tokens[tc.credential])
					}

					r := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
					r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")

					if tc.transmission == "" {
						r.Header.Set(consts.HeaderAuthorization, "Bearer "+tokens[tc.credential])
					}

					rw := httptest.NewRecorder()

					responder, err := provider.NewIntrospectionRequest(ctx, r, &DefaultSession{})
					if err != nil {
						provider.WriteIntrospectionError(context.WithValue(ctx, RequestContextKey, r), rw, err)
					} else {
						provider.WriteIntrospectionResponse(ctx, rw, responder)
					}

					assert.Equal(t, tc.code, rw.Code)
					assert.Equal(t, tc.challenge, rw.Header().Get(consts.HeaderWWWAuthenticate))
					assert.Contains(t, rw.Body.String(), tc.contains)

					if tc.code != http.StatusOK {
						assert.NotContains(t, rw.Body.String(), `"active"`)
					}
				})
			}
		})
	}
}

func TestIntrospectionBearerCallerIntrospectorFailure(t *testing.T) {
	testCases := []struct {
		name     string
		failure  error
		code     int
		contains string
	}{
		{name: "ShouldReportATemporarilyUnavailableIntrospector", failure: errorsx.WithStack(ErrTemporarilyUnavailable), code: http.StatusServiceUnavailable, contains: `"error":"temporarily_unavailable"`},
		{name: "ShouldReportAMisconfiguredIntrospector", failure: errorsx.WithStack(ErrMisconfiguration), code: http.StatusInternalServerError, contains: `"error":"misconfiguration"`},
		{name: "ShouldReportAnIntrospectorServerError", failure: errorsx.WithStack(ErrServerError), code: http.StatusInternalServerError, contains: `"error":"server_error"`},
	}

	for _, tc := range testCases {
		for _, bearer := range []bool{false, true} {
			name := tc.name + "ForTheToken"
			if bearer {
				name = tc.name + "ForTheCredential"
			}

			t.Run(name, func(t *testing.T) {
				const secret = "foobarfoobarfoobarfoobarfoobar12"

				store := storage.NewMemoryStore()
				store.Clients["rs"] = &DefaultClient{ID: "rs", ClientSecret: NewPlainTextClientSecret(secret)}

				provider := &Fosite{Store: store, Config: &Config{TokenIntrospectionHandlers: TokenIntrospectionHandlers{&fixedIntrospector{failure: tc.failure}}}}

				r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {"token"}}.Encode()))
				r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")

				if bearer {
					r.Header.Set(consts.HeaderAuthorization, "Bearer credential")
				} else {
					r.SetBasicAuth("rs", secret)
				}

				rw := httptest.NewRecorder()

				_, err := provider.NewIntrospectionRequest(context.Background(), r, &DefaultSession{})
				require.Error(t, err)

				provider.WriteIntrospectionError(context.Background(), rw, err)

				assert.Equal(t, tc.code, rw.Code)
				assert.Contains(t, rw.Body.String(), tc.contains)
				assert.NotContains(t, rw.Body.String(), `"active"`)
				assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
			})
		}
	}
}

func TestIntrospectionClientAuthenticationFailure(t *testing.T) {
	const basic = `Basic realm="oauth2"`

	testCases := []struct {
		name      string
		failure   error
		code      int
		challenge string
		contains  string
	}{
		// RFC 7662 Section 2.3: invalid client credentials are answered as described in RFC 6749 Section 5.2.
		{name: "ShouldReportInvalidClient", failure: errorsx.WithStack(ErrInvalidClient), code: http.StatusUnauthorized, challenge: basic, contains: `"error":"invalid_client"`},
		{name: "ShouldReportAnotherRejectionAsInvalidClient", failure: errorsx.WithStack(ErrAccessDenied), code: http.StatusUnauthorized, challenge: basic, contains: `"error":"invalid_client"`},
		{name: "ShouldReportInvalidRequest", failure: errorsx.WithStack(ErrInvalidRequest), code: http.StatusBadRequest, contains: `"error":"invalid_request"`},
		{name: "ShouldReportAServerError", failure: errorsx.WithStack(ErrServerError), code: http.StatusInternalServerError, contains: `"error":"server_error"`},
		{name: "ShouldReportTemporarilyUnavailable", failure: errorsx.WithStack(ErrTemporarilyUnavailable), code: http.StatusServiceUnavailable, contains: `"error":"temporarily_unavailable"`},
		{name: "ShouldReportAPlainFailureAsAServerError", failure: errors.New("the store failed"), code: http.StatusInternalServerError, contains: `"error":"server_error"`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Store: storage.NewMemoryStore(), Config: &Config{ClientAuthenticationStrategy: &failingClientAuthenticationStrategy{err: tc.failure}}}

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {"token"}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.SetBasicAuth("rs", "secret")

			rw := httptest.NewRecorder()

			_, err := provider.NewIntrospectionRequest(context.Background(), r, &DefaultSession{})
			require.Error(t, err)

			provider.WriteIntrospectionError(context.Background(), rw, err)

			assert.Equal(t, tc.code, rw.Code)
			assert.Equal(t, tc.challenge, rw.Header().Get(consts.HeaderWWWAuthenticate))
			assert.Contains(t, rw.Body.String(), tc.contains)
			assert.NotContains(t, rw.Body.String(), `"active"`)
		})
	}
}

func TestIntrospectionClientAuthenticationMultipleMethods(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobarfoobar12"

	store := storage.NewMemoryStore()
	store.Clients["rs"] = &DefaultClient{ID: "rs", ClientSecret: NewPlainTextClientSecret(secret)}

	provider := &Fosite{Store: store, Config: &Config{}}

	form := url.Values{consts.FormParameterToken: {"token"}, consts.FormParameterClientID: {"rs"}, consts.FormParameterClientSecret: {secret}}

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
	r.SetBasicAuth("rs", secret)

	rw := httptest.NewRecorder()

	_, err := provider.NewIntrospectionRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	provider.WriteIntrospectionError(context.Background(), rw, err)

	// RFC 6749 Section 5.2: a request which "utilizes more than one mechanism for authenticating the client" is invalid_request.
	assert.Equal(t, http.StatusBadRequest, rw.Code)
	assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`)
	assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
}

type failingClientAuthenticationStrategy struct {
	err error
}

func (s *failingClientAuthenticationStrategy) AuthMethodsSupported(_ context.Context) (methods []string) {
	return []string{consts.ClientAuthMethodClientSecretBasic}
}

func (s *failingClientAuthenticationStrategy) AuthenticateClient(_ context.Context, _ *http.Request, _ url.Values, _ EndpointClientAuthStrategy) (client Client, method string, err error) {
	return nil, "", s.err
}
