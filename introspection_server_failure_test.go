// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
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

	. "authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestIntrospectorErrorClassification(t *testing.T) {
	const (
		rejected = http.StatusUnauthorized
		inactive = http.StatusOK
	)

	testCases := []struct {
		name string
		err  error

		// status is the HTTP status of a server failure or rate limit, and zero for a rejection of the token.
		status int
		field  string
	}{
		{name: "ShouldReportAPlainError", err: errors.New("db down"), status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportAJoinedPlainError", err: errors.Join(errors.New("db down"), errors.New("db down again")), status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportAnExceededDeadline", err: context.DeadlineExceeded, status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportACancellation", err: context.Canceled, status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportAnUnnamedServerFailure", err: &RFC6749Error{ErrorField: "error", CodeField: http.StatusServiceUnavailable}, status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportAnUnnamedRateLimit", err: &RFC6749Error{ErrorField: "error", CodeField: http.StatusTooManyRequests}, status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportAServerFailureWithAnEmptyName", err: &RFC6749Error{CodeField: http.StatusInternalServerError}, status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportANamedServerFailure", err: &RFC6749Error{ErrorField: "custom_failure", CodeField: http.StatusInternalServerError}, status: http.StatusInternalServerError, field: "custom_failure"},
		{name: "ShouldReportAServerFailureWrappingAnInvalidToken", err: errorsx.WithStack(ErrServerError.WithWrap(ErrInvalidToken)), status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportServerError", err: errorsx.WithStack(ErrServerError), status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldReportTemporarilyUnavailable", err: errorsx.WithStack(ErrTemporarilyUnavailable), status: http.StatusServiceUnavailable, field: "temporarily_unavailable"},
		{name: "ShouldReportAValueTemporarilyUnavailable", err: *ErrTemporarilyUnavailable, status: http.StatusServiceUnavailable, field: "temporarily_unavailable"},
		{name: "ShouldReportAWrappedTemporarilyUnavailable", err: fmt.Errorf("lookup: %w", *ErrTemporarilyUnavailable), status: http.StatusServiceUnavailable, field: "temporarily_unavailable"},
		{name: "ShouldReportTooManyRequests", err: errorsx.WithStack(ErrTooManyRequests), status: http.StatusTooManyRequests, field: "too_many_requests"},
		{name: "ShouldRejectAnExpiredToken", err: errorsx.WithStack(ErrTokenExpired)},
		{name: "ShouldRejectAnInactiveToken", err: errorsx.WithStack(ErrInactiveToken)},
		{name: "ShouldRejectAnUnknownToken", err: errorsx.WithStack(ErrNotFound)},
		{name: "ShouldRejectAMalformedToken", err: errorsx.WithStack(ErrInvalidTokenFormat)},
		{name: "ShouldRejectATokenNoIntrospectorResolves", err: errorsx.WithStack(ErrUnknownRequest)},
	}

	endpoints := []struct {
		name     string
		rejected int
		field    string
		do       func(t *testing.T, provider *Fosite, token string) *httptest.ResponseRecorder
	}{
		{name: "IntrospectedToken", rejected: inactive, do: introspectorErrorTestIntrospectedToken},
		{name: "IntrospectionCredential", rejected: rejected, field: "invalid_token", do: introspectorErrorTestIntrospectionCredential},
		{name: "UserInfo", rejected: rejected, field: "invalid_token", do: introspectorErrorTestUserInfo},
		{name: "SSF", rejected: rejected, field: "invalid_token", do: introspectorErrorTestSSF},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					provider, _ := newIntrospectorErrorTestProvider()

					provider.Config.(*Config).TokenIntrospectionHandlers = TokenIntrospectionHandlers{&introspectorErrorTestIntrospector{token: introspectorErrorTestToken, err: tc.err}}

					rw := endpoint.do(t, provider, introspectorErrorTestToken)

					if tc.status != 0 {
						assert.Equal(t, tc.status, rw.Code)
						assert.Contains(t, rw.Body.String(), `"error":"`+tc.field+`"`)
						assert.NotContains(t, rw.Body.String(), `"active"`)
						assert.NotContains(t, rw.Body.String(), "db down")
						assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))

						return
					}

					assert.Equal(t, endpoint.rejected, rw.Code)

					if endpoint.field == "" {
						assert.JSONEq(t, `{"active":false}`, rw.Body.String())
					} else {
						assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `error="`+endpoint.field+`"`)
					}
				})
			}
		})
	}
}

func TestCoreValidatorErrorClassification(t *testing.T) {
	endpoints := []struct {
		name     string
		rejected int
		do       func(t *testing.T, provider *Fosite, token string) *httptest.ResponseRecorder
	}{
		{name: "IntrospectedToken", rejected: http.StatusOK, do: introspectorErrorTestIntrospectedToken},
		{name: "IntrospectionCredential", rejected: http.StatusUnauthorized, do: introspectorErrorTestIntrospectionCredential},
		{name: "UserInfo", rejected: http.StatusUnauthorized, do: introspectorErrorTestUserInfo},
		{name: "SSF", rejected: http.StatusUnauthorized, do: introspectorErrorTestSSF},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			t.Run("ShouldRejectAStoredTokenWithAMalformedKey", func(t *testing.T) {
				provider, token := newIntrospectorErrorTestCoreProvider(t)

				rw := endpoint.do(t, provider, "authelia_at_!!!!."+strings.SplitN(token, ".", 2)[1])

				assert.Equal(t, endpoint.rejected, rw.Code)
				assert.NotContains(t, rw.Body.String(), "server_error")
			})

			t.Run("ShouldReportARateLimitedStore", func(t *testing.T) {
				provider, token := newIntrospectorErrorTestCoreProvider(t)

				config := provider.Config.(*Config)
				core := config.TokenIntrospectionHandlers[0].(*hoauth2.CoreValidator)
				core.CoreStorage = &introspectorErrorTestFailingStore{CoreStorage: core.CoreStorage, err: errorsx.WithStack(ErrTooManyRequests)}

				rw := endpoint.do(t, provider, token)

				assert.Equal(t, http.StatusTooManyRequests, rw.Code)
				assert.Contains(t, rw.Body.String(), `"error":"too_many_requests"`)
				assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
			})

			t.Run("ShouldReportAMissingGlobalSecret", func(t *testing.T) {
				provider, token := newIntrospectorErrorTestCoreProvider(t)

				provider.Config.(*Config).GlobalSecret = nil

				rw := endpoint.do(t, provider, token)

				assert.Equal(t, http.StatusInternalServerError, rw.Code)
				assert.Contains(t, rw.Body.String(), `"error":"server_error"`)
				assert.NotContains(t, rw.Body.String(), `"active"`)
				assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
			})
		})
	}
}

func TestIntrospectionServerFailure(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		ok       bool
		expected *RFC6749Error
	}{
		{name: "ShouldNotReportNil", err: nil},
		{name: "ShouldReportAPlainErrorAsServerError", err: errors.New("db down"), ok: true, expected: ErrServerError},
		{name: "ShouldReportACancellationAsServerError", err: context.Canceled, ok: true, expected: ErrServerError},
		{name: "ShouldReportAnUnnamedServerFailureAsServerError", err: ErrorToRFC6749Error(errors.New("db down")), ok: true, expected: ErrServerError},
		{name: "ShouldReportAnUnnamedRateLimitAsServerError", err: &RFC6749Error{ErrorField: "error", CodeField: http.StatusTooManyRequests}, ok: true, expected: ErrServerError},
		{name: "ShouldReportAServerFailureWithAnEmptyNameAsServerError", err: &RFC6749Error{CodeField: http.StatusServiceUnavailable}, ok: true, expected: ErrServerError},
		{name: "ShouldReportTemporarilyUnavailable", err: ErrTemporarilyUnavailable, ok: true, expected: ErrTemporarilyUnavailable},
		{name: "ShouldReportAValueTemporarilyUnavailable", err: *ErrTemporarilyUnavailable, ok: true, expected: ErrTemporarilyUnavailable},
		{name: "ShouldReportAWrappedTemporarilyUnavailable", err: fmt.Errorf("lookup: %w", *ErrTemporarilyUnavailable), ok: true, expected: ErrTemporarilyUnavailable},
		{name: "ShouldReportTooManyRequests", err: errorsx.WithStack(ErrTooManyRequests), ok: true, expected: ErrTooManyRequests},
		{name: "ShouldReportAServerFailureWrappingARejection", err: ErrServerError.WithWrap(ErrInactiveToken), ok: true, expected: ErrServerError},
		{name: "ShouldNotReportARejectionWrappingAServerFailure", err: ErrInactiveToken.WithWrap(ErrTemporarilyUnavailable)},
		{name: "ShouldNotReportAnExpiredToken", err: errorsx.WithStack(ErrTokenExpired)},
		{name: "ShouldNotReportAMalformedToken", err: ErrInvalidTokenFormat},
		{name: "ShouldNotReportATokenNoIntrospectorResolves", err: ErrRequestUnauthorized},
		{name: "ShouldNotReportAnUnknownRequest", err: ErrUnknownRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			failure, ok := IntrospectionServerFailure(tc.err)

			assert.Equal(t, tc.ok, ok)

			if !tc.ok {
				assert.Nil(t, failure)

				return
			}

			rfc := ErrorToRFC6749Error(failure)

			assert.Equal(t, tc.expected.ErrorField, rfc.ErrorField)
			assert.Equal(t, tc.expected.CodeField, rfc.CodeField)
		})
	}
}

const introspectorErrorTestToken = "introspector-error-test-token"

type introspectorErrorTestFailingStore struct {
	hoauth2.CoreStorage

	err error
}

func (s *introspectorErrorTestFailingStore) GetAccessTokenSession(_ context.Context, _ string, _ Session) (Requester, error) {
	return nil, s.err
}

type introspectorErrorTestIntrospector struct {
	token string
	err   error
}

func (i *introspectorErrorTestIntrospector) IntrospectToken(_ context.Context, token string, _ TokenUse, _ AccessRequester, _ []string) (TokenUse, error) {
	if token == i.token {
		return "", i.err
	}

	return "", ErrUnknownRequest
}

func newIntrospectorErrorTestProvider() (provider *Fosite, store *storage.MemoryStore) {
	store = storage.NewMemoryStore()

	store.Clients["rs"] = &DefaultClient{ID: "rs", ClientSecret: NewPlainTextClientSecret("foobarfoobarfoobarfoobar")}

	return &Fosite{Store: store, Config: &Config{
		Issuer:              ssfHandlerIssuer,
		SSF:                 &SSFConfig{},
		GlobalSecret:        []byte("foofoofoofoofoofoofoofoofoofoofoo"),
		AccessTokenLifespan: time.Hour,
	}}, store
}

func newIntrospectorErrorTestCoreProvider(t *testing.T) (provider *Fosite, token string) {
	t.Helper()

	provider, store := newIntrospectorErrorTestProvider()

	config := provider.Config.(*Config)
	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{&hoauth2.CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config}}

	request := NewRequest()
	request.Client = store.Clients["rs"]
	request.Session = &DefaultSession{Subject: "peter", ExpiresAt: map[TokenType]time.Time{AccessToken: time.Now().Add(time.Hour)}}

	token, signature, err := strategy.GenerateAccessToken(context.Background(), request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(context.Background(), signature, request))

	return provider, token
}

func introspectorErrorTestIntrospectedToken(t *testing.T, provider *Fosite, token string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {token}}.Encode()))
	r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
	r.SetBasicAuth("rs", "foobarfoobarfoobarfoobar")

	return introspectorErrorTestWriteIntrospection(t, provider, r)
}

func introspectorErrorTestIntrospectionCredential(t *testing.T, provider *Fosite, token string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {"another-token"}}.Encode()))
	r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
	r.Header.Set(consts.HeaderAuthorization, "Bearer "+token)

	return introspectorErrorTestWriteIntrospection(t, provider, r)
}

func introspectorErrorTestWriteIntrospection(t *testing.T, provider *Fosite, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	rw := httptest.NewRecorder()

	responder, err := provider.NewIntrospectionRequest(context.Background(), r, &DefaultSession{})
	if err != nil {
		provider.WriteIntrospectionError(context.Background(), rw, r, err)

		return rw
	}

	provider.WriteIntrospectionResponse(context.Background(), rw, responder)

	return rw
}

func introspectorErrorTestUserInfo(t *testing.T, provider *Fosite, token string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "https://as.example.com/userinfo", nil)
	r.Header.Set(consts.HeaderAuthorization, "Bearer "+token)

	rw := httptest.NewRecorder()

	requester, err := provider.NewUserinfoRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	provider.WriteUserinfoError(context.Background(), rw, requester, err)

	return rw
}

func introspectorErrorTestSSF(t *testing.T, provider *Fosite, token string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, ssfHandlerIssuer+"/ssf/stream", nil)
	r.Header.Set(consts.HeaderAuthorization, "Bearer "+token)

	rw := httptest.NewRecorder()

	_, _, err := provider.AuthorizeSSFRequestForTest(context.Background(), r, &DefaultSession{}, false)
	require.Error(t, err)

	provider.WriteSSFError(context.Background(), rw, r, err)

	return rw
}
