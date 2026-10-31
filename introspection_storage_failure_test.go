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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestIntrospectionStorageFailure(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobarfoobar12"

	outage := errors.New("the database is unavailable")

	testCases := []struct {
		name     string
		access   error
		refresh  error
		bearer   bool
		token    string
		code     int
		contains string
		excludes string
	}{
		{name: "ShouldReportAStoreFailureOnTheAccessTokenPath", access: outage, refresh: ErrNotFound, code: http.StatusInternalServerError, contains: "server_error", excludes: `"active"`},
		{name: "ShouldReportAStoreFailureOnTheRefreshTokenPath", access: ErrNotFound, refresh: outage, token: "authelia_rt_token.signature", code: http.StatusInternalServerError, contains: "server_error", excludes: `"active"`},
		{name: "ShouldReportAStoreServerError", access: ErrServerError, refresh: ErrNotFound, code: http.StatusInternalServerError, contains: "server_error", excludes: `"active"`},
		{name: "ShouldReportAStoreFailureForABearerCredential", access: outage, refresh: outage, bearer: true, code: http.StatusInternalServerError, contains: "server_error", excludes: "invalid_token"},
		{name: "ShouldAnswerAnUnknownTokenAsInactive", access: ErrNotFound, refresh: ErrNotFound, code: http.StatusOK, contains: `"active":false`},
		{name: "ShouldAnswerARevokedRefreshTokenAsInactive", access: ErrNotFound, refresh: ErrInactiveToken, token: "authelia_rt_token.signature", code: http.StatusOK, contains: `"active":false`},
		{name: "ShouldAnswerAnUnknownBearerCredentialAsUnauthorized", access: ErrNotFound, refresh: ErrNotFound, bearer: true, code: http.StatusUnauthorized, contains: "invalid_token"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo")}

			memory := storage.NewMemoryStore()
			memory.Clients["rs"] = &DefaultClient{ID: "rs", ClientSecret: NewPlainTextClientSecret(secret)}

			store := &failingSessionStore{MemoryStore: memory, access: tc.access, refresh: tc.refresh}

			config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{
				&hoauth2.CoreValidator{CoreStrategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"), CoreStorage: store, Config: config},
			}

			provider := &Fosite{Store: memory, Config: config}

			token := tc.token
			if token == "" {
				token = "authelia_at_token.signature"
			}

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {token}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")

			if tc.bearer {
				r.Header.Set(consts.HeaderAuthorization, "Bearer authelia_at_credential.signature")
			} else {
				r.SetBasicAuth("rs", secret)
			}

			ctx := context.Background()
			recorder := httptest.NewRecorder()

			_, err := provider.NewIntrospectionRequest(ctx, r, &DefaultSession{})
			require.Error(t, err)

			provider.WriteIntrospectionError(ctx, recorder, err)

			assert.Equal(t, tc.code, recorder.Code)
			assert.Contains(t, recorder.Body.String(), tc.contains)

			if tc.excludes != "" {
				assert.NotContains(t, recorder.Body.String(), tc.excludes)
			}
		})
	}
}

type failingSessionStore struct {
	*storage.MemoryStore

	access, refresh error
}

func (s *failingSessionStore) GetAccessTokenSession(_ context.Context, _ string, _ Session) (Requester, error) {
	return nil, s.access
}

func (s *failingSessionStore) GetRefreshTokenSession(_ context.Context, _ string, _ Session) (Requester, error) {
	return nil, s.refresh
}
