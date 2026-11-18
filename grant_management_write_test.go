// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestWriteGrantManagementResponse(t *testing.T) {
	provider := &Fosite{Config: &Config{}}

	t.Run("ShouldWriteTheBody", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementResponse(t.Context(), rw, &GrantManagementRequest{Method: http.MethodGet}, &GrantManagementResponse{
			StatusCode: http.StatusOK,
			Body:       &GrantManagementResponseBody{Scopes: []GrantScope{{Scope: "read"}}, CreatedAt: 1700000000, UpdatedBy: GrantUpdatedByClient},
		})

		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, "no-cache, no-store", rw.Header().Get(consts.HeaderCacheControl))
		assert.Equal(t, "application/json", rw.Header().Get(consts.HeaderContentType))
		assert.JSONEq(t, `{"scopes":[{"scope":"read"}],"created_at":1700000000,"updated_by":"client"}`, rw.Body.String())
	})

	t.Run("ShouldWriteNoContent", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementResponse(t.Context(), rw, &GrantManagementRequest{Method: http.MethodDelete}, &GrantManagementResponse{StatusCode: http.StatusNoContent})

		assert.Equal(t, http.StatusNoContent, rw.Code)
		assert.Equal(t, "no-cache, no-store", rw.Header().Get(consts.HeaderCacheControl))
		assert.Empty(t, rw.Header().Get(consts.HeaderContentType))
		assert.Empty(t, rw.Body.String())
	})
}

func TestWriteGrantManagementError(t *testing.T) {
	config := &Config{GrantManagement: &GrantManagementConfig{Actions: []GrantManagementAction{GrantManagementActionQuery, GrantManagementActionRevoke}}}

	provider := &Fosite{Config: config}

	request := func(authorization string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://as.example.com/grants/one", nil)

		if authorization != "" {
			r.Header.Set(consts.HeaderAuthorization, authorization)
		}

		return r
	}

	t.Run("ShouldWriteNotFoundWithoutABody", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementError(t.Context(), rw, request("Bearer some-token"), ErrNotFound)

		assert.Equal(t, http.StatusNotFound, rw.Code)
		assert.Equal(t, "no-cache, no-store", rw.Header().Get(consts.HeaderCacheControl))
		assert.Empty(t, rw.Header().Get(consts.HeaderContentType))
		assert.Empty(t, rw.Body.String())
	})

	t.Run("ShouldChallengeWithoutAnErrorCodeWhenTheRequestHasNoCredentials", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementError(t.Context(), rw, request(""), ErrInvalidToken)

		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.Equal(t, "application/json", rw.Header().Get(consts.HeaderContentType))
		assert.Equal(t, "Bearer", rw.Header().Get(consts.HeaderWWWAuthenticate))
		assert.Contains(t, rw.Body.String(), `"error":"invalid_token"`)
	})

	t.Run("ShouldChallengeWithTheErrorCodeForARejectedCredential", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementError(t.Context(), rw, request("Bearer some-token"), ErrInvalidToken)

		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `Bearer error="invalid_token"`)
		assert.Contains(t, rw.Body.String(), `"error":"invalid_token"`)
	})

	t.Run("ShouldCarryTheResourceMetadataOfTheRequest", func(t *testing.T) {
		rw := httptest.NewRecorder()

		located := &Fosite{Config: &grantManagementWriteConfig{Config: config}}

		located.WriteGrantManagementError(t.Context(), rw, request(""), ErrInvalidToken)

		assert.Equal(t, `Bearer resource_metadata="https://as.example.com/.well-known/oauth-protected-resource/grants"`, rw.Header().Get(consts.HeaderWWWAuthenticate))
	})

	t.Run("ShouldChallengeBothSchemesWithoutARequest", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementError(t.Context(), rw, nil, ErrInvalidToken)

		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `Bearer error="invalid_token"`)
	})

	t.Run("ShouldAnswerInsufficientScopeAsForbidden", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementError(t.Context(), rw, request("Bearer some-token"), ErrInsufficientScope)

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `error="insufficient_scope"`)
		assert.Contains(t, rw.Body.String(), `"error":"insufficient_scope"`)
	})

	t.Run("ShouldNameTheSupportedMethods", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementError(t.Context(), rw, request("Bearer some-token"), ErrInvalidRequest.WithCode(http.StatusMethodNotAllowed))

		assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
		assert.Equal(t, "GET, DELETE", rw.Header().Get(consts.HeaderAllow))
	})

	t.Run("ShouldNotExposeDebugUnlessConfigured", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteGrantManagementError(t.Context(), rw, request("Bearer some-token"), ErrServerError.WithDebug("Grant management is not configured."))

		assert.Equal(t, http.StatusInternalServerError, rw.Code)
		assert.NotContains(t, rw.Body.String(), "not configured")
		assert.Empty(t, rw.Header().Get(consts.HeaderAllow))
	})
}

type grantManagementWriteConfig struct {
	*Config
}

func (c *grantManagementWriteConfig) GetProtectedResourceMetadataURL(context.Context, *http.Request) string {
	return "https://as.example.com/.well-known/oauth-protected-resource/grants"
}
