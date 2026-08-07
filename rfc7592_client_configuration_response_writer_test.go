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
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestFositeWriteRFC7592ClientConfigurationResponse(t *testing.T) {
	t.Run("ShouldWriteNoBodyForNoContentWithNilMetadata", func(t *testing.T) {
		provider := &Fosite{Config: new(Config)}

		response := NewClientRegistrationResponse()
		response.SetMetadata(nil)
		response.SetStatusCode(http.StatusNoContent)

		rw := httptest.NewRecorder()

		provider.WriteRFC7592ClientConfigurationResponse(context.Background(), rw, NewClientConfigurationRequest(), response)

		assert.Equal(t, http.StatusNoContent, rw.Code)
		assert.Empty(t, rw.Body.Bytes())
	})

	t.Run("ShouldWriteMetadataForOK", func(t *testing.T) {
		provider := &Fosite{Config: new(Config)}

		response := NewClientRegistrationResponse()
		response.SetMetadata(&ClientRegistrationMetadata{ClientName: "Example"})
		response.SetClientID("abc")
		response.SetStatusCode(http.StatusOK)

		rw := httptest.NewRecorder()

		provider.WriteRFC7592ClientConfigurationResponse(context.Background(), rw, NewClientConfigurationRequest(), response)

		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
		assert.Contains(t, rw.Body.String(), `"client_id":"abc"`)
		assert.Contains(t, rw.Body.String(), `"client_name":"Example"`)
	})
}

func TestFositeWriteRFC7592ClientConfigurationError(t *testing.T) {
	testCases := []struct {
		name       string
		err        error
		code       int
		wwwAuth    string
		allow      string
		bodyErrKey string
	}{
		{
			name:       "ShouldWrite401AndWWWAuthenticateForRequestUnauthorized",
			err:        errorsx.WithStack(ErrRequestUnauthorized),
			code:       http.StatusUnauthorized,
			wwwAuth:    "Bearer",
			bodyErrKey: "request_unauthorized",
		},
		{
			name:       "ShouldWrite404ForNotFound",
			err:        errorsx.WithStack(ErrNotFound),
			code:       http.StatusNotFound,
			bodyErrKey: "not_found",
		},
		{
			name:       "ShouldWrite405ForInvalidRequestCarryingMethodHint",
			err:        errorsx.WithStack(ErrInvalidRequest.WithHintf("The client configuration endpoint does not support the '%s' method.", http.MethodPatch)),
			code:       http.StatusMethodNotAllowed,
			allow:      "GET, PUT, DELETE",
			bodyErrKey: "invalid_request",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: new(Config)}
			rw := httptest.NewRecorder()

			provider.WriteRFC7592ClientConfigurationError(context.Background(), rw, NewClientConfigurationRequest(), tc.err)

			assert.Equal(t, tc.code, rw.Code)
			assert.Equal(t, tc.wwwAuth, rw.Header().Get(consts.HeaderWWWAuthenticate))
			assert.Equal(t, tc.allow, rw.Header().Get(consts.HeaderAllow))
			assert.Contains(t, rw.Body.String(), tc.bodyErrKey)
		})
	}
}
