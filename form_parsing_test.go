// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestEndpointsDoNotParseMultipartBodies(t *testing.T) {
	var body bytes.Buffer

	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("upload", "upload.bin")
	require.NoError(t, err)

	_, err = part.Write(bytes.Repeat([]byte{'a'}, 3<<20))
	require.NoError(t, err)

	require.NoError(t, writer.WriteField(consts.FormParameterGrantType, "client_credentials"))
	require.NoError(t, writer.Close())

	provider := &Fosite{Store: storage.NewMemoryStore(), Config: &Config{}}

	testCases := []struct {
		name string
		call func(ctx context.Context, r *http.Request)
	}{
		{"ShouldNotParseAtTheTokenEndpoint", func(ctx context.Context, r *http.Request) {
			_, _ = provider.NewAccessRequest(ctx, r, &DefaultSession{})
		}},
		{"ShouldNotParseAtTheAuthorizationEndpoint", func(ctx context.Context, r *http.Request) {
			_, _ = provider.NewAuthorizeRequest(ctx, r)
		}},
		{"ShouldNotParseAtThePushedAuthorizationEndpoint", func(ctx context.Context, r *http.Request) {
			_, _ = provider.NewPushedAuthorizeRequest(ctx, r)
		}},
		{"ShouldNotParseAtTheDeviceAuthorizationEndpoint", func(ctx context.Context, r *http.Request) {
			_, _ = provider.NewRFC862DeviceAuthorizeRequest(ctx, r)
		}},
		{"ShouldNotParseAtTheDeviceUserAuthorizationEndpoint", func(ctx context.Context, r *http.Request) {
			_, _ = provider.NewRFC8628UserAuthorizeRequest(ctx, r, &DefaultSession{})
		}},
		{"ShouldNotParseAtTheRevocationEndpoint", func(ctx context.Context, r *http.Request) {
			_ = provider.NewRevocationRequest(ctx, r)
		}},
		{"ShouldNotParseAtTheIntrospectionEndpoint", func(ctx context.Context, r *http.Request) {
			_, _ = provider.NewIntrospectionRequest(ctx, r, &DefaultSession{})
		}},
		{"ShouldNotParseAtTheLogoutEndpoint", func(ctx context.Context, r *http.Request) {
			_, _ = provider.NewRPInitiatedLogoutRequest(ctx, r)
		}},
		{"ShouldNotParseForAnAccessToken", func(_ context.Context, r *http.Request) {
			assert.Empty(t, AccessTokenFromRequest(r))
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)

			r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/endpoint", strings.NewReader(body.String()))
			r.Header.Set(consts.HeaderContentType, writer.FormDataContentType())

			tc.call(t.Context(), r)

			assert.Nil(t, r.MultipartForm)

			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}
}
