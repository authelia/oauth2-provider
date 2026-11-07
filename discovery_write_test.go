// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestWellKnownURLs(t *testing.T) {
	testCases := []struct {
		name, issuer, insert, append string
		err                          bool
	}{
		{name: "ShouldHandleNoPath", issuer: "https://ex.com", insert: "https://ex.com/.well-known/oauth-authorization-server", append: "https://ex.com/.well-known/oauth-authorization-server"},
		{name: "ShouldStripTrailingSlash", issuer: "https://ex.com/tenant/", insert: "https://ex.com/.well-known/oauth-authorization-server/tenant", append: "https://ex.com/tenant/.well-known/oauth-authorization-server"},
		{name: "ShouldHandleMultipleSegments", issuer: "https://ex.com/a/b", insert: "https://ex.com/.well-known/oauth-authorization-server/a/b", append: "https://ex.com/a/b/.well-known/oauth-authorization-server"},
		{name: "ShouldPreserveEncodedQuestionMark", issuer: "https://ex.com/a%3Fb", insert: "https://ex.com/.well-known/oauth-authorization-server/a%3Fb", append: "https://ex.com/a%3Fb/.well-known/oauth-authorization-server"},
		{name: "ShouldPreserveEncodedHash", issuer: "https://ex.com/a%23b", insert: "https://ex.com/.well-known/oauth-authorization-server/a%23b", append: "https://ex.com/a%23b/.well-known/oauth-authorization-server"},
		{name: "ShouldPreserveEncodedSlash", issuer: "https://ex.com/a%2Fb", insert: "https://ex.com/.well-known/oauth-authorization-server/a%2Fb", append: "https://ex.com/a%2Fb/.well-known/oauth-authorization-server"},
		{name: "ShouldRejectQuery", issuer: "https://ex.com?x=1", err: true},
		{name: "ShouldRejectFragment", issuer: "https://ex.com/a#f", err: true},
		{name: "ShouldRejectRelative", issuer: "/a", err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ins, err1 := oauth2.WellKnownURLInsert(tc.issuer, oauth2.WellKnownOAuthAuthorizationServerSuffix)
			app, err2 := oauth2.WellKnownURLAppend(tc.issuer, oauth2.WellKnownOAuthAuthorizationServerSuffix)

			if tc.err {
				assert.Error(t, err1)
				assert.Error(t, err2)

				return
			}

			require.NoError(t, err1)
			require.NoError(t, err2)
			assert.Equal(t, tc.insert, ins)
			assert.Equal(t, tc.append, app)
		})
	}

	app, err := oauth2.WellKnownURLAppend("https://ex.com/tenant/", oauth2.WellKnownOpenIDConfigurationSuffix)
	require.NoError(t, err)
	assert.Equal(t, "https://ex.com/tenant/.well-known/openid-configuration", app)
}

func TestDiscoveryHookRuns(t *testing.T) {
	hook := &discoveryTestHook{}
	config := newDiscoveryAllEnabledConfig()
	config.DiscoveryMetadataHooks = []oauth2.DiscoveryMetadataHook{hook}

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 1, hook.calls)
	assert.Equal(t, "https://auth.example.com/check", marshalMembers(t, metadata)["check_session_iframe"])

	oauth, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 2, hook.calls)
	assert.NotContains(t, marshalMembers(t, oauth), "check_session_iframe")

	hook.err = errors.New("boom")

	_, err = provider.NewOpenIDConnectProviderMetadata(context.Background())
	assert.Error(t, err)
}

func TestDiscoverySignedMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		issuer   func() *jwt.DefaultIssuer
		expected string
		err      string
	}{
		{
			"ShouldSignWithRS256",
			func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())
			},
			"RS256",
			"",
		},
		{
			"ShouldPreferRS256",
			func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: gen.MustES256Key(), KeyID: "ec", Use: jwt.JSONWebTokenUseSignature, Algorithm: string(jose.ES256)},
					{Key: gen.MustRSAKey(), KeyID: "rsa", Use: jwt.JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
				}})
			},
			"RS256",
			"",
		},
		{
			"ShouldSignWithES256WhenOnlyES256",
			func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: gen.MustES256Key(), KeyID: "ec", Use: jwt.JSONWebTokenUseSignature, Algorithm: string(jose.ES256)},
				}})
			},
			"ES256",
			"",
		},
		{
			"ShouldErrorWithoutSigningAlgorithms",
			func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})
			},
			"",
			"unable to sign the discovery metadata: the signing strategy has no signing algorithms",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newDiscoveryAllEnabledConfig()
			config.DiscoveryMetadataSigningStrategy = &jwt.DefaultStrategy{Config: config, Issuer: tc.issuer()}

			provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

			metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				_, err = provider.NewOAuth2AuthorizationServerMetadata(context.Background())
				assert.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, metadata.SignedMetadata)

			oauth, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			require.NoError(t, err)
			require.NotEmpty(t, oauth.SignedMetadata)

			for _, token := range []string{metadata.SignedMetadata, oauth.SignedMetadata} {
				parts := strings.Split(token, ".")
				require.Len(t, parts, 3)

				raw, err := base64.RawURLEncoding.DecodeString(parts[0])
				require.NoError(t, err)

				header := map[string]any{}
				require.NoError(t, json.Unmarshal(raw, &header))

				assert.Equal(t, tc.expected, header["alg"])

				raw, err = base64.RawURLEncoding.DecodeString(parts[1])
				require.NoError(t, err)

				claims := map[string]any{}
				require.NoError(t, json.Unmarshal(raw, &claims))

				assert.Equal(t, "https://auth.example.com", claims["iss"])
				assert.Contains(t, claims, "token_endpoint")
				assert.NotContains(t, claims, "signed_metadata")
			}
		})
	}
}

func TestWriteDiscoveryResponse(t *testing.T) {
	provider := compose.ComposeAllEnabled(newDiscoveryAllEnabledConfig(), storage.NewMemoryStore(), gen.MustRSAKey())

	rw := httptest.NewRecorder()
	provider.WriteDiscoveryResponse(context.Background(), rw, map[string]any{"issuer": "https://auth.example.com"})

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "application/json;charset=UTF-8", rw.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"issuer":"https://auth.example.com"}`, rw.Body.String())

	rw = httptest.NewRecorder()
	provider.WriteDiscoveryResponse(context.Background(), rw, map[string]any{"x": make(chan int)})

	assert.Equal(t, http.StatusInternalServerError, rw.Code)
	assert.Empty(t, rw.Body.String())
}

type discoveryTestHook struct {
	calls int
	err   error
}

func (h *discoveryTestHook) HandleDiscoveryMetadata(_ context.Context, metadata *oauth2.OpenIDConnectProviderMetadata) error {
	h.calls++

	if h.err != nil {
		return h.err
	}

	metadata.OpenIDConnectSessionManagementMetadata = &oauth2.OpenIDConnectSessionManagementMetadata{CheckSessionIFrame: "https://auth.example.com/check"}

	return nil
}
