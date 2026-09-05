// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBearerAuthorizationParity(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name      string
		scopes    []string
		audience  []string
		required  []string
		permitted []string
		expected  string
		code      int
	}{
		{
			name:      "ShouldAgreeOnSuccess",
			scopes:    []string{"urn:need"},
			audience:  []string{"urn:aud"},
			required:  []string{"urn:need"},
			permitted: []string{"urn:aud"},
		},
		{
			name:      "ShouldAgreeOnInsufficientScope",
			scopes:    []string{"read"},
			audience:  []string{"urn:aud"},
			required:  []string{"urn:need"},
			permitted: []string{"urn:aud"},
			expected:  "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'urn:need', at least one of which is required.",
			code:      http.StatusForbidden,
		},
		{
			name:      "ShouldAgreeOnWrongAudience",
			scopes:    []string{"urn:need"},
			audience:  []string{"urn:wrong"},
			required:  []string{"urn:need"},
			permitted: []string{"urn:aud"},
			expected:  "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'urn:aud' but the audience had the values 'urn:wrong'.",
			code:      http.StatusUnauthorized,
		},
		{
			name:      "ShouldAgreeOnNoAudience",
			scopes:    []string{"urn:need"},
			audience:  nil,
			required:  []string{"urn:need"},
			permitted: []string{"urn:aud"},
			expected:  "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'urn:aud' but it does not have an audience.",
			code:      http.StatusUnauthorized,
		},
		{
			name:      "ShouldAgreeOnAnyOfTheRequiredScopes",
			scopes:    []string{"urn:b"},
			audience:  []string{"urn:aud"},
			required:  []string{"urn:a", "urn:b"},
			permitted: []string{"urn:aud"},
		},
		{
			name:      "ShouldAgreeOnAnyOfThePermittedAudiences",
			scopes:    []string{"urn:need"},
			audience:  []string{"urn:b"},
			required:  []string{"urn:need"},
			permitted: []string{"urn:a", "urn:b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{}
			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/endpoint", nil)

			err := ValidateBearerAuthorization(ctx, config, r, newBearerRequester(tc.scopes, tc.audience), "token",
				BearerAuthorization{Audiences: tc.permitted, Scopes: tc.required})

			if tc.expected == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)

			rfc := ErrorToRFC6749Error(err)

			assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)
			assert.Equal(t, tc.code, rfc.CodeField)
		})
	}
}

func TestBearerAuthorizationIndistinguishableFailures(t *testing.T) {
	ctx := context.Background()
	config := &Config{}
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/endpoint", nil)
	auth := BearerAuthorization{Audiences: []string{"urn:aud"}}

	wrong := ValidateBearerAuthorization(ctx, config, r, newBearerRequester(nil, []string{"urn:wrong"}), "t", auth)
	none := ValidateBearerAuthorization(ctx, config, r, newBearerRequester(nil, nil), "t", auth)

	require.Error(t, wrong)
	require.Error(t, none)

	a, b := ErrorToRFC6749Error(wrong), ErrorToRFC6749Error(none)

	assert.Equal(t, a.ErrorField, b.ErrorField)
	assert.Equal(t, a.CodeField, b.CodeField)
	assert.Equal(t, a.HintField, b.HintField)
	assert.Equal(t, a.DescriptionField, b.DescriptionField)
}

func TestBearerAuthorizationScopeDisclosesNothingElse(t *testing.T) {
	ctx := context.Background()

	err := ValidateBearerAuthorization(ctx, &Config{}, httptest.NewRequest(http.MethodPost, "https://as.example.com/endpoint", nil),
		newBearerRequester([]string{"read"}, []string{"urn:wrong"}), "token",
		BearerAuthorization{Audiences: []string{"urn:aud"}, Scopes: []string{"urn:need"}})

	require.Error(t, err)
	assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'urn:need', at least one of which is required.")
}

func TestBearerAuthorizationEnforcementPrecedesScope(t *testing.T) {
	ctx := context.Background()
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/endpoint", nil)
	auth := BearerAuthorization{Audiences: []string{"urn:aud"}, Scopes: []string{"urn:need"}}

	for _, tc := range []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "ShouldRejectAnUnboundCredentialWhenDPoPEnforced",
			config:   &Config{DPoPEnforce: true},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a DPoP key. DPoP is enforced, so every credential presented to authenticate a request must be bound to a DPoP key, but this credential records no binding.",
		},
		{
			name:     "ShouldRejectAnUnboundCredentialWhenMTLSEnforced",
			config:   &Config{MTLSEnforce: true},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBearerAuthorization(ctx, tc.config, r, newBearerRequester([]string{"read"}, []string{"urn:aud"}), "token", auth)

			require.Error(t, err)

			assert.Equal(t, http.StatusUnauthorized, ErrorToRFC6749Error(err).CodeField)
			assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}
