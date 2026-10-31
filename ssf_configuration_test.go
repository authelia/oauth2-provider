// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"mime"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSSFConfiguration(t *testing.T) {
	provider := &Fosite{Config: &Config{}}

	rw := httptest.NewRecorder()

	provider.WriteSSFConfiguration(context.Background(), rw, &SSFConfiguration{
		SpecVersion:              SSFSpecVersion,
		Issuer:                   "https://tr.example.com",
		JWKSURI:                  "https://tr.example.com/jwks.json",
		DeliveryMethodsSupported: []string{"urn:ietf:rfc:8935", "urn:ietf:rfc:8936"},
		ConfigurationEndpoint:    "https://tr.example.com/ssf/mgmt/stream",
		StatusEndpoint:           "https://tr.example.com/ssf/mgmt/status",
		AddSubjectEndpoint:       "https://tr.example.com/ssf/mgmt/subject:add",
		RemoveSubjectEndpoint:    "https://tr.example.com/ssf/mgmt/subject:remove",
		VerificationEndpoint:     "https://tr.example.com/ssf/mgmt/verification",
		CriticalSubjectMembers:   []string{"tenant", "user"},
		AuthorizationSchemes: []SSFAuthorizationScheme{
			{SpecURN: "urn:ietf:rfc:6749"},
			{SpecURN: "urn:ietf:rfc:8705"},
		},
		DefaultSubjects: "NONE",
	})

	assert.Equal(t, http.StatusOK, rw.Code)

	mt, _, err := mime.ParseMediaType(rw.Header().Get("Content-Type"))
	require.NoError(t, err)
	assert.Equal(t, "application/json", mt)

	assert.JSONEq(t, `{
  "spec_version": "1_0",
  "issuer": "https://tr.example.com",
  "jwks_uri": "https://tr.example.com/jwks.json",
  "delivery_methods_supported": ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
  "configuration_endpoint": "https://tr.example.com/ssf/mgmt/stream",
  "status_endpoint": "https://tr.example.com/ssf/mgmt/status",
  "add_subject_endpoint": "https://tr.example.com/ssf/mgmt/subject:add",
  "remove_subject_endpoint": "https://tr.example.com/ssf/mgmt/subject:remove",
  "verification_endpoint": "https://tr.example.com/ssf/mgmt/verification",
  "critical_subject_members": ["tenant", "user"],
  "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6749"}, {"spec_urn": "urn:ietf:rfc:8705"}],
  "default_subjects": "NONE"
}`, rw.Body.String())
}

func TestWriteSSFConfigurationOmitsEmpty(t *testing.T) {
	provider := &Fosite{Config: &Config{}}

	rw := httptest.NewRecorder()

	provider.WriteSSFConfiguration(context.Background(), rw, &SSFConfiguration{Issuer: "https://tr.example.com"})

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.JSONEq(t, `{"issuer":"https://tr.example.com"}`, rw.Body.String())
}

func TestSSFConfigurationURL(t *testing.T) {
	testCases := []struct {
		name     string
		issuer   string
		expected string
		err      string
	}{
		{"ShouldInsertWellKnownBeforePath", "https://tr.example.com/issuer1", "https://tr.example.com/.well-known/ssf-configuration/issuer1", ""},
		{"ShouldHandleNoPath", "https://tr.example.com", "https://tr.example.com/.well-known/ssf-configuration", ""},
		{"ShouldStripTrailingSlashOnRoot", "https://tr.example.com/", "https://tr.example.com/.well-known/ssf-configuration", ""},
		{"ShouldStripTrailingSlashOnPath", "https://tr.example.com/issuer1/", "https://tr.example.com/.well-known/ssf-configuration/issuer1", ""},
		{"ShouldNotDoubleEscape", "https://tr.example.com/a%20b", "https://tr.example.com/.well-known/ssf-configuration/a%20b", ""},
		{"ShouldKeepEscapedSlash", "https://tr.example.com/a%2Fb/", "https://tr.example.com/.well-known/ssf-configuration/a%2Fb", ""},
		{"ShouldKeepPort", "https://tr.example.com:8443/a/b", "https://tr.example.com:8443/.well-known/ssf-configuration/a/b", ""},
		{"ShouldRejectRelative", "tr.example.com/issuer1", "", "issuer must be an absolute URL"},
		{"ShouldRejectEmpty", "", "", "issuer must be an absolute URL"},
		{"ShouldRejectPathOnly", "/issuer1", "", "issuer must be an absolute URL"},
		{"ShouldRejectQuery", "https://tr.example.com/a?b=c", "", "issuer must not contain a query or fragment"},
		{"ShouldRejectFragment", "https://tr.example.com/a#b", "", "issuer must not contain a query or fragment"},
		{"ShouldRejectInvalid", "https://tr.example.com/%zz", "", "issuer is not a valid URL"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := SSFConfigurationURL(tc.issuer)

			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.Empty(t, actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
