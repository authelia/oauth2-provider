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

func TestWriteSSFConfiguration(t *testing.T) {
	provider := &Fosite{Config: &Config{Issuer: "https://tr.example.com"}}

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

	assert.Equal(t, "application/json", rw.Header().Get("Content-Type"))

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
	provider := &Fosite{Config: &Config{Issuer: "https://tr.example.com"}}

	rw := httptest.NewRecorder()

	provider.WriteSSFConfiguration(context.Background(), rw, &SSFConfiguration{Issuer: "https://tr.example.com", JWKSURI: "https://tr.example.com/jwks.json"})

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.JSONEq(t, `{"issuer":"https://tr.example.com","jwks_uri":"https://tr.example.com/jwks.json"}`, rw.Body.String())
}

func TestWriteSSFConfigurationShouldRefuseInvalidMetadata(t *testing.T) {
	testCases := []struct {
		name          string
		configuration *SSFConfiguration
	}{
		{"ShouldRefuseNil", nil},
		{"ShouldRefuseAnotherIssuer", &SSFConfiguration{Issuer: "https://other.example.com", JWKSURI: "https://other.example.com/jwks.json"}},
		{"ShouldRefuseHTTPEndpoint", &SSFConfiguration{Issuer: "https://tr.example.com", JWKSURI: "https://tr.example.com/jwks.json", StatusEndpoint: "http://tr.example.com/ssf/status"}},
		{"ShouldRefuseNoJWKSURI", &SSFConfiguration{Issuer: "https://tr.example.com"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{Issuer: "https://tr.example.com", SendDebugMessagesToClients: true}}

			rw := httptest.NewRecorder()

			provider.WriteSSFConfiguration(context.Background(), rw, tc.configuration)

			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
			assert.Contains(t, rw.Body.String(), `"error":"server_error"`)
			assert.NotContains(t, rw.Body.String(), `"issuer"`)
		})
	}
}

func TestValidateSSFConfiguration(t *testing.T) {
	const issuer = "https://tr.example.com/issuer1"

	valid := func(mutate func(c *SSFConfiguration)) *SSFConfiguration {
		c := &SSFConfiguration{
			SpecVersion:              SSFSpecVersion,
			Issuer:                   issuer,
			JWKSURI:                  "https://tr.example.com/jwks.json",
			DeliveryMethodsSupported: []string{SSFDeliveryMethodPush, SSFDeliveryMethodPoll},
			ConfigurationEndpoint:    "https://tr.example.com/ssf/stream",
			StatusEndpoint:           "https://tr.example.com/ssf/status",
			VerificationEndpoint:     "https://tr.example.com/ssf/verify",
			AuthorizationSchemes:     []SSFAuthorizationScheme{{SpecURN: "urn:ietf:rfc:8705"}, {SpecURN: SSFAuthorizationSchemeOAuth2}},
			DefaultSubjects:          "ALL",
		}

		if mutate != nil {
			mutate(c)
		}

		return c
	}

	testCases := []struct {
		name          string
		configuration *SSFConfiguration
		issuer        string
		profile       bool
		noConfig      bool
		err           string
	}{
		{name: "ShouldAcceptFullMetadata", configuration: valid(nil)},
		{name: "ShouldAcceptFullMetadataWithProfile", configuration: valid(nil), profile: true},
		{name: "ShouldAcceptIssuerAndJWKSURIOnly", configuration: &SSFConfiguration{Issuer: issuer, JWKSURI: issuer + "/jwks.json"}},
		{name: "ShouldAcceptIssuerAndJWKSURIOnlyWithoutSSFConfig", configuration: &SSFConfiguration{Issuer: issuer, JWKSURI: issuer + "/jwks.json"}, noConfig: true},
		{name: "ShouldRejectNoJWKSURI", configuration: valid(func(c *SSFConfiguration) { c.JWKSURI = "" }), err: "'jwks_uri'"},
		{name: "ShouldRejectNoJWKSURIWithoutSSFConfig", configuration: &SSFConfiguration{Issuer: issuer}, noConfig: true, err: "'jwks_uri'"},
		{name: "ShouldAcceptDefaultSubjectsNone", configuration: valid(func(c *SSFConfiguration) { c.DefaultSubjects = "NONE" })},
		{name: "ShouldAcceptLaterSpecVersionWithProfile", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "1_1" }), profile: true},
		{name: "ShouldAcceptLaterDraftSpecVersionWithProfile", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "2_0-ID1" }), profile: true},
		{name: "ShouldAcceptDraftSpecVersion", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "1_0-ID3" })},
		{name: "ShouldAcceptNoOAuth2Scheme", configuration: valid(func(c *SSFConfiguration) {
			c.AuthorizationSchemes = []SSFAuthorizationScheme{{SpecURN: "urn:ietf:rfc:8705"}}
		})},
		{name: "ShouldRejectNil", err: "is missing"},
		{name: "ShouldRejectNoIssuer", configuration: valid(func(c *SSFConfiguration) { c.Issuer = "" }), err: "'issuer'"},
		{name: "ShouldRejectHTTPIssuer", configuration: valid(func(c *SSFConfiguration) { c.Issuer = "http://tr.example.com/issuer1" }), issuer: "http://tr.example.com/issuer1", err: "'issuer'"},
		{name: "ShouldRejectIssuerWithQuery", configuration: valid(func(c *SSFConfiguration) { c.Issuer = issuer + "?a=b" }), issuer: issuer + "?a=b", err: "'issuer'"},
		{name: "ShouldRejectAnotherIssuer", configuration: valid(func(c *SSFConfiguration) { c.Issuer = "https://other.example.com" }), err: "is not the configured issuer"},
		{name: "ShouldRejectIssuerWithTrailingSlash", configuration: valid(func(c *SSFConfiguration) { c.Issuer = issuer + "/" }), err: "is not the configured issuer"},
		{name: "ShouldRejectHTTPJWKSURI", configuration: valid(func(c *SSFConfiguration) { c.JWKSURI = "http://tr.example.com/jwks.json" }), err: "'jwks_uri'"},
		{name: "ShouldRejectHTTPConfigurationEndpoint", configuration: valid(func(c *SSFConfiguration) { c.ConfigurationEndpoint = "http://tr.example.com/ssf/stream" }), err: "'configuration_endpoint'"},
		{name: "ShouldRejectRelativeStatusEndpoint", configuration: valid(func(c *SSFConfiguration) { c.StatusEndpoint = "/ssf/status" }), err: "'status_endpoint'"},
		{name: "ShouldRejectHTTPAddSubjectEndpoint", configuration: valid(func(c *SSFConfiguration) { c.AddSubjectEndpoint = "http://tr.example.com/add" }), err: "'add_subject_endpoint'"},
		{name: "ShouldRejectHTTPRemoveSubjectEndpoint", configuration: valid(func(c *SSFConfiguration) { c.RemoveSubjectEndpoint = "http://tr.example.com/remove" }), err: "'remove_subject_endpoint'"},
		{name: "ShouldRejectVerificationEndpointWithoutHost", configuration: valid(func(c *SSFConfiguration) { c.VerificationEndpoint = "https:///verify" }), err: "'verification_endpoint'"},
		{name: "ShouldRejectUnknownDefaultSubjects", configuration: valid(func(c *SSFConfiguration) { c.DefaultSubjects = "SOME" }), err: "'default_subjects'"},
		{name: "ShouldRejectLowerCaseDefaultSubjects", configuration: valid(func(c *SSFConfiguration) { c.DefaultSubjects = "all" }), err: "'default_subjects'"},
		{name: "ShouldRejectSchemeWithoutSpecURN", configuration: valid(func(c *SSFConfiguration) {
			c.AuthorizationSchemes = append(c.AuthorizationSchemes, SSFAuthorizationScheme{})
		}), err: "'spec_urn'"},
		{name: "ShouldRejectNoSpecVersionWithProfile", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "" }), profile: true, err: "'spec_version'"},
		{name: "ShouldRejectDraftSpecVersionWithProfile", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "1_0-ID3" }), profile: true, err: "'spec_version'"},
		{name: "ShouldRejectEmptyDraftSpecVersionWithProfile", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "1_0-" }), profile: true, err: "'spec_version'"},
		{name: "ShouldRejectEarlierSpecVersionWithProfile", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "0_9" }), profile: true, err: "'spec_version'"},
		{name: "ShouldRejectMalformedSpecVersionWithProfile", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "one" }), profile: true, err: "'spec_version'"},
		{name: "ShouldRejectNoDeliveryMethodsWithProfile", configuration: valid(func(c *SSFConfiguration) { c.DeliveryMethodsSupported = nil }), profile: true, err: "'delivery_methods_supported'"},
		{name: "ShouldRejectNoJWKSURIWithProfile", configuration: valid(func(c *SSFConfiguration) { c.JWKSURI = "" }), profile: true, err: "'jwks_uri'"},
		{name: "ShouldRejectNoConfigurationEndpointWithProfile", configuration: valid(func(c *SSFConfiguration) { c.ConfigurationEndpoint = "" }), profile: true, err: "'configuration_endpoint'"},
		{name: "ShouldRejectNoStatusEndpointWithProfile", configuration: valid(func(c *SSFConfiguration) { c.StatusEndpoint = "" }), profile: true, err: "'status_endpoint'"},
		{name: "ShouldRejectNoVerificationEndpointWithProfile", configuration: valid(func(c *SSFConfiguration) { c.VerificationEndpoint = "" }), profile: true, err: "'verification_endpoint'"},
		{name: "ShouldRejectNoAuthorizationSchemesWithProfile", configuration: valid(func(c *SSFConfiguration) { c.AuthorizationSchemes = nil }), profile: true, err: "'authorization_schemes'"},
		{name: "ShouldRejectNoOAuth2SchemeWithProfile", configuration: valid(func(c *SSFConfiguration) {
			c.AuthorizationSchemes = []SSFAuthorizationScheme{{SpecURN: "urn:ietf:rfc:8705"}}
		}), profile: true, err: "'authorization_schemes'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{Issuer: issuer, SSF: &SSFConfig{EnforceCAEPInteroperabilityProfile: tc.profile}}

			if tc.issuer != "" {
				config.Issuer = tc.issuer
			}

			if tc.noConfig {
				config.SSF = nil
			}

			err := (&Fosite{Config: config}).ValidateSSFConfiguration(context.Background(), tc.configuration)

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrServerError)
			assert.Contains(t, ErrorToRFC6749Error(err).DebugField, tc.err)
		})
	}
}

func TestValidateSSFConfigurationForIssuer(t *testing.T) {
	const issuer = "https://tr.example.com/issuer1"

	valid := func(mutate func(c *SSFConfiguration)) *SSFConfiguration {
		c := &SSFConfiguration{
			SpecVersion:              SSFSpecVersion,
			Issuer:                   issuer,
			JWKSURI:                  "https://tr.example.com/jwks.json",
			DeliveryMethodsSupported: []string{SSFDeliveryMethodPush, SSFDeliveryMethodPoll},
			ConfigurationEndpoint:    "https://tr.example.com/ssf/stream",
			StatusEndpoint:           "https://tr.example.com/ssf/status",
			VerificationEndpoint:     "https://tr.example.com/ssf/verify",
			AuthorizationSchemes:     []SSFAuthorizationScheme{{SpecURN: SSFAuthorizationSchemeOAuth2}},
		}

		if mutate != nil {
			mutate(c)
		}

		return c
	}

	type testCase struct {
		name          string
		configuration *SSFConfiguration
		issuer        string
		noIssuer      bool
		profile       bool
		err           string
	}

	groups := []struct {
		name      string
		testCases []testCase
	}{
		{
			// SSF Section 7.2.4: the 'issuer' MUST be identical to the issuer the location was derived from.
			name: "ShouldRejectIssuerMismatch",
			testCases: []testCase{
				{name: "AnotherHost", configuration: valid(nil), issuer: "https://other.example.com/issuer1", err: "'issuer' is not the configured issuer"},
				{name: "TrailingSlash", configuration: valid(nil), issuer: issuer + "/", err: "'issuer' is not the configured issuer"},
				{name: "Case", configuration: valid(nil), issuer: "https://TR.example.com/issuer1", err: "'issuer' is not the configured issuer"},
				{name: "EmptyExpected", configuration: valid(nil), noIssuer: true, err: "'issuer' is not the configured issuer"},
				{name: "EmptyMetadata", configuration: valid(func(c *SSFConfiguration) { c.Issuer = "" }), noIssuer: true, err: "'issuer' is not valid"},
				{name: "HTTPOnBoth", configuration: valid(func(c *SSFConfiguration) { c.Issuer = "http://tr.example.com" }), issuer: "http://tr.example.com", err: "'issuer' is not valid"},
			},
		},
		{
			// SSF Section 7.1: 'jwks_uri' and each endpoint use the https scheme.
			name: "ShouldRejectHTTPEndpoint",
			testCases: []testCase{
				{name: "JWKSURI", configuration: valid(func(c *SSFConfiguration) { c.JWKSURI = "http://tr.example.com/jwks.json" }), err: "'jwks_uri' must be an absolute https URL"},
				{name: "ConfigurationEndpoint", configuration: valid(func(c *SSFConfiguration) { c.ConfigurationEndpoint = "http://tr.example.com/ssf/stream" }), err: "'configuration_endpoint' must be an absolute https URL"},
				{name: "StatusEndpoint", configuration: valid(func(c *SSFConfiguration) { c.StatusEndpoint = "http://tr.example.com/ssf/status" }), err: "'status_endpoint' must be an absolute https URL"},
				{name: "AddSubjectEndpoint", configuration: valid(func(c *SSFConfiguration) { c.AddSubjectEndpoint = "http://tr.example.com/add" }), err: "'add_subject_endpoint' must be an absolute https URL"},
				{name: "RemoveSubjectEndpoint", configuration: valid(func(c *SSFConfiguration) { c.RemoveSubjectEndpoint = "http://tr.example.com/remove" }), err: "'remove_subject_endpoint' must be an absolute https URL"},
				{name: "VerificationEndpoint", configuration: valid(func(c *SSFConfiguration) { c.VerificationEndpoint = "http://tr.example.com/ssf/verify" }), err: "'verification_endpoint' must be an absolute https URL"},
				{name: "NoJWKSURI", configuration: valid(func(c *SSFConfiguration) { c.JWKSURI = "" }), err: "'jwks_uri' is required"},
			},
		},
		{
			// Profile Section 2.3.1 to 2.3.7.
			name: "ShouldRequireProfileMembers",
			testCases: []testCase{
				{name: "AcceptFullMetadata", configuration: valid(nil), profile: true},
				{name: "AcceptIssuerAndJWKSURIOnlyWithoutProfile", configuration: &SSFConfiguration{Issuer: issuer, JWKSURI: issuer + "/jwks.json"}},
				{name: "SpecVersion", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "" }), profile: true, err: "'spec_version' does not meet the CAEP Interoperability Profile"},
				{name: "DraftSpecVersion", configuration: valid(func(c *SSFConfiguration) { c.SpecVersion = "1_0-ID3" }), profile: true, err: "'spec_version' does not meet the CAEP Interoperability Profile"},
				{name: "DeliveryMethodsSupported", configuration: valid(func(c *SSFConfiguration) { c.DeliveryMethodsSupported = nil }), profile: true, err: "'delivery_methods_supported' does not meet the CAEP Interoperability Profile"},
				{name: "JWKSURI", configuration: valid(func(c *SSFConfiguration) { c.JWKSURI = "" }), profile: true, err: "'jwks_uri' is required"},
				{name: "ConfigurationEndpoint", configuration: valid(func(c *SSFConfiguration) { c.ConfigurationEndpoint = "" }), profile: true, err: "'configuration_endpoint' does not meet the CAEP Interoperability Profile"},
				{name: "StatusEndpoint", configuration: valid(func(c *SSFConfiguration) { c.StatusEndpoint = "" }), profile: true, err: "'status_endpoint' does not meet the CAEP Interoperability Profile"},
				{name: "VerificationEndpoint", configuration: valid(func(c *SSFConfiguration) { c.VerificationEndpoint = "" }), profile: true, err: "'verification_endpoint' does not meet the CAEP Interoperability Profile"},
				{name: "AuthorizationSchemes", configuration: valid(func(c *SSFConfiguration) { c.AuthorizationSchemes = nil }), profile: true, err: "'authorization_schemes' does not meet the CAEP Interoperability Profile"},
				{name: "OAuth2AuthorizationScheme", configuration: valid(func(c *SSFConfiguration) {
					c.AuthorizationSchemes = []SSFAuthorizationScheme{{SpecURN: "urn:ietf:rfc:8705"}}
				}), profile: true, err: "'authorization_schemes' does not meet the CAEP Interoperability Profile"},
				{name: "NotWithoutProfile", configuration: valid(func(c *SSFConfiguration) {
					c.SpecVersion, c.DeliveryMethodsSupported, c.ConfigurationEndpoint, c.StatusEndpoint, c.VerificationEndpoint, c.AuthorizationSchemes = "", nil, "", "", "", nil
				})},
			},
		},
		{
			name: "ShouldKeepProviderBehavior",
			testCases: []testCase{
				{name: "Accept", configuration: valid(nil), profile: true},
				{name: "Nil", err: "The Transmitter Configuration Metadata is missing."},
				{name: "InvalidIssuer", configuration: valid(func(c *SSFConfiguration) { c.Issuer = issuer + "?a=b" }), issuer: issuer + "?a=b", err: "The Transmitter Configuration Metadata 'issuer' is not valid: issuer must not contain a query or fragment."},
				{name: "AnotherIssuer", configuration: valid(func(c *SSFConfiguration) { c.Issuer = "https://other.example.com" }), err: "The Transmitter Configuration Metadata 'issuer' is not the configured issuer."},
				{name: "NoJWKSURI", configuration: valid(func(c *SSFConfiguration) { c.JWKSURI = "" }), err: "The Transmitter Configuration Metadata 'jwks_uri' is required."},
				{name: "RelativeEndpoint", configuration: valid(func(c *SSFConfiguration) { c.StatusEndpoint = "/ssf/status" }), err: "The Transmitter Configuration Metadata 'status_endpoint' must be an absolute https URL."},
				{name: "DefaultSubjects", configuration: valid(func(c *SSFConfiguration) { c.DefaultSubjects = "all" }), err: "The Transmitter Configuration Metadata 'default_subjects' must be 'ALL' or 'NONE'."},
				{name: "SchemeWithoutSpecURN", configuration: valid(func(c *SSFConfiguration) {
					c.AuthorizationSchemes = append(c.AuthorizationSchemes, SSFAuthorizationScheme{})
				}), err: "The Transmitter Configuration Metadata 'authorization_schemes' has an entry with no 'spec_urn'."},
				{name: "Profile", configuration: valid(func(c *SSFConfiguration) { c.VerificationEndpoint = "" }), profile: true, err: "The Transmitter Configuration Metadata 'verification_endpoint' does not meet the CAEP Interoperability Profile."},
			},
		},
	}

	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			for _, tc := range group.testCases {
				t.Run(tc.name, func(t *testing.T) {
					expected := issuer

					if tc.issuer != "" || tc.noIssuer {
						expected = tc.issuer
					}

					err := ValidateSSFConfigurationForIssuer(tc.configuration, expected, tc.profile)

					provider := &Fosite{Config: &Config{Issuer: expected, SSF: &SSFConfig{EnforceCAEPInteroperabilityProfile: tc.profile}}}

					wrapped := provider.ValidateSSFConfiguration(context.Background(), tc.configuration)

					if tc.err == "" {
						assert.NoError(t, err)
						assert.NoError(t, wrapped)

						return
					}

					require.Error(t, err)
					assert.Contains(t, err.Error(), tc.err)
					assert.NotErrorIs(t, err, ErrServerError)

					// The provider method gives the same fault as the debug of a 'server_error'.
					require.ErrorIs(t, wrapped, ErrServerError)
					assert.Equal(t, err.Error(), ErrorToRFC6749Error(wrapped).DebugField)
				})
			}
		})
	}
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
		{"ShouldRejectHTTP", "http://tr.example.com", "", "issuer must use the https scheme"},
		{"ShouldRejectQuery", "https://tr.example.com/a?b=c", "", "issuer must not contain a query or fragment"},
		{"ShouldRejectFragment", "https://tr.example.com/a#b", "", "issuer must not contain a query or fragment"},
		{"ShouldRejectInvalid", "https://tr.example.com/%zz", "", "issuer is not a valid URL"},
		{"ShouldRejectEmptyQuery", "https://tr.example.com/a?", "", "issuer must not contain a query or fragment"},
		{"ShouldRejectEmptyFragment", "https://tr.example.com#", "", "issuer must not contain a query or fragment"},
		{"ShouldRejectEmptyFragmentAfterPath", "https://tr.example.com/a#", "", "issuer must not contain a query or fragment"},
		{"ShouldRejectUsername", "https://user@tr.example.com", "", "issuer must not contain userinfo"},
		{"ShouldRejectUsernameAndPassword", "https://user:pass@tr.example.com/a", "", "issuer must not contain userinfo"},
		{"ShouldRejectEmptyUserinfo", "https://@tr.example.com", "", "issuer must not contain userinfo"},
		{"ShouldRejectPortWithoutHost", "https://:443", "", "issuer must be an absolute URL"},
		{"ShouldRejectPortWithoutHostAndPath", "https://:443/a", "", "issuer must be an absolute URL"},
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
