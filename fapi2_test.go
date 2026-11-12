// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestIsFAPI2SecurityProfileClient(t *testing.T) {
	assert.True(t, IsFAPI2SecurityProfileClient(newFAPI2Client()))
	assert.False(t, IsFAPI2SecurityProfileClient(&DefaultRegisteredClient{DefaultClient: &DefaultClient{}}))
	assert.False(t, IsFAPI2SecurityProfileClient(&DefaultClient{}))
}

func TestGetAuthorizeCodeLifespan(t *testing.T) {
	testCases := []struct {
		name     string
		config   *Config
		client   Client
		expected time.Duration
	}{
		{"ShouldUseTheConfiguredLifespan", &Config{AuthorizeCodeLifespan: 5 * time.Minute}, &DefaultClient{}, 5 * time.Minute},
		{"ShouldCapTheLifespanForAFAPI2Client", &Config{AuthorizeCodeLifespan: 5 * time.Minute}, newFAPI2Client(), time.Minute},
		{"ShouldKeepAShorterLifespanForAFAPI2Client", &Config{AuthorizeCodeLifespan: 30 * time.Second}, newFAPI2Client(), 30 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetAuthorizeCodeLifespan(t.Context(), tc.config, tc.client))
		})
	}
}

func TestGetPushedAuthorizeContextLifespan(t *testing.T) {
	testCases := []struct {
		name     string
		config   *Config
		client   Client
		expected time.Duration
	}{
		{"ShouldUseTheConfiguredContextLifespan", &Config{PushedAuthorizeContextLifespan: 15 * time.Minute}, &DefaultClient{}, 15 * time.Minute},
		{"ShouldUseTheClientLifespan", &Config{PushedAuthorizeContextLifespan: 15 * time.Minute}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, PushedAuthorizeContextLifespan: 2 * time.Minute}, 2 * time.Minute},
		{"ShouldCapTheContextLifespanForAFAPI2Client", &Config{PushedAuthorizeContextLifespan: 15 * time.Minute}, newFAPI2Client(), 10*time.Minute - time.Second},
		{"ShouldKeepTheDefaultLifespanForAFAPI2Client", &Config{}, newFAPI2Client(), 5 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetPushedAuthorizeContextLifespan(t.Context(), tc.config, tc.client))
		})
	}
}

func TestFAPI2SigningAlgValues(t *testing.T) {
	rs256, ps256, es256 := string(jose.RS256), string(jose.PS256), string(jose.ES256)

	algs := []string{rs256, ps256, es256, consts.JSONWebTokenAlgNone}

	assert.Equal(t, algs, fapi2SigningAlgValues(&DefaultClient{}, algs))
	assert.Equal(t, []string{ps256, es256}, fapi2SigningAlgValues(newFAPI2Client(), algs))
	assert.Equal(t, []string{rs256, ps256, es256, consts.JSONWebTokenAlgNone}, algs)
}

func TestFAPI2SecurityProfileClientPolicies(t *testing.T) {
	config := &Config{}
	f := &Fosite{Config: config}

	assert.True(t, IsSenderConstrainedAccessTokenEnforced(t.Context(), config, newFAPI2Client()))
	assert.True(t, IsRefreshTokenRotationDisabled(t.Context(), config, newFAPI2Client()))
	assert.True(t, f.RequireRedirectURIPushedAuthorizationRequest(t.Context(), newFAPI2Client()))

	client := &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}

	assert.False(t, IsSenderConstrainedAccessTokenEnforced(t.Context(), config, client))
	assert.False(t, IsRefreshTokenRotationDisabled(t.Context(), config, client))
	assert.False(t, f.RequireRedirectURIPushedAuthorizationRequest(t.Context(), client))
}

func TestFAPI2SecurityProfileClientAuthenticationMethods(t *testing.T) {
	f := &Fosite{Config: &Config{}}

	for _, strategy := range []EndpointClientAuthStrategy{&TokenEndpointClientAuthStrategy{}, &RevocationEndpointClientAuthStrategy{}} {
		t.Run(strategy.Name(), func(t *testing.T) {
			assert.ErrorIs(t, f.checkEndpointAuthMethod(t.Context(), newFAPI2Client(), consts.ClientAuthMethodClientSecretBasic, strategy), ErrInvalidClient)
			assert.ErrorIs(t, f.checkEndpointAuthMethod(t.Context(), newFAPI2Client(), consts.ClientAuthMethodNone, strategy), ErrInvalidClient)
			assert.NoError(t, f.checkEndpointAuthMethod(t.Context(), newFAPI2Client(), consts.ClientAuthMethodPrivateKeyJWT, strategy))
			assert.NoError(t, f.checkEndpointAuthMethod(t.Context(), newFAPI2Client(), consts.ClientAuthMethodTLSClientAuth, strategy))
			assert.NoError(t, f.checkEndpointAuthMethod(t.Context(), &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}, consts.ClientAuthMethodClientSecretBasic, strategy))
		})
	}
}

func TestFAPI2SecurityProfileClientResponseTypes(t *testing.T) {
	f := &Fosite{Config: &Config{}}

	testCases := []struct {
		name         string
		responseType string
		fapi2        bool
		err          bool
	}{
		{"ShouldAllowCode", consts.ResponseTypeAuthorizationCodeFlow, true, false},
		{"ShouldRejectToken", consts.ResponseTypeImplicitFlowToken, true, true},
		{"ShouldRejectHybrid", consts.ResponseTypeHybridFlowToken, true, true},
		{"ShouldAllowTokenForAnotherClient", consts.ResponseTypeImplicitFlowToken, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newFAPI2Client()
			client.FAPI2SecurityProfile = tc.fapi2
			client.ResponseTypes = []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeHybridFlowToken}

			request := &AuthorizeRequest{Request: Request{Client: client, Form: url.Values{consts.FormParameterResponseType: {tc.responseType}}}}

			err := f.validateResponseTypes(t.Context(), nil, request)

			if tc.err {
				assert.ErrorIs(t, err, ErrUnsupportedResponseType)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFAPI2SecurityProfileClientRequiresPushedAuthorizationRequests(t *testing.T) {
	client := newFAPI2Client()

	store := &mtlsClientStore{clients: map[string]Client{client.GetID(): client}}

	f := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy}}

	query := url.Values{
		consts.FormParameterClientID:     {client.GetID()},
		consts.FormParameterRedirectURI:  {testFAPI2RedirectURI},
		consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterState:        {"strong-enough-state"},
	}

	r := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: query.Encode()}}

	_, err := f.NewAuthorizeRequest(t.Context(), r)
	require.ErrorIs(t, err, ErrInvalidRequest)
	assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "Pushed Authorization Requests are required")
}

const testFAPI2RedirectURI = "https://client.example.com/cb"

func newFAPI2Client() *DefaultRegisteredClient {
	return &DefaultRegisteredClient{
		DefaultClient: &DefaultClient{
			ID:            "fapi2-client",
			RedirectURIs:  []string{testFAPI2RedirectURI},
			ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		},
		FAPI2SecurityProfile: true,
	}
}
