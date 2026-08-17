// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthorizeRequestParametersFromJARRequireSignedRequestObject(t *testing.T) {
	keyRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkPublicSigRSA := &jose.JSONWebKey{
		Key:       keyRSA.Public(),
		KeyID:     "rs256-sig",
		Algorithm: string(jose.RS256),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkPrivateSigRSA := &jose.JSONWebKey{
		Key:       keyRSA,
		KeyID:     "rs256-sig",
		Algorithm: string(jose.RS256),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkNone := &jose.JSONWebKey{
		Key: jwt.UnsafeAllowNoneSignatureType,
	}

	jwksPublic := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*jwkPublicSigRSA}}
	jwksPrivate := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*jwkPrivateSigRSA}}

	claims := jwt.MapClaims{
		consts.FormParameterScope:        consts.ScopeOpenID,
		consts.FormParameterState:        "some-state-value-that-is-long-enough",
		consts.FormParameterClientID:     "foo",
		consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow,
		consts.ClaimIssuer:               "foo",
		consts.ClaimAudience:             []string{"https://auth.example.com"},
	}

	assertionSigned := mustGenerateRequestObjectJWS(t, claims, nil, jwkPrivateSigRSA)
	assertionNone := mustGenerateRequestObjectJWS(t, claims, nil, jwkNone)

	baseForm := func(extra url.Values) url.Values {
		form := url.Values{
			consts.FormParameterScope:        {consts.ScopeOpenID},
			consts.FormParameterClientID:     {"foo"},
			consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
		}

		for k, v := range extra {
			form[k] = v
		}

		return form
	}

	testCases := []struct {
		name           string
		serverRequires bool
		skipPAR        bool
		par            bool
		client         Client
		have           url.Values
		err            error
		errString      string
	}{
		{
			name:           "ShouldPassAbsentRequestObjectWhenNotRequired",
			serverRequires: false,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(nil),
		},
		{
			name:           "ShouldFailAbsentRequestObjectForPARWhenSkipDisabled",
			serverRequires: true,
			skipPAR:        false,
			par:            true,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(nil),
			err:            ErrInvalidRequest,
		},
		{
			name:           "ShouldPassAbsentRequestObjectForPARWhenSkipEnabledAndRequiredByServer",
			serverRequires: true,
			skipPAR:        true,
			par:            true,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(nil),
		},
		{
			name:           "ShouldPassAbsentRequestObjectForPARWhenSkipEnabledAndRequiredByClient",
			serverRequires: false,
			skipPAR:        true,
			par:            true,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, RequireSignedRequestObject: true, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(nil),
		},
		{
			name:           "ShouldFailAbsentRequestObjectAtAuthorizeEndpointWhenSkipEnabled",
			serverRequires: true,
			skipPAR:        true,
			par:            false,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(nil),
			err:            ErrInvalidRequest,
		},
		{
			name:           "ShouldFailAbsentRequestObjectWhenRequiredByServer",
			serverRequires: true,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(nil),
			err:            ErrInvalidRequest,
			errString:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 requests must be protected as a Request Object provided by either the 'request' or 'request_uri' parameter, but neither parameter was included in this request. The OAuth 2.0 client with id 'foo' is subject to a policy which requires a signed request object but neither the 'request' nor 'request_uri' parameter was included in the request.",
		},
		{
			name:           "ShouldFailAbsentRequestObjectWhenRequiredByClient",
			serverRequires: false,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, RequireSignedRequestObject: true, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(nil),
			err:            ErrInvalidRequest,
			errString:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 requests must be protected as a Request Object provided by either the 'request' or 'request_uri' parameter, but neither parameter was included in this request. The OAuth 2.0 client with id 'foo' is subject to a policy which requires a signed request object but neither the 'request' nor 'request_uri' parameter was included in the request.",
		},
		{
			name:           "ShouldFailRegisteredAlgNoneWhenRequired",
			serverRequires: false,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: consts.JSONWebTokenAlgNone, RequireSignedRequestObject: true, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(url.Values{consts.FormParameterRequest: {assertionNone}}),
			err:            ErrInvalidRequest,
			errString:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 requests must be protected as a signed Request Object, but the OAuth 2.0 Client is registered with a 'request_object_signing_alg' value of 'none'. The OAuth 2.0 client with id 'foo' is subject to a policy which requires a signed request object but the client is registered with a 'request_object_signing_alg' value of 'none'.",
		},
		{
			name:           "ShouldFailUnsignedRequestObjectWhenRequiredAndAlgUnregistered",
			serverRequires: true,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(url.Values{consts.FormParameterRequest: {assertionNone}}),
			err:            ErrInvalidRequestObject,
		},
		{
			name:           "ShouldPassSignedRequestObjectWhenRequiredByServer",
			serverRequires: true,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(url.Values{consts.FormParameterRequest: {assertionSigned}}),
		},
		{
			name:           "ShouldPassSignedRequestObjectWhenRequiredByClient",
			serverRequires: false,
			client:         &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", RequireSignedRequestObject: true, DefaultClient: &DefaultClient{ID: "foo"}},
			have:           baseForm(url.Values{consts.FormParameterRequest: {assertionSigned}}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &AuthorizeRequest{
				Request: Request{
					Client: tc.client,
					Form:   tc.have,
				},
			}

			config := &Config{
				JWKSFetcherStrategy:        NewDefaultJWKSFetcherStrategy(),
				IDTokenIssuer:              "https://auth.example.com",
				RequireSignedRequestObject: tc.serverRequires,
				RequireSignedRequestObjectSkipPushedAuthorizationRequests: tc.skipPAR,
			}

			config.JWTStrategy = &jwt.DefaultStrategy{
				Config: config,
				Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(jwksPrivate),
			}

			provider := &Fosite{Config: config}

			actual := provider.authorizeRequestParametersFromJAR(context.Background(), r, tc.par)

			if tc.err != nil {
				require.Error(t, actual)
				assert.EqualError(t, actual, tc.err.Error())

				if tc.errString != "" {
					assert.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.errString)
				}

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
		})
	}
}

func TestRequireSignedRequestObjectResolution(t *testing.T) {
	ctx := context.Background()

	clientPlain := &DefaultClient{ID: "foo"}
	clientJARFalse := &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo"}}
	clientJARTrue := &DefaultJARClient{RequireSignedRequestObject: true, DefaultClient: &DefaultClient{ID: "foo"}}

	configSkipPAR := &Config{RequireSignedRequestObjectSkipPushedAuthorizationRequests: true}

	testCases := []struct {
		name     string
		config   Configurator
		client   Client
		par      bool
		expected bool
	}{
		{"ShouldNotRequireWithBareClientAndConfig", &Config{}, clientPlain, false, false},
		{"ShouldNotRequireWithJARClientOptedOut", &Config{}, clientJARFalse, false, false},
		{"ShouldRequireWithJARClientOptedIn", &Config{}, clientJARTrue, false, true},
		{"ShouldRequireWithServerPolicy", &Config{RequireSignedRequestObject: true}, clientPlain, false, true},
		{"ShouldRequireWithServerPolicyOverridingClient", &Config{RequireSignedRequestObject: true}, clientJARFalse, false, true},
		{"ShouldRequireForPARWhenSkipDisabled", &Config{RequireSignedRequestObject: true}, clientJARTrue, true, true},
		{"ShouldNotRequireForPARWhenSkipEnabledWithServerPolicy", &Config{RequireSignedRequestObject: true, RequireSignedRequestObjectSkipPushedAuthorizationRequests: true}, clientPlain, true, false},
		{"ShouldNotRequireForPARWhenSkipEnabledWithClientPolicy", configSkipPAR, clientJARTrue, true, false},
		{"ShouldRequireAtAuthorizeEndpointWhenSkipEnabled", configSkipPAR, clientJARTrue, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: tc.config}

			assert.Equal(t, tc.expected, provider.requireSignedRequestObject(ctx, tc.client, tc.par))
		})
	}
}
