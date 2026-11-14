// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	audienceTestIssuer   = "https://as.example.com"
	audienceTestTokenURL = "https://as.example.com/token" //nolint:gosec
	audienceTestMTLSURL  = "https://mtls.as.example.com/token"
	audienceTestPARURL   = "https://as.example.com/par"
	audienceTestRevURL   = "https://as.example.com/revoke"
	audienceTestIntURL   = "https://as.example.com/introspect"
	audienceTestDevURL   = "https://as.example.com/device"
	audienceTestCIBAURL  = "https://as.example.com/ciba"
	audienceTestCIBAMTLS = "https://mtls.as.example.com/ciba"
	audienceTestListed   = "https://legacy.example.com"
	audienceTestOther    = "https://other.example.com"
	audienceTestSecret   = "0123456789abcdef0123456789abcdef"

	audienceTestRSA = "rsa"
	audienceTestHS  = "hs"

	audienceTestPAR           = "par"
	audienceTestDevice        = "device"
	audienceTestBackChannel   = string(ClientAuthEndpointBackChannelAuthentication)
	audienceTestRevocation    = string(ClientAuthEndpointRevocation)
	audienceTestIntrospection = string(ClientAuthEndpointIntrospection)

	audienceTestErrInvalid  = "invalid audience"
	audienceTestErrSole     = "sole audience value"
	audienceTestErrSingle   = "must carry exactly one of"
	audienceTestErrNoIssuer = "no issuer identifier configured"
)

func TestClientAssertionAudience(t *testing.T) {
	testCases := []struct {
		name     string
		disable  bool
		config   func(config *Config)
		method   string
		endpoint string
		typ      string
		aud      any
		err      string
	}{
		{name: "ShouldAcceptTheIssuerAsAString", aud: audienceTestIssuer},
		{name: "ShouldAcceptTheIssuerAsASingleElementArray", aud: []string{audienceTestIssuer}},
		{name: "ShouldRejectTheTokenEndpointURL", aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectTheMutualTLSTokenEndpointAlias", aud: audienceTestMTLSURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectThePushedAuthorizationRequestEndpointURL", aud: audienceTestPARURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectAConfiguredAudience", aud: audienceTestListed, err: audienceTestErrInvalid},
		{name: "ShouldRejectAnUnknownAudience", aud: audienceTestOther, err: audienceTestErrInvalid},
		{name: "ShouldRejectTheIssuerWithATrailingSlash", aud: audienceTestIssuer + "/", err: audienceTestErrInvalid},
		{name: "ShouldRejectAMissingAudience", err: audienceTestErrInvalid},
		{name: "ShouldRejectTheIssuerAlongsideTheTokenEndpointURL", aud: []string{audienceTestIssuer, audienceTestTokenURL}, err: audienceTestErrSole},
		{name: "ShouldRejectTheIssuerRepeated", aud: []string{audienceTestIssuer, audienceTestIssuer}, err: audienceTestErrSole},
		{
			name:   "ShouldRejectWhenTheIssuerIsUnset",
			config: func(config *Config) { config.Issuer = "" },
			aud:    audienceTestTokenURL,
			err:    audienceTestErrNoIssuer,
		},
		{
			name:   "ShouldRejectAnEmptyAudienceWhenTheIssuerIsUnset",
			config: func(config *Config) { config.Issuer = "" },
			aud:    "",
			err:    audienceTestErrNoIssuer,
		},
		{name: "ShouldAcceptTheClientAuthenticationType", typ: jwt.JSONWebTokenTypeClientAuthentication, aud: audienceTestIssuer},
		{name: "ShouldAcceptTheClientAuthenticationMediaType", typ: "application/client-authentication+jwt", aud: audienceTestIssuer},
		{name: "ShouldAcceptTheJWTType", typ: consts.JSONWebTokenTypeJWT, aud: audienceTestIssuer},
		{name: "ShouldAcceptAnAbsentType", typ: "-", aud: audienceTestIssuer},
		{name: "ShouldRejectAnotherExplicitType", typ: consts.JSONWebTokenTypeAccessToken, aud: audienceTestIssuer, err: "'typ' header value"},
		{name: "ShouldAcceptTheIssuerWithClientSecretJWT", method: consts.ClientAuthMethodClientSecretJWT, aud: audienceTestIssuer},
		{name: "ShouldRejectTheTokenEndpointURLWithClientSecretJWT", method: consts.ClientAuthMethodClientSecretJWT, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerAtTheRevocationEndpoint", endpoint: audienceTestRevocation, aud: audienceTestIssuer},
		{name: "ShouldRejectTheTokenEndpointURLAtTheRevocationEndpoint", endpoint: audienceTestRevocation, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerAtTheIntrospectionEndpoint", endpoint: audienceTestIntrospection, aud: audienceTestIssuer},
		{name: "ShouldRejectTheTokenEndpointURLAtTheIntrospectionEndpoint", endpoint: audienceTestIntrospection, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerAtThePushedAuthorizationRequestEndpoint", endpoint: audienceTestPAR, aud: audienceTestIssuer},
		{name: "ShouldRejectThePushedAuthorizationRequestEndpointURLAtThatEndpoint", endpoint: audienceTestPAR, aud: audienceTestPARURL, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerAtTheDeviceAuthorizationEndpoint", endpoint: audienceTestDevice, aud: audienceTestIssuer},
		{name: "ShouldRejectTheTokenEndpointURLAtTheDeviceAuthorizationEndpoint", endpoint: audienceTestDevice, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerWhenDisabled", disable: true, aud: audienceTestIssuer},
		{name: "ShouldAcceptTheTokenEndpointURLWhenDisabled", disable: true, aud: audienceTestTokenURL},
		{name: "ShouldAcceptTheMutualTLSTokenEndpointAliasWhenDisabled", disable: true, aud: audienceTestMTLSURL},
		{name: "ShouldRejectThePushedAuthorizationRequestEndpointURLAtTheTokenEndpointWhenDisabled", disable: true, aud: audienceTestPARURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectAConfiguredAudienceWhenDisabled", disable: true, aud: audienceTestListed, err: audienceTestErrInvalid},
		{name: "ShouldRejectMultipleAudiencesWhenDisabled", disable: true, aud: []string{audienceTestOther, audienceTestTokenURL}, err: audienceTestErrSingle},
		{name: "ShouldRejectTheIssuerAlongsideTheTokenEndpointURLWhenDisabled", disable: true, aud: []string{audienceTestIssuer, audienceTestTokenURL}, err: audienceTestErrSingle},
		{name: "ShouldRejectTheTokenEndpointURLRepeatedWhenDisabled", disable: true, aud: []string{audienceTestTokenURL, audienceTestTokenURL}, err: audienceTestErrSingle},
		{name: "ShouldRejectAnUnknownAudienceWhenDisabled", disable: true, aud: audienceTestOther, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerAtThePushedAuthorizationRequestEndpointWhenDisabled", disable: true, endpoint: audienceTestPAR, aud: audienceTestIssuer},
		{name: "ShouldAcceptThePushedAuthorizationRequestEndpointURLAtThatEndpointWhenDisabled", disable: true, endpoint: audienceTestPAR, aud: audienceTestPARURL},
		{name: "ShouldRejectTheTokenEndpointURLAtThePushedAuthorizationRequestEndpointWhenDisabled", disable: true, endpoint: audienceTestPAR, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectMultipleAudiencesAtThePushedAuthorizationRequestEndpointWhenDisabled", disable: true, endpoint: audienceTestPAR, aud: []string{audienceTestIssuer, audienceTestPARURL}, err: audienceTestErrSingle},
		{name: "ShouldAcceptTheIssuerAtTheRevocationEndpointWhenDisabled", disable: true, endpoint: audienceTestRevocation, aud: audienceTestIssuer},
		{name: "ShouldAcceptTheRevocationEndpointURLAtThatEndpointWhenDisabled", disable: true, endpoint: audienceTestRevocation, aud: audienceTestRevURL},
		{name: "ShouldRejectTheTokenEndpointURLAtTheRevocationEndpointWhenDisabled", disable: true, endpoint: audienceTestRevocation, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerAtTheIntrospectionEndpointWhenDisabled", disable: true, endpoint: audienceTestIntrospection, aud: audienceTestIssuer},
		{name: "ShouldAcceptTheIntrospectionEndpointURLAtThatEndpointWhenDisabled", disable: true, endpoint: audienceTestIntrospection, aud: audienceTestIntURL},
		{name: "ShouldRejectTheTokenEndpointURLAtTheIntrospectionEndpointWhenDisabled", disable: true, endpoint: audienceTestIntrospection, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldAcceptTheIssuerAtTheDeviceAuthorizationEndpointWhenDisabled", disable: true, endpoint: audienceTestDevice, aud: audienceTestIssuer},
		{name: "ShouldAcceptTheDeviceAuthorizationEndpointURLAtThatEndpointWhenDisabled", disable: true, endpoint: audienceTestDevice, aud: audienceTestDevURL},
		{name: "ShouldRejectTheTokenEndpointURLAtTheDeviceAuthorizationEndpointWhenDisabled", disable: true, endpoint: audienceTestDevice, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{
			name:     "ShouldAcceptOnlyTheIssuerAtAnEndpointWithoutAURLWhenDisabled",
			disable:  true,
			endpoint: audienceTestRevocation,
			config:   func(config *Config) { config.EndpointURLs.Revocation = "" },
			aud:      audienceTestRevURL,
			err:      audienceTestErrInvalid,
		},
		{
			name:    "ShouldAcceptTheTokenEndpointURLWhenDisabledWithoutAnIssuer",
			disable: true,
			config:  func(config *Config) { config.Issuer = "" },
			aud:     audienceTestTokenURL,
		},
		{
			name:    "ShouldRejectAnEmptyAudienceWhenDisabledWithoutAnIssuer",
			disable: true,
			config:  func(config *Config) { config.Issuer = "" },
			aud:     "",
			err:     audienceTestErrInvalid,
		},
		{
			name:    "ShouldRejectWhenDisabledWithoutAnyAudience",
			disable: true,
			config: func(config *Config) {
				config.Issuer = ""
				config.EndpointURLs = EndpointURLs{}
				config.AllowedJWTAssertionAudiences = nil
			},
			aud: audienceTestTokenURL,
			err: "could not determine any safe value",
		},
	}

	key := gen.MustRSAKey()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider := newAudienceTestProvider(key)
			config.DisableClientAssertionIssuerAudience = tc.disable

			if tc.config != nil {
				tc.config(config)
			}

			form := url.Values{
				consts.FormParameterClientAssertion:     {newAudienceTestAssertion(t, key, tc.method, tc.typ, tc.aud)},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
			}

			err := authenticateAudienceTestClient(t, config, provider, tc.endpoint, form)

			if tc.err == "" {
				switch tc.endpoint {
				case audienceTestPAR, audienceTestDevice:
					assert.NotErrorIs(t, err, ErrInvalidClient, "%+v", ErrorToDebugRFC6749Error(err))
				default:
					require.NoError(t, ErrorToDebugRFC6749Error(err))
				}

				return
			}

			require.ErrorIs(t, err, ErrInvalidClient)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}
}

func TestClientAssertionAudienceBackChannelEndpoint(t *testing.T) {
	testCases := []struct {
		name     string
		disable  bool
		endpoint string
		aud      any
		err      string
	}{
		{name: "ShouldAcceptTheBackChannelEndpointURL", disable: true, endpoint: audienceTestBackChannel, aud: audienceTestCIBAURL},
		{name: "ShouldAcceptTheBackChannelEndpointMutualTLSAlias", disable: true, endpoint: audienceTestBackChannel, aud: audienceTestCIBAMTLS},
		{name: "ShouldRejectTheTokenEndpointURL", disable: true, endpoint: audienceTestBackChannel, aud: audienceTestTokenURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectMultipleAudiences", disable: true, endpoint: audienceTestBackChannel, aud: []string{audienceTestIssuer, audienceTestCIBAURL}, err: audienceTestErrSingle},
		{name: "ShouldAcceptTheIssuer", disable: true, endpoint: audienceTestBackChannel, aud: audienceTestIssuer},
		{name: "ShouldAcceptTheIssuerWhenEnforced", endpoint: audienceTestBackChannel, aud: audienceTestIssuer},
		{name: "ShouldRejectTheBackChannelEndpointURLWhenEnforced", endpoint: audienceTestBackChannel, aud: audienceTestCIBAURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectAnUnknownAudience", disable: true, endpoint: audienceTestBackChannel, aud: audienceTestOther, err: audienceTestErrInvalid},
		{name: "ShouldRejectTheBackChannelEndpointURLAtTheTokenEndpoint", disable: true, aud: audienceTestCIBAURL, err: audienceTestErrInvalid},
		{name: "ShouldRejectTheBackChannelEndpointMutualTLSAliasAtTheTokenEndpoint", disable: true, aud: audienceTestCIBAMTLS, err: audienceTestErrInvalid},
	}

	key := gen.MustRSAKey()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider := newAudienceTestProvider(key)
			config.DisableClientAssertionIssuerAudience = tc.disable

			form := url.Values{
				consts.FormParameterClientAssertion:     {newAudienceTestAssertion(t, key, "", "", tc.aud)},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
			}

			err := authenticateAudienceTestClient(t, config, provider, tc.endpoint, form)

			if tc.err == "" {
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, ErrInvalidClient)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}
}

func TestClientAssertionAudienceDefaultsToEnforced(t *testing.T) {
	config := &Config{}

	assert.False(t, config.GetDisableClientAssertionIssuerAudience(t.Context()))
}

func newAudienceTestProvider(key *rsa.PrivateKey) (config *Config, provider *Fosite) {
	config = &Config{
		JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(),
		Issuer:              audienceTestIssuer,
		EndpointURLs: EndpointURLs{
			Token:                      audienceTestTokenURL,
			PushedAuthorizationRequest: audienceTestPARURL,
			Revocation:                 audienceTestRevURL,
			Introspection:              audienceTestIntURL,
			DeviceAuthorization:        audienceTestDevURL,
			BackChannelAuthentication:  audienceTestCIBAURL,
			MutualTLSAliases:           RFC8705MutualTLSEndpointAliases{Token: audienceTestMTLSURL, BackChannelAuthentication: audienceTestCIBAMTLS},
		},
		AllowedJWTAssertionAudiences: []string{audienceTestListed},
	}

	config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	store := storage.NewMemoryStore()
	store.Clients[audienceTestRSA] = &DefaultJARClient{
		DefaultClient: &DefaultClient{
			ID:         audienceTestRSA,
			GrantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeOAuthDeviceCode},
		},
		JSONWebKeys: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{KeyID: "kid-foo", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}},
		},
		TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
	}
	store.Clients[audienceTestHS] = &DefaultJARClient{
		DefaultClient:           &DefaultClient{ID: audienceTestHS, ClientSecret: NewPlainTextClientSecret(audienceTestSecret)},
		TokenEndpointAuthMethod: consts.ClientAuthMethodClientSecretJWT,
	}

	return config, &Fosite{Store: store, Config: config}
}

func newAudienceTestAssertion(t *testing.T, key *rsa.PrivateKey, method, typ string, aud any) string {
	t.Helper()

	id := audienceTestRSA
	if method == consts.ClientAuthMethodClientSecretJWT {
		id = audienceTestHS
	}

	claims := jwt.MapClaims{
		consts.ClaimSubject:        id,
		consts.ClaimIssuer:         id,
		consts.ClaimJWTID:          time.Now().String(),
		consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
	}

	if aud != nil {
		claims[consts.ClaimAudience] = aud
	}

	if method == consts.ClientAuthMethodClientSecretJWT {
		return mustGenerateHSAssertion(t, claims, []byte(audienceTestSecret))
	}

	switch typ {
	case "":
		typ = jwt.JSONWebTokenTypeClientAuthentication
	case "-":
		typ = ""
	}

	return mustGenerateClientAssertion(t, claims, jose.RS256, typ, "kid-foo", key)
}

func authenticateAudienceTestClient(t *testing.T, config *Config, provider *Fosite, endpoint string, form url.Values) (err error) {
	t.Helper()

	ctx := t.Context()

	switch endpoint {
	case audienceTestRevocation:
		_, _, err = provider.AuthenticateClientWithAuthHandler(ctx, new(http.Request), form, config.GetRevocationEndpointClientAuthStrategy(ctx))
	case audienceTestIntrospection:
		_, _, err = provider.AuthenticateClientWithAuthHandler(ctx, new(http.Request), form, config.GetIntrospectionEndpointClientAuthStrategy(ctx))
	case audienceTestPAR:
		_, err = provider.NewPushedAuthorizeRequest(ctx, newAudienceTestFormRequest(audienceTestPARURL, form))
	case audienceTestBackChannel:
		_, _, err = provider.AuthenticateClientWithAuthHandler(ctx, new(http.Request), form, &BackChannelAuthenticationEndpointClientAuthStrategy{})
	case audienceTestDevice:
		_, err = provider.NewRFC862DeviceAuthorizeRequest(ctx, newAudienceTestFormRequest(audienceTestDevURL, form))
	default:
		_, _, err = provider.AuthenticateClientWithAuthHandler(ctx, new(http.Request), form, config.GetTokenEndpointClientAuthStrategy(ctx))
	}

	return err
}

func newAudienceTestFormRequest(target string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	return r
}
