// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
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
		{"ShouldCapTheClientLifespanOfAFAPI2Server", &Config{FAPI2SecurityProfile: true}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, PushedAuthorizeContextLifespan: time.Hour}, 10*time.Minute - time.Second},
		{"ShouldKeepTheClientLifespanOfAnotherServer", &Config{}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, PushedAuthorizeContextLifespan: time.Hour}, time.Hour},
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

	assert.Equal(t, algs, FilterFAPI2SecurityProfileSigningAlgValues(t.Context(), &Config{}, &DefaultClient{}, algs))
	assert.Equal(t, []string{ps256, es256}, FilterFAPI2SecurityProfileSigningAlgValues(t.Context(), &Config{}, newFAPI2Client(), algs))
	assert.Equal(t, []string{ps256, es256}, FilterFAPI2SecurityProfileSigningAlgValues(t.Context(), &Config{FAPI2SecurityProfile: true}, &DefaultClient{}, algs))
	assert.Equal(t, []string{rs256, ps256, es256, consts.JSONWebTokenAlgNone}, algs)
}

func TestGetJWTClockSkewFAPI2SecurityProfileClient(t *testing.T) {
	testCases := []struct {
		name     string
		skew     time.Duration
		client   Client
		expected time.Duration
		profile  bool
	}{
		{"ShouldKeepTheConfiguredSkew", 5 * time.Second, &DefaultClient{}, 5 * time.Second, false},
		{"ShouldKeepADisabledSkew", 0, &DefaultClient{}, 0, false},
		{"ShouldKeepALongSkew", 5 * time.Minute, &DefaultClient{}, 5 * time.Minute, false},
		{"ShouldKeepASkewWithoutAClient", 5 * time.Minute, nil, 5 * time.Minute, false},
		{"ShouldRaiseADisabledSkewForAFAPI2Client", 0, newFAPI2Client(), 10 * time.Second, false},
		{"ShouldRaiseAShortSkewForAFAPI2Client", 5 * time.Second, newFAPI2Client(), 10 * time.Second, false},
		{"ShouldKeepAPermittedSkewForAFAPI2Client", 30 * time.Second, newFAPI2Client(), 30 * time.Second, false},
		{"ShouldLowerALongSkewForAFAPI2Client", 5 * time.Minute, newFAPI2Client(), time.Minute, false},
		{"ShouldRaiseADisabledSkewForAFAPI2Server", 0, &DefaultClient{}, 10 * time.Second, true},
		{"ShouldLowerALongSkewForAFAPI2Server", 5 * time.Minute, nil, time.Minute, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &fapi2ClockSkewConfig{skew: tc.skew, profile: tc.profile}

			assert.Equal(t, tc.expected, GetJWTClockSkew(t.Context(), config, tc.client))
			assert.Equal(t, tc.expected, GetDPoPClockSkew(t.Context(), config, tc.client))
		})
	}
}

func TestFAPI2SecurityProfileEncodeOptions(t *testing.T) {
	ctx := t.Context()

	assert.Nil(t, FAPI2SecurityProfileEncodeOptions(ctx, &Config{}, nil))
	assert.Nil(t, FAPI2SecurityProfileEncodeOptions(ctx, &Config{}, &DefaultClient{}))
	assert.Nil(t, FAPI2SecurityProfileEncodeOptions(ctx, nil, &DefaultClient{}))
	assert.Len(t, FAPI2SecurityProfileEncodeOptions(ctx, &Config{}, newFAPI2Client()), 1)
	assert.Len(t, FAPI2SecurityProfileEncodeOptions(ctx, &Config{FAPI2SecurityProfile: true}, &DefaultClient{}), 1)
	assert.Len(t, FAPI2SecurityProfileEncodeOptions(ctx, &Config{FAPI2SecurityProfile: true}, nil), 1)
}

func TestDPoPProofClientContext(t *testing.T) {
	client := newFAPI2Client()

	assert.Nil(t, DPoPProofClientFromContext(t.Context()))
	assert.Nil(t, DPoPProofClientFromContext(NewDPoPProofClientContext(t.Context(), nil)))
	assert.Equal(t, Client(client), DPoPProofClientFromContext(NewDPoPProofClientContext(t.Context(), client)))
}

func TestSetFAPI2SecurityProfileIssuer(t *testing.T) {
	const issuer = "https://auth.example.com"

	testCases := []struct {
		name     string
		config   *Config
		client   Client
		mode     ResponseModeType
		existing string
		expected string
	}{
		{"ShouldSetTheIssuerWithoutAHandler", &Config{Issuer: issuer, DisableAuthorizationServerIdentification: true}, newFAPI2Client(), ResponseModeQuery, "", issuer},
		{"ShouldSetTheIssuerForTheDefaultMode", &Config{Issuer: issuer}, newFAPI2Client(), ResponseModeDefault, "", issuer},
		{"ShouldKeepAnIssuerAlreadySet", &Config{Issuer: issuer}, newFAPI2Client(), ResponseModeQuery, "https://other.example.com", "https://other.example.com"},
		{"ShouldNotSetTheIssuerForAJWTMode", &Config{Issuer: issuer}, newFAPI2Client(), ResponseModeQueryJWT, "", ""},
		{"ShouldNotSetTheIssuerForAnotherClient", &Config{Issuer: issuer}, &DefaultClient{ID: "other"}, ResponseModeQuery, "", ""},
		{"ShouldNotSetAnEmptyIssuer", &Config{}, newFAPI2Client(), ResponseModeQuery, "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := NewAuthorizeRequest()
			request.Client = tc.client

			parameters := url.Values{}

			if tc.existing != "" {
				parameters.Set(consts.FormParameterIssuer, tc.existing)
			}

			setFAPI2SecurityProfileIssuer(t.Context(), tc.config, request, tc.mode, parameters)

			assert.Equal(t, tc.expected, parameters.Get(consts.FormParameterIssuer))
		})
	}
}

func TestDPoPProofClientIsCarriedToTheStrategy(t *testing.T) {
	client := newFAPI2Client()

	t.Run("ShouldCarryTheClientOfAPushedAuthorizationRequest", func(t *testing.T) {
		strategy := &fapi2DPoPStrategy{}

		f := &Fosite{Config: &Config{DPoPEnabled: true, DPoPStrategy: strategy}}

		r := &http.Request{Method: http.MethodPost, Header: http.Header{}, URL: &url.URL{Path: "/par"}}
		r.Header.Set(consts.HeaderDPoP, "proof")

		request := NewAuthorizeRequest()
		request.Client = client

		require.ErrorIs(t, f.handlePushedAuthorizeRequestDPoP(t.Context(), r, request), ErrInvalidDPoPProof)
		assert.Equal(t, Client(client), strategy.client)
	})

	t.Run("ShouldCarryTheClientOfABoundAccessToken", func(t *testing.T) {
		strategy := &fapi2DPoPStrategy{}

		requester := NewRequest()
		requester.Client = client
		requester.Session = &DefaultSession{JWKThumbprint: "some-jkt"}

		require.ErrorIs(t, validateBearerProofOfPossession(t.Context(), &Config{DPoPEnabled: true, DPoPStrategy: strategy}, newBearerRequest(), requester, requester.GetClient(), "token", nil), ErrInvalidDPoPProof)
		assert.Equal(t, Client(client), strategy.client)
	})
}

func TestRequestObjectClockSkewFAPI2SecurityProfileClient(t *testing.T) {
	testCases := []struct {
		name   string
		fapi2  bool
		future time.Duration
		err    bool
	}{
		{name: "ShouldRejectTheNearFutureWithoutSkew", future: 6 * time.Second, err: true},
		{name: "ShouldAcceptTheNearFutureFromAFAPI2ClientWithoutSkew", fapi2: true, future: 6 * time.Second},
		{name: "ShouldRejectTheFarFutureFromAFAPI2ClientWithoutSkew", fapi2: true, future: 2 * time.Minute, err: true},
	}

	key := gen.MustES256Key()

	private := &jose.JSONWebKey{Key: key, KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature}
	public := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature}}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newFAPI2Client()
			client.FAPI2SecurityProfile = tc.fapi2
			client.JSONWebKeys = public
			client.RequestObjectSigningAlg = string(jose.ES256)

			future := time.Now().Add(tc.future).Unix()

			claims := jwt.MapClaims{
				consts.ClaimIssuer:               client.GetID(),
				consts.ClaimAudience:             []string{"https://auth.example.com"},
				consts.ClaimIssuedAt:             future,
				consts.ClaimNotBefore:            future,
				consts.ClaimExpirationTime:       time.Now().Add(5 * time.Minute).Unix(),
				consts.ClaimClientIdentifier:     client.GetID(),
				consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow,
			}

			r := &AuthorizeRequest{
				Request: Request{
					Client: client,
					Form: url.Values{
						consts.FormParameterClientID:     {client.GetID()},
						consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
						consts.FormParameterRequest:      {mustGenerateRequestObjectJWS(t, claims, nil, private)},
					},
				},
			}

			config := &Config{JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(), Issuer: "https://auth.example.com", JWTClockSkew: -1}
			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*private}})}

			err := (&Fosite{Config: config}).authorizeRequestParametersFromJAR(t.Context(), r, false)

			if tc.err {
				require.ErrorIs(t, err, ErrInvalidRequestObject)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
		})
	}
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

type fapi2DPoPStrategy struct {
	DPoPStrategy

	client Client
}

func (s *fapi2DPoPStrategy) ValidateDPoPProof(ctx context.Context, _, _, _ string, _ bool, _ ...string) (*DPoPProof, error) {
	s.client = DPoPProofClientFromContext(ctx)

	return nil, ErrInvalidDPoPProof
}

func (s *fapi2DPoPStrategy) ValidateResourceAccess(ctx context.Context, _ *http.Request, _, _ string, _ bool, _ ...string) (*DPoPProof, error) {
	s.client = DPoPProofClientFromContext(ctx)

	return nil, ErrInvalidDPoPProof
}

type fapi2ClockSkewConfig struct {
	skew    time.Duration
	profile bool
}

func (c *fapi2ClockSkewConfig) GetFAPI2SecurityProfile(_ context.Context) bool {
	return c.profile
}

func (c *fapi2ClockSkewConfig) GetJWTClockSkew(_ context.Context) time.Duration {
	return c.skew
}

func (c *fapi2ClockSkewConfig) GetDPoPClockSkew(_ context.Context) time.Duration {
	return c.skew
}

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
