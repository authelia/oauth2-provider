package jarm

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestEncodeParameters(t *testing.T) {
	testCases := []struct {
		name      string
		token     string
		signature string
		tErr      error
		expected  url.Values
		err       string
	}{
		{
			name:     "ShouldReturnURLValuesWithResponseToken",
			token:    "signed.jwt.token",
			expected: url.Values{consts.FormParameterResponse: []string{"signed.jwt.token"}},
		},
		{
			name:     "ShouldReturnURLValuesIgnoringSignature",
			token:    "header.payload.sig",
			expected: url.Values{consts.FormParameterResponse: []string{"header.payload.sig"}},
		},
		{
			name: "ShouldReturnErrorWhenTokenErrIsNotNil",
			tErr: errors.New("generate failed"),
			err:  "generate failed",
		},
		{
			name:     "ShouldReturnURLValuesWithEmptyTokenWhenNoError",
			token:    "",
			expected: url.Values{consts.FormParameterResponse: []string{""}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := EncodeParameters(tc.token, tc.signature, tc.tErr)

			if tc.err != "" {
				assert.Nil(t, actual)
				require.Error(t, err)
				assert.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestGenerate(t *testing.T) {
	testCases := []struct {
		name       string
		config     *stubConfigurator
		client     Client
		session    any
		parameters url.Values
		err        string
		checkToken func(t *testing.T, token, signature string, strategy *stubStrategy)
	}{
		{
			name: "ShouldFailWhenSessionIsNilAndNoConfiguredIssuer",
			config: &stubConfigurator{
				strategy: &stubStrategy{token: "stub.token"},
			},
			client:  &stubClient{id: "client-id"},
			session: nil,
			err:     "The JARM response modes require the Authorize Requester session to be set but it wasn't.",
		},
		{
			name: "ShouldFailWhenSessionImplementsNeitherInterface",
			config: &stubConfigurator{
				strategy: &stubStrategy{token: "stub.token"},
			},
			client:  &stubClient{id: "client-id"},
			session: struct{}{},
			err:     "The JARM response modes require the Authorize Requester session to implement either the openid.Session or oauth2.JWTSessionContainer interfaces but it doesn't.",
		},
		{
			name: "ShouldFailWhenStrategyIsNil",
			config: &stubConfigurator{
				issuer: "https://issuer.example.com",
			},
			client:  &stubClient{id: "client-id"},
			session: struct{}{},
			err:     "The JARM response modes require the JWTSecuredAuthorizeResponseModeSignerProvider to return a jwt.Strategy but it didn't.",
		},
		{
			name: "ShouldUseConfiguredIssuerOverSessionIssuer",
			config: &stubConfigurator{
				issuer:   "https://config.example.com",
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client:  &stubClient{id: "client-id"},
			session: nil,
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				assert.Equal(t, "tok", token)
				assert.Equal(t, "https://config.example.com", strategy.lastClaims[jwt.ClaimIssuer])
				assert.Equal(t, []string{"client-id"}, strategy.lastClaims[jwt.ClaimAudience])
			},
		},
		{
			name: "ShouldExtractIssuerFromOpenIDSession",
			config: &stubConfigurator{
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id"},
			session: &openIDSession{
				claims: &jwt.IDTokenClaims{Issuer: "https://session.example.com"},
			},
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				assert.Equal(t, "https://session.example.com", strategy.lastClaims[jwt.ClaimIssuer])
			},
		},
		{
			name: "ShouldExtractIssuerFromJWTSessionContainer",
			config: &stubConfigurator{
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id"},
			session: &jwtSessionContainer{
				claims: &jwt.JWTClaims{Issuer: "https://jwt-session.example.com"},
			},
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				assert.Equal(t, "https://jwt-session.example.com", strategy.lastClaims[jwt.ClaimIssuer])
			},
		},
		{
			name: "ShouldOmitIssuerWhenSessionHasNone",
			config: &stubConfigurator{
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id"},
			session: &openIDSession{
				claims: &jwt.IDTokenClaims{},
			},
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				_, ok := strategy.lastClaims[jwt.ClaimIssuer]
				assert.False(t, ok, "issuer should not be set when both config and session lack one")
			},
		},
		{
			name: "ShouldEncodeSingleValueParametersAsScalar",
			config: &stubConfigurator{
				issuer:   "https://issuer.example.com",
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id"},
			parameters: url.Values{
				"code":  {"abc"},
				"state": {"xyz"},
			},
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				assert.Equal(t, "abc", strategy.lastClaims["code"])
				assert.Equal(t, "xyz", strategy.lastClaims["state"])
			},
		},
		{
			name: "ShouldEncodeMultiValueParametersAsSlice",
			config: &stubConfigurator{
				issuer:   "https://issuer.example.com",
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id"},
			parameters: url.Values{
				"scope": {"openid", "profile"},
			},
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				assert.Equal(t, []string{"openid", "profile"}, strategy.lastClaims["scope"])
			},
		},
		{
			name: "ShouldSkipEmptyValueSlices",
			config: &stubConfigurator{
				issuer:   "https://issuer.example.com",
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id"},
			parameters: url.Values{
				"empty": {},
				"code":  {"abc"},
			},
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				_, ok := strategy.lastClaims["empty"]
				assert.False(t, ok, "empty value slice must not be encoded")
				assert.Equal(t, "abc", strategy.lastClaims["code"])
			},
		},
		{
			name: "ShouldEncodeWithAlgAndKidConfigured",
			config: &stubConfigurator{
				issuer:   "https://issuer.example.com",
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id", alg: "RS256", kid: "key-1"},
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				assert.Equal(t, "tok", token)
				assert.Equal(t, "https://issuer.example.com", strategy.lastClaims[jwt.ClaimIssuer])
			},
		},
		{
			name: "ShouldEncodeWhenAlgAndKidUnset",
			config: &stubConfigurator{
				issuer:   "https://issuer.example.com",
				strategy: &stubStrategy{token: "tok"},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id"},
			checkToken: func(t *testing.T, token, signature string, strategy *stubStrategy) {
				assert.Equal(t, "tok", token)
				assert.Equal(t, "https://issuer.example.com", strategy.lastClaims[jwt.ClaimIssuer])
			},
		},
		{
			name: "ShouldReturnStrategyError",
			config: &stubConfigurator{
				issuer:   "https://issuer.example.com",
				strategy: &stubStrategy{err: errors.New("strategy failure")},
				lifespan: time.Hour,
			},
			client: &stubClient{id: "client-id"},
			err:    "strategy failure",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, signature, err := Generate(context.Background(), tc.config, tc.client, tc.session, tc.parameters)

			if tc.err != "" {
				assert.Empty(t, token)
				assert.Empty(t, signature)
				require.Error(t, err)
				assert.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			tc.checkToken(t, token, signature, tc.config.strategy)
		})
	}
}

// stubConfigurator is a minimal Configurator backed by static values.
type stubConfigurator struct {
	issuer   string
	strategy *stubStrategy
	lifespan time.Duration
}

func (c *stubConfigurator) GetJWTSecuredAuthorizeResponseModeIssuer(_ context.Context) string {
	return c.issuer
}

func (c *stubConfigurator) GetJWTSecuredAuthorizeResponseModeStrategy(_ context.Context) jwt.Strategy {
	if c.strategy == nil {
		return nil
	}
	return c.strategy
}

func (c *stubConfigurator) GetJWTSecuredAuthorizeResponseModeLifespan(_ context.Context) time.Duration {
	return c.lifespan
}

// stubClient is a minimal Client implementation.
type stubClient struct {
	id, alg, kid           string
	encAlg, encKid, encEnc string
	public                 bool
}

func (c *stubClient) GetID() string                                  { return c.id }
func (c *stubClient) IsPublic() bool                                 { return c.public }
func (c *stubClient) GetAuthorizationSignedResponseKeyID() string    { return c.kid }
func (c *stubClient) GetAuthorizationSignedResponseAlg() string      { return c.alg }
func (c *stubClient) GetAuthorizationEncryptedResponseKeyID() string { return c.encKid }
func (c *stubClient) GetAuthorizationEncryptedResponseAlg() string   { return c.encAlg }
func (c *stubClient) GetAuthorizationEncryptedResponseEnc() string   { return c.encEnc }

// stubStrategy captures the claims passed by Generate and returns a fixed token.
type stubStrategy struct {
	token      string
	signature  string
	err        error
	lastClaims jwt.MapClaims
}

func (s *stubStrategy) Encode(_ context.Context, claims jwt.Claims, _ ...jwt.StrategyOpt) (string, string, error) {
	if mc, ok := claims.(jwt.MapClaims); ok {
		s.lastClaims = mc
	}

	return s.token, s.signature, s.err
}

func (s *stubStrategy) Decrypt(_ context.Context, _ string, _ ...jwt.StrategyOpt) (string, string, *jose.JSONWebEncryption, error) {
	return "", "", nil, nil
}

func (s *stubStrategy) Decode(_ context.Context, _ string, _ ...jwt.StrategyOpt) (*jwt.Token, error) {
	return nil, nil
}

func (s *stubStrategy) Validate(_ context.Context, _ *jwt.Token, _ ...jwt.StrategyOpt) error {
	return nil
}

// openIDSession is a minimal OpenIDSession implementation.
type openIDSession struct {
	claims *jwt.IDTokenClaims
}

func (s *openIDSession) IDTokenHeaders() *jwt.Headers      { return &jwt.Headers{} }
func (s *openIDSession) IDTokenClaims() *jwt.IDTokenClaims { return s.claims }

// jwtSessionContainer is a minimal JWTSessionContainer implementation.
type jwtSessionContainer struct {
	claims *jwt.JWTClaims
}

func (s *jwtSessionContainer) GetJWTHeader() *jwt.Headers           { return &jwt.Headers{} }
func (s *jwtSessionContainer) GetJWTClaims() jwt.JWTClaimsContainer { return s.claims }
