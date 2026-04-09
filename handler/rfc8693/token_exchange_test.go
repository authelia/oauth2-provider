package rfc8693_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

// expose key to verify id_token
var key = gen.MustRSAKey()

func TestAccessTokenExchangeImpersonation(t *testing.T) {
	store := storage.NewExampleStore()
	jwtName := "urn:custom:jwt"

	customJWTType := &JWTType{
		Name: jwtName,
		JWTValidationConfig: JWTValidationConfig{
			ValidateJTI: true,
			ValidateFunc: jwt.Keyfunc(func(t *jwt.Token) (any, error) {
				return key.PublicKey, nil
			}),
			JWTLifetimeToleranceWindow: 15 * time.Minute,
		},
		JWTIssueConfig: JWTIssueConfig{
			Audience: []string{"https://resource1.com"},
		},
		Issuer: "https://customory.com",
	}

	config := &oauth2.Config{
		ScopeStrategy:            oauth2.HierarchicScopeStrategy,
		AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
		GlobalSecret:             []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken: &DefaultTokenType{
				Name: consts.TokenTypeRFC8693AccessToken,
			},
			consts.TokenTypeRFC8693IDToken: &DefaultTokenType{
				Name: consts.TokenTypeRFC8693IDToken,
			},
			consts.TokenTypeRFC8693RefreshToken: &DefaultTokenType{
				Name: consts.TokenTypeRFC8693RefreshToken,
			},
			customJWTType.GetName(t.Context()): customJWTType,
		},
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
	}

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	coreStrategy := &hoauth2.HMACCoreStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}

	genericTEHandler := &TokenExchangeGrantHandler{
		Config:                   config,
		ScopeStrategy:            config.ScopeStrategy,
		AudienceMatchingStrategy: config.AudienceMatchingStrategy,
	}

	accessTokenHandler := &AccessTokenTypeHandler{
		Config:               config,
		AccessTokenLifespan:  5 * time.Minute,
		RefreshTokenLifespan: 5 * time.Minute,
		RefreshTokenScopes:   []string{"offline"},
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        config.ScopeStrategy,
		Storage:              store,
	}

	customJWTHandler := &CustomJWTTypeHandler{
		Config: config,
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
		},
		Storage: store,
	}

	testCases := []struct {
		name     string
		handlers []oauth2.TokenEndpointHandler
		areq     *oauth2.AccessRequest
		err      string
		expect   func(t *testing.T, areq *oauth2.AccessRequest, aresp *oauth2.AccessResponse)
	}{
		{
			name:     "ShouldPassExchangeAccessTokenForAnotherAccessToken",
			handlers: []oauth2.TokenEndpointHandler{genericTEHandler, accessTokenHandler},
			areq: &oauth2.AccessRequest{
				Request: oauth2.Request{
					ID:     uuid.New().String(),
					Client: store.Clients["my-client"],
					Form: url.Values{
						"subject_token_type": []string{consts.TokenTypeRFC8693AccessToken},
						"subject_token": []string{createAccessToken(context.Background(), coreStrategy, store,
							store.Clients["custom-lifespan-client"])},
					},
					Session: &DefaultSession{
						DefaultSession: &openid.DefaultSession{},
						Extra:          map[string]any{},
					},
				},
			},
			expect: func(t *testing.T, areq *oauth2.AccessRequest, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken, "Access token is empty; %+v", aresp)
				req, err := introspectAccessToken(context.Background(), aresp.AccessToken, coreStrategy, store)
				require.NoError(t, err, "Error occurred during introspection; err=%v", err)

				assert.EqualValues(t, "peter", req.GetSession().GetSubject(), "Subject did not match the expected value")
			},
		},
		{
			name:     "ShouldPassExchangeCustomJWTForAccessToken",
			handlers: []oauth2.TokenEndpointHandler{genericTEHandler, accessTokenHandler, customJWTHandler},
			areq: &oauth2.AccessRequest{
				Request: oauth2.Request{
					ID:     uuid.New().String(),
					Client: store.Clients["my-client"],
					Form: url.Values{
						"subject_token_type": []string{jwtName},
						"subject_token": []string{createJWT(context.Background(), store.Clients["my-client"], strategy, jwt.MapClaims{
							"subject": "peter_for_jwt",
							"jti":     uuid.New(),
							"iss":     "https://customory.com",
							"sub":     "peter",
							"exp":     time.Now().Add(15 * time.Minute).Unix(),
						})},
					},
					Session: &DefaultSession{
						DefaultSession: &openid.DefaultSession{},
						Extra:          map[string]any{},
					},
				},
			},
			expect: func(t *testing.T, areq *oauth2.AccessRequest, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken, "Access token is empty; %+v", aresp)
				req, err := introspectAccessToken(context.Background(), aresp.AccessToken, coreStrategy, store)
				require.NoError(t, err, "Error occurred during introspection; err=%v", err)

				assert.EqualValues(t, "peter_for_jwt", req.GetSession().GetSubject(), "Subject did not match the expected value")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			aresp := oauth2.NewAccessResponse()
			found := false
			var err error
			tc.areq.Form.Set("grant_type", string(oauth2.GrantTypeTokenExchange))
			tc.areq.GrantTypes = oauth2.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
			tc.areq.Client = store.Clients["my-client"]
			for _, loader := range tc.handlers {
				if !loader.CanHandleTokenEndpointRequest(ctx, tc.areq) {
					continue
				}

				found = true

				if err = loader.HandleTokenEndpointRequest(ctx, tc.areq); err == nil {
					continue
				} else if errors.Is(err, oauth2.ErrUnknownRequest) {
					err = nil
					continue
				} else if err != nil {
					break
				}
			}

			if !found {
				assert.Fail(t, "Unable to find a valid handler")
			}

			if err == nil {
				for _, loader := range tc.handlers {
					if !loader.CanHandleTokenEndpointRequest(ctx, tc.areq) {
						continue
					}

					if err = loader.PopulateTokenEndpointResponse(ctx, tc.areq, aresp); err == nil {
						found = true
					} else if errors.Is(err, oauth2.ErrUnknownRequest) {
						err = nil
						continue
					} else if err != nil {
						break
					}
				}
			}

			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err, "Error received: %v", err)
			}

			if tc.expect != nil {
				tc.expect(t, tc.areq, aresp)
			}
		})
	}
}

func createAccessToken(ctx context.Context, coreStrategy hoauth2.CoreStrategy, storage hoauth2.AccessTokenStorage, client oauth2.Client) string {
	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"password"},
		Request: oauth2.Request{
			Session: &oauth2.DefaultSession{
				Username: "peter",
				Subject:  "peter",
				ExpiresAt: map[oauth2.TokenType]time.Time{
					oauth2.AccessToken: time.Now().UTC().Add(10 * time.Minute),
				},
			},
			Client: client,
		},
	}

	token, signature, err := coreStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		panic(err.Error())
	} else if err := storage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}

func createJWT(ctx context.Context, client any, strategy jwt.Strategy, claims jwt.MapClaims) string {
	token, _, err := strategy.Encode(ctx, claims, jwt.WithIDTokenClient(client))

	if err != nil {
		panic(err.Error())
	}

	return token
}

func introspectAccessToken(ctx context.Context, token string, coreStrategy hoauth2.CoreStrategy, storage hoauth2.CoreStorage) (
	oauth2.Requester, error) {
	sig := coreStrategy.AccessTokenSignature(ctx, token)
	or, err := storage.GetAccessTokenSession(ctx, sig, &oauth2.DefaultSession{})
	return or, err
}
