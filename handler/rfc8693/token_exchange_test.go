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
	"authelia.com/provider/oauth2/handler/rfc8693"
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

	jwtSigner := &jwt.DefaultSigner{
		GetPrivateKey: func(_ context.Context) (any, error) {
			return key, nil
		},
	}

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
			customJWTType.GetName(context.TODO()): customJWTType,
		},
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
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
		JWTStrategy: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (any, error) {
				return key, nil
			},
		},
		Storage: store,
	}

	for _, c := range []struct {
		handlers    []oauth2.TokenEndpointHandler
		areq        *oauth2.AccessRequest
		description string
		expectErr   error
		expect      func(t *testing.T, areq *oauth2.AccessRequest, aresp *oauth2.AccessResponse)
	}{
		{
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
					Session: &rfc8693.DefaultSession{
						DefaultSession: &openid.DefaultSession{},
						Extra:          map[string]any{},
					},
				},
			},
			description: "should pass because a valid access token is exchanged for another access token",
			expect: func(t *testing.T, areq *oauth2.AccessRequest, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken, "Access token is empty; %+v", aresp)
				req, err := introspectAccessToken(context.Background(), aresp.AccessToken, coreStrategy, store)
				require.NoError(t, err, "Error occurred during introspection; err=%v", err)

				assert.EqualValues(t, "peter", req.GetSession().GetSubject(), "Subject did not match the expected value")
			},
		},
		{
			handlers: []oauth2.TokenEndpointHandler{genericTEHandler, accessTokenHandler, customJWTHandler},
			areq: &oauth2.AccessRequest{
				Request: oauth2.Request{
					ID:     uuid.New().String(),
					Client: store.Clients["my-client"],
					Form: url.Values{
						"subject_token_type": []string{jwtName},
						"subject_token": []string{createJWT(context.Background(), jwtSigner, jwt.MapClaims{
							"subject": "peter_for_jwt",
							"jti":     uuid.New(),
							"iss":     "https://customory.com",
							"sub":     "peter",
							"exp":     time.Now().Add(15 * time.Minute).Unix(),
						})},
					},
					Session: &rfc8693.DefaultSession{
						DefaultSession: &openid.DefaultSession{},
						Extra:          map[string]any{},
					},
				},
			},
			description: "should pass because a valid custom JWT is exchanged for access token",
			expect: func(t *testing.T, areq *oauth2.AccessRequest, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken, "Access token is empty; %+v", aresp)
				req, err := introspectAccessToken(context.Background(), aresp.AccessToken, coreStrategy, store)
				require.NoError(t, err, "Error occurred during introspection; err=%v", err)

				assert.EqualValues(t, "peter_for_jwt", req.GetSession().GetSubject(), "Subject did not match the expected value")
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			ctx := context.Background()
			aresp := oauth2.NewAccessResponse()
			found := false
			var err error
			c.areq.Form.Set("grant_type", string(oauth2.GrantTypeTokenExchange))
			c.areq.GrantTypes = oauth2.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
			c.areq.Client = store.Clients["my-client"]
			for _, loader := range c.handlers {
				// Is the loader responsible for handling the request?
				if !loader.CanHandleTokenEndpointRequest(ctx, c.areq) {
					continue
				}

				// The handler **is** responsible!
				found = true

				if err = loader.HandleTokenEndpointRequest(ctx, c.areq); err == nil {
					continue
				} else if errors.Is(err, oauth2.ErrUnknownRequest) {
					// This is a duplicate because it should already have been handled by
					// `loader.CanHandleTokenEndpointRequest(accessRequest)` but let's keep it for sanity.
					//
					err = nil
					continue
				} else if err != nil {
					break
				}
			}

			if !found {
				assert.Fail(t, "Unable to find a valid handler")
			}

			// now execute the response
			if err == nil {
				for _, loader := range c.handlers {
					// Is the loader responsible for handling the request?
					if !loader.CanHandleTokenEndpointRequest(ctx, c.areq) {
						continue
					}

					// The handler **is** responsible!

					if err = loader.PopulateTokenEndpointResponse(ctx, c.areq, aresp); err == nil {
						found = true
					} else if errors.Is(err, oauth2.ErrUnknownRequest) {
						// This is a duplicate because it should already have been handled by
						// `loader.CanHandleTokenEndpointRequest(accessRequest)` but let's keep it for sanity.
						//
						err = nil
						continue
					} else if err != nil {
						break
					}
				}
			}

			var rfcerr *oauth2.RFC6749Error
			rfcerr, _ = err.(*oauth2.RFC6749Error)
			if rfcerr == nil {
				rfcerr = oauth2.ErrServerError
			}
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error(), "Error received: %v, rfcerr=%s", err, rfcerr.GetDescription())
			} else {
				require.NoError(t, err, "Error received: %v, rfcerr=%s", err, rfcerr.GetDescription())
			}

			if c.expect != nil {
				c.expect(t, c.areq, aresp)
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

func createJWT(ctx context.Context, signer jwt.Signer, claims jwt.MapClaims) string {
	token, _, err := signer.Generate(ctx, claims, &jwt.Headers{})
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
