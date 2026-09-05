// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

// RFC 8693 §2.1: 'subject_token' and 'subject_token_type' must both be present.
func TestHandleTokenEndpointRequest_RequiredParameters(t *testing.T) {
	handler := newTokenExchangeHandler()
	client := newConfidentialClient()

	t.Run("ShouldFailWhenSubjectTokenMissing", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{
			consts.FormParameterSubjectToken: {""},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Mandatory parameter 'subject_token' is missing.")
	})

	t.Run("ShouldFailWhenSubjectTokenTypeMissing", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{
			consts.FormParameterSubjectTokenType: {""},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), consts.FormParameterSubjectTokenType)
	})
}

// RFC 8693 §3: 'subject_token_type' and 'requested_token_type' must be among the server's supported types.
func TestHandleTokenEndpointRequest_TokenTypeRegistration(t *testing.T) {
	handler := newTokenExchangeHandler()
	client := newConfidentialClient()

	t.Run("ShouldFailWhenSubjectTokenTypeUnknown", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{
			consts.FormParameterSubjectTokenType: {"urn:example:unknown"},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldFailWhenRequestedTokenTypeUnknown", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{
			consts.FormParameterRequestedTokenType: {"urn:example:unknown"},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldDefaultRequestedTokenTypeFromConfig", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.NoError(t, err)
	})
}

// RFC 8693 §2.1: 'actor_token' and 'actor_token_type' are each REQUIRED when the other is present.
func TestHandleTokenEndpointRequest_ActorTokenPair(t *testing.T) {
	handler := newTokenExchangeHandler()
	client := newConfidentialClient()

	t.Run("ShouldFailWhenActorTokenWithoutType", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{
			consts.FormParameterActorToken: {"actor-token"},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldFailWhenActorTokenTypeWithoutActorToken", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{
			consts.FormParameterActorTokenType: {consts.TokenTypeRFC8693AccessToken},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldFailWhenActorTokenTypeUnknown", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{
			consts.FormParameterActorToken:     {"actor-token"},
			consts.FormParameterActorTokenType: {"urn:example:unknown"},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldPassWithBothActorTokenAndType", func(t *testing.T) {
		req := baseRequest(t, client, url.Values{
			consts.FormParameterActorToken:     {"actor-token"},
			consts.FormParameterActorTokenType: {consts.TokenTypeRFC8693AccessToken},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.NoError(t, err)
	})
}

func TestHandleTokenEndpointRequest_ClientTokenTypeRestrictions(t *testing.T) {
	handler := newTokenExchangeHandler()

	makeClient := func(subj, actor, req []string) *rfc8693Client {
		return &rfc8693Client{
			DefaultClient:       newConfidentialClient(),
			subjectTokenTypes:   subj,
			actorTokenTypes:     actor,
			requestedTokenTypes: req,
		}
	}

	t.Run("ShouldFailWhenSubjectTokenTypeNotPermittedForClient", func(t *testing.T) {
		client := makeClient([]string{consts.TokenTypeRFC8693IDToken}, nil, nil)
		req := baseRequest(t, client, url.Values{})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldFailWhenActorTokenTypeNotPermittedForClient", func(t *testing.T) {
		client := makeClient(nil, []string{consts.TokenTypeRFC8693IDToken}, nil)
		req := baseRequest(t, client, url.Values{
			consts.FormParameterActorToken:     {"actor-token"},
			consts.FormParameterActorTokenType: {consts.TokenTypeRFC8693AccessToken},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldFailWhenRequestedTokenTypeNotPermittedForClient", func(t *testing.T) {
		client := makeClient(nil, nil, []string{consts.TokenTypeRFC8693IDToken})
		req := baseRequest(t, client, url.Values{
			consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken},
		})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})
}

// RFC 8693 §4.4: token exchange requires client authentication and the registered grant type.
func TestHandleTokenEndpointRequest_ClientEligibility(t *testing.T) {
	handler := newTokenExchangeHandler()

	t.Run("ShouldFailForPublicClient", func(t *testing.T) {
		client := newConfidentialClient()
		client.Public = true
		req := baseRequest(t, client, url.Values{})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})

	t.Run("ShouldFailWhenClientLacksTokenExchangeGrant", func(t *testing.T) {
		client := newConfidentialClient()
		client.GrantTypes = []string{consts.GrantTypeAuthorizationCode}
		req := baseRequest(t, client, url.Values{})

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrUnauthorizedClient)
	})
}

// RFC 8693 §2.1: the scope constraint, and the 'audience' and RFC 8707 'resource' parameters.
func TestHandleTokenEndpointRequest_ScopeAudienceResource(t *testing.T) {
	handler := newTokenExchangeHandler()

	t.Run("ShouldFailWhenScopeNotPermitted", func(t *testing.T) {
		client := newConfidentialClient()
		req := baseRequest(t, client, url.Values{})
		req.RequestedScope = oauth2.Arguments{"forbidden-scope"}

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidScope)
	})

	t.Run("ShouldFailWhenAudienceNotInClientAllowList", func(t *testing.T) {
		client := newConfidentialClient()
		req := baseRequest(t, client, url.Values{})
		req.RequestedAudience = oauth2.Arguments{"unauthorized-audience"}

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidTarget)
	})

	t.Run("ShouldFailWhenResourceNotInClientAllowList", func(t *testing.T) {
		client := newConfidentialClient()
		req := baseRequest(t, client, url.Values{})
		req.RequestedResource = oauth2.Arguments{"https://unauthorized.example.com"}

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidTarget)
	})

	t.Run("ShouldPassWithOnlyAudience", func(t *testing.T) {
		client := newConfidentialClient()
		req := baseRequest(t, client, url.Values{})
		req.RequestedAudience = oauth2.Arguments{"my-service"}

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, oauth2.Arguments{"my-service"}, req.GetGrantedAudience())
		assert.Empty(t, req.GetGrantedResource())
	})

	t.Run("ShouldPassWithOnlyResource", func(t *testing.T) {
		client := newConfidentialClient()
		req := baseRequest(t, client, url.Values{})
		req.RequestedResource = oauth2.Arguments{"https://api.example.com"}

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.NoError(t, err)
		assert.Empty(t, req.GetGrantedAudience())
		assert.Equal(t, oauth2.Arguments{"https://api.example.com"}, req.GetGrantedResource())
	})

	t.Run("ShouldPassAndGrantBothAudienceAndResource", func(t *testing.T) {
		client := newConfidentialClient()
		req := baseRequest(t, client, url.Values{})
		req.RequestedAudience = oauth2.Arguments{"my-service"}
		req.RequestedResource = oauth2.Arguments{"https://api.example.com"}

		err := handler.HandleTokenEndpointRequest(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, oauth2.Arguments{"my-service"}, req.GetGrantedAudience())
		assert.Equal(t, oauth2.Arguments{"https://api.example.com"}, req.GetGrantedResource())
		assert.Equal(t, oauth2.Arguments{"my-service", "https://api.example.com"},
			oauth2.JoinGrantedAudienceAndResource(req.GetGrantedAudience(), req.GetGrantedResource()))
	})
}

func TestHandleTokenEndpointRequest_PerClientIssuerEndToEnd(t *testing.T) {
	const (
		jwtType        = "urn:custom:jwt"
		issuerAccepted = "https://idp.accepted.example.com"
		issuerRejected = "https://idp.rejected.example.com"
	)

	rsa := gen.MustRSAKey()
	strategy := &jwt.DefaultStrategy{Issuer: jwt.NewDefaultIssuerRS256Unverified(rsa)}

	mkConfig := func() *oauth2.Config {
		return &oauth2.Config{
			ScopeStrategy:    oauth2.HierarchicScopeStrategy,
			AudienceStrategy: oauth2.ExactAudienceStrategy,
			RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
				consts.TokenTypeRFC8693AccessToken: &DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
				jwtType: &JWTType{
					Name:   jwtType,
					Issuer: issuerAccepted,
					JWTValidationConfig: JWTValidationConfig{
						ValidateFunc:               jwt.Keyfunc(func(t *jwt.Token) (any, error) { return rsa.PublicKey, nil }),
						JWTLifetimeToleranceWindow: 15 * time.Minute,
					},
				},
			},
			DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
		}
	}

	mkJWT := func(t *testing.T, iss string) string {
		t.Helper()
		token, _, err := strategy.Encode(context.Background(), jwt.MapClaims{
			"iss":     iss,
			"sub":     "alice",
			"subject": "alice", // MemoryStore.GetSubjectForTokenExchange reads "subject"
			"exp":     time.Now().Add(15 * time.Minute).Unix(),
		})
		require.NoError(t, err)
		return token
	}

	run := func(t *testing.T, client oauth2.Client, jwtIss string) error {
		t.Helper()
		cfg := mkConfig()
		teHandler := &TokenExchangeGrantHandler{
			Config:           cfg,
			ScopeStrategy:    cfg.ScopeStrategy,
			AudienceStrategy: cfg.AudienceStrategy,
			ResourceStrategy: cfg.GetResourceStrategy(context.Background()),
		}
		store := storage.NewExampleStore()
		jwtHandler := &CustomJWTTypeHandler{
			Config:   cfg,
			Strategy: strategy,
			Storage:  store,
		}

		req := baseRequest(t, client, url.Values{
			consts.FormParameterSubjectTokenType: {jwtType},
			consts.FormParameterSubjectToken:     {mkJWT(t, jwtIss)},
		})
		req.Session = &DefaultSession{DefaultSession: &openid.DefaultSession{}, Extra: map[string]any{}}

		if err := teHandler.HandleTokenEndpointRequest(context.Background(), req); err != nil {
			return err
		}

		return jwtHandler.HandleTokenEndpointRequest(context.Background(), req)
	}

	baseClient := func() *rfc8693Client {
		return &rfc8693Client{DefaultClient: newConfidentialClient()}
	}

	t.Run("ShouldAcceptWhenJWTIssuerInClientAllowList", func(t *testing.T) {
		client := baseClient()
		client.subjectTokenIssuers = []string{issuerAccepted, issuerRejected}

		err := run(t, client, issuerRejected) // not the type's static Issuer, but is in the client's list
		require.NoError(t, err)
	})

	t.Run("ShouldRejectWhenJWTIssuerNotInClientAllowList", func(t *testing.T) {
		client := baseClient()
		client.subjectTokenIssuers = []string{issuerAccepted}

		err := run(t, client, issuerRejected)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'iss' from token is not in the OAuth 2.0 Client's permitted issuer list.")
	})

	t.Run("ShouldFallBackToTokenTypeIssuerWhenClientListEmpty", func(t *testing.T) {
		client := baseClient() // empty subjectTokenIssuers → fallback path

		err := run(t, client, issuerAccepted)
		require.NoError(t, err)

		err = run(t, client, issuerRejected)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), issuerAccepted)
	})
}

func TestValidateIssuer(t *testing.T) {
	t.Run("ShouldMatchAgainstPerClientAllowList", func(t *testing.T) {
		matched, ok := ValidateIssuer("https://b.example.com", "https://other.example.com",
			[]string{"https://a.example.com", "https://b.example.com"})
		require.True(t, ok)
		assert.Equal(t, "https://b.example.com", matched)
	})

	t.Run("ShouldRejectIssuerNotInAllowList", func(t *testing.T) {
		_, ok := ValidateIssuer("https://c.example.com", "https://c.example.com",
			[]string{"https://a.example.com", "https://b.example.com"})
		assert.False(t, ok)
	})

	t.Run("ShouldFallBackToTokenTypeIssuerWhenAllowListEmpty", func(t *testing.T) {
		matched, ok := ValidateIssuer("https://idp.example.com", "https://idp.example.com", nil)
		require.True(t, ok)
		assert.Equal(t, "https://idp.example.com", matched)
	})

	t.Run("ShouldRejectFallbackMismatch", func(t *testing.T) {
		_, ok := ValidateIssuer("https://idp.example.com", "https://other.example.com", nil)
		assert.False(t, ok)
	})

	t.Run("ShouldPassThroughWhenNoIssuerConfigured", func(t *testing.T) {
		matched, ok := ValidateIssuer("https://anything.example.com", "", nil)
		require.True(t, ok)
		assert.Equal(t, "https://anything.example.com", matched)
	})
}

func TestHandleTokenEndpointRequest_StrategyFallback(t *testing.T) {
	config := &oauth2.Config{
		ScopeStrategy:    oauth2.HierarchicScopeStrategy,
		AudienceStrategy: oauth2.ExactAudienceStrategy,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken: &DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
		},
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
	}

	handler := &TokenExchangeGrantHandler{Config: config}

	client := newConfidentialClient()
	req := baseRequest(t, client, url.Values{})
	req.RequestedAudience = oauth2.Arguments{"my-service"}

	err := handler.HandleTokenEndpointRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, oauth2.Arguments{"my-service"}, req.GetGrantedAudience())
}

// newTokenExchangeHandler builds a TokenExchangeGrantHandler against a Config whose
// supported token types include the standard RFC 8693 set.
func newTokenExchangeHandler() *TokenExchangeGrantHandler {
	config := &oauth2.Config{
		ScopeStrategy:    oauth2.HierarchicScopeStrategy,
		AudienceStrategy: oauth2.ExactAudienceStrategy,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken:  &DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
			consts.TokenTypeRFC8693RefreshToken: &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken},
			consts.TokenTypeRFC8693IDToken:      &DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken},
		},
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
	}

	return &TokenExchangeGrantHandler{
		Config:           config,
		ScopeStrategy:    config.ScopeStrategy,
		AudienceStrategy: config.AudienceStrategy,
		ResourceStrategy: config.GetResourceStrategy(context.Background()),
	}
}

// newConfidentialClient returns a confidential client that is allowed to perform token exchange.
func newConfidentialClient() *oauth2.DefaultClient {
	return &oauth2.DefaultClient{
		ID:           "exchange-client",
		ClientSecret: oauth2.NewPlainTextClientSecret("secret"),
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
		Scopes:       []string{"openid", "offline_access"},
		Audience:     []string{"https://api.example.com", "my-service"},
	}
}

// baseRequest builds an AccessRequest with the token-exchange grant type already set,
// the given client, and the supplied form values. Required RFC 8693 §2.1 params
// (subject_token, subject_token_type) are seeded with valid defaults so individual
// tests only need to override what they care about.
func baseRequest(t *testing.T, client oauth2.Client, form url.Values) *oauth2.AccessRequest {
	t.Helper()

	merged := url.Values{
		consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectToken:     {"opaque-subject-token"},
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
	}

	for k, vs := range form {
		merged[k] = vs
	}

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			Client:  client,
			Form:    merged,
			Session: &DefaultSession{},
		},
	}
}

// rfc8693Client is an oauth2.Client that also exposes the rfc8693.Client interface,
// letting tests assert RFC 8693 §2.1 client-level token-type restrictions.
type rfc8693Client struct {
	*oauth2.DefaultClient

	subjectTokenTypes   []string
	actorTokenTypes     []string
	requestedTokenTypes []string
	subjectTokenIssuers []string
	actorTokenIssuers   []string
	exchangePermitted   bool
	allow               bool
}

func (c *rfc8693Client) GetSupportedSubjectTokenTypes() []string { return c.subjectTokenTypes }

func (c *rfc8693Client) GetSupportedActorTokenTypes() []string { return c.actorTokenTypes }

func (c *rfc8693Client) GetSupportedRequestTokenTypes() []string { return c.requestedTokenTypes }

func (c *rfc8693Client) GetSupportedSubjectTokenIssuers() []string { return c.subjectTokenIssuers }

func (c *rfc8693Client) GetSupportedActorTokenIssuers() []string { return c.actorTokenIssuers }

func (c *rfc8693Client) GetTokenExchangePermitted(_ oauth2.Client, _ oauth2.RFC8693TokenType) bool {
	return c.exchangePermitted
}

func (c *rfc8693Client) GetAllowActorTokenWithoutMayAct() (allow bool) {
	return c.allow
}
