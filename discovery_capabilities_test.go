// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/idjag"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestSupportedResponseTypesComposeAllEnabled(t *testing.T) {
	config := &oauth2.Config{RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}
	compose.ComposeAllEnabled(config, storage.NewMemoryStore(), nil)

	assert.Equal(t, []string{
		"code",
		"code id_token",
		"code id_token token",
		"code token",
		"id_token",
		"id_token token",
		"none",
		"token",
	}, oauth2.SupportedResponseTypes(context.Background(), config))
}

func TestSupportedGrantTypesComposeAllEnabled(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true, RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}
	compose.ComposeAllEnabled(config, storage.NewMemoryStore(), nil)

	assert.Equal(t, []string{
		consts.GrantTypeAuthorizationCode,
		consts.GrantTypeClientCredentials,
		consts.GrantTypeImplicit,
		consts.GrantTypeResourceOwnerPasswordCredentials,
		consts.GrantTypeRefreshToken,
		consts.GrantTypeOAuthDeviceCode,
		consts.GrantTypeOAuthJWTBearer,
		consts.GrantTypeOAuthJWTDPoP,
		consts.GrantTypeOAuthTokenExchange,
	}, oauth2.SupportedGrantTypes(context.Background(), config))
}

func TestSupportedGrantTypesAugmentingOnly(t *testing.T) {
	config := &oauth2.Config{}
	config.AuthorizeEndpointHandlers.Append(&openid.OpenIDConnectExplicitHandler{})
	config.AuthorizeEndpointHandlers.Append(&pkce.Handler{Config: config})
	config.TokenEndpointHandlers.Append(&pkce.Handler{Config: config})

	assert.Nil(t, oauth2.SupportedGrantTypes(context.Background(), config))
	assert.Nil(t, oauth2.SupportedResponseTypes(context.Background(), config))
	assert.Nil(t, oauth2.SupportedRFC8693TokenTypes(context.Background(), config))
}

func TestSupportedCodeChallengeMethods(t *testing.T) {
	config := &oauth2.Config{}
	config.AuthorizeEndpointHandlers.Append(&pkce.Handler{Config: config})

	assert.Equal(t, []string{"S256"}, oauth2.SupportedCodeChallengeMethods(context.Background(), config))

	config.EnablePKCEPlainChallengeMethod = true

	assert.Equal(t, []string{"S256", "plain"}, oauth2.SupportedCodeChallengeMethods(context.Background(), config))
}

func TestSupportedRFC8693TokenTypesExcludesUnissuable(t *testing.T) {
	config := &oauth2.Config{
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken: &rfc8693.JWTType{Name: "at", Issue: &rfc8693.JWTIssueConfig{Issuer: "https://example.com"}},
			"urn:example:self-signed":          &rfc8693.SelfSignedTokenType{},
			"urn:example:unsigned":             &rfc8693.UnsignedJSONTokenType{},
			"urn:example:jwt-no-issue":         &rfc8693.JWTType{Name: "x"},
			"urn:example:jwt":                  &rfc8693.JWTType{Name: "y", Issue: &rfc8693.JWTIssueConfig{Issuer: "https://example.com"}},
		},
	}

	config.TokenEndpointHandlers.Append(&rfc8693.TokenExchangeGrantHandler{Config: config})
	config.TokenEndpointHandlers.Append(&rfc8693.AccessTokenTypeHandler{Config: config})
	config.TokenEndpointHandlers.Append(&rfc8693.CustomJWTTypeHandler{Config: config})
	config.TokenEndpointHandlers.Append(&rfc8693.TxnTokenTypeHandler{Config: config})

	assert.Equal(t, []string{"urn:example:jwt", consts.TokenTypeRFC8693AccessToken}, oauth2.SupportedRFC8693TokenTypes(context.Background(), config))
}

func TestSupportedRFC8693TokenTypesRequiresIssuingHandler(t *testing.T) {
	tokenTypes := map[string]oauth2.RFC8693TokenType{
		consts.TokenTypeRFC8693AccessToken:  &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
		consts.TokenTypeRFC8693RefreshToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken},
		consts.TokenTypeRFC8693IDToken:      &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken},
		consts.TokenTypeRFC8693IDJAG:        &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG},
		consts.TokenTypeRFC8693TxnToken:     &rfc8693.TxnTokenType{},
		"urn:example:jwt":                   &rfc8693.JWTType{Name: "y", Issue: &rfc8693.JWTIssueConfig{Issuer: "https://example.com"}},
		"urn:example:unknown":               &rfc8693.DefaultTokenType{Name: "urn:example:unknown"},
	}

	allIssuers := func(config *oauth2.Config) []oauth2.TokenEndpointHandler {
		return []oauth2.TokenEndpointHandler{
			&rfc8693.TokenExchangeGrantHandler{Config: config},
			&rfc8693.AccessTokenTypeHandler{Config: config},
			&rfc8693.RefreshTokenTypeHandler{Config: config},
			&rfc8693.IDTokenTypeHandler{Config: config},
			&rfc8693.CustomJWTTypeHandler{Config: config},
			&rfc8693.TxnTokenTypeHandler{Config: config},
			&idjag.IssueHandler{Config: config},
		}
	}

	testCases := []struct {
		name       string
		tokenTypes map[string]oauth2.RFC8693TokenType
		handlers   func(config *oauth2.Config) []oauth2.TokenEndpointHandler
		expected   []string
	}{
		{
			name: "ShouldNotAdvertiseWithoutAnIssuingHandler",
			handlers: func(config *oauth2.Config) []oauth2.TokenEndpointHandler {
				return []oauth2.TokenEndpointHandler{&rfc8693.TokenExchangeGrantHandler{Config: config}}
			},
		},
		{
			name: "ShouldAdvertiseOnlyTheTypesOfRegisteredIssuers",
			handlers: func(config *oauth2.Config) []oauth2.TokenEndpointHandler {
				return []oauth2.TokenEndpointHandler{
					&rfc8693.TokenExchangeGrantHandler{Config: config},
					&rfc8693.AccessTokenTypeHandler{Config: config},
				}
			},
			expected: []string{consts.TokenTypeRFC8693AccessToken},
		},
		{
			name: "ShouldNotAdvertiseAJWTTypedIDJAGFromTheCustomJWTHandler",
			tokenTypes: map[string]oauth2.RFC8693TokenType{
				consts.TokenTypeRFC8693IDJAG: &rfc8693.JWTType{Name: "idjag", Issue: &rfc8693.JWTIssueConfig{Issuer: "https://example.com"}},
			},
			handlers: func(config *oauth2.Config) []oauth2.TokenEndpointHandler {
				return []oauth2.TokenEndpointHandler{
					&rfc8693.TokenExchangeGrantHandler{Config: config},
					&rfc8693.CustomJWTTypeHandler{Config: config},
				}
			},
		},
		{
			name: "ShouldNotAdvertiseATypedNilDefaultTokenType",
			tokenTypes: map[string]oauth2.RFC8693TokenType{
				consts.TokenTypeRFC8693AccessToken: (*rfc8693.DefaultTokenType)(nil),
				"urn:example:nil":                  (*rfc8693.DefaultTokenType)(nil),
			},
			handlers: allIssuers,
		},
		{
			name:     "ShouldAdvertiseEveryTypeWithAnIssuer",
			handlers: allIssuers,
			expected: []string{
				"urn:example:jwt",
				consts.TokenTypeRFC8693AccessToken,
				consts.TokenTypeRFC8693IDJAG,
				consts.TokenTypeRFC8693IDToken,
				consts.TokenTypeRFC8693RefreshToken,
				consts.TokenTypeRFC8693TxnToken,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{RFC8693TokenTypes: tokenTypes}

			if tc.tokenTypes != nil {
				config.RFC8693TokenTypes = tc.tokenTypes
			}

			for _, h := range tc.handlers(config) {
				config.TokenEndpointHandlers.Append(h)
			}

			assert.Equal(t, tc.expected, oauth2.SupportedRFC8693TokenTypes(context.Background(), config))
		})
	}
}

func TestSupportedScopesDerived(t *testing.T) {
	config := &oauth2.Config{
		ScopesSupported:                       []string{"profile", "openid"},
		RefreshTokenScopes:                    []string{"offline_access"},
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}
	compose.ComposeAllEnabled(config, storage.NewMemoryStore(), nil)

	assert.Equal(t, []string{"offline_access", "openid", "profile"}, oauth2.SupportedScopes(context.Background(), config))
}

func TestSupportedScopesBoundKey(t *testing.T) {
	config := &oauth2.Config{
		ScopesSupported:                       []string{"profile"},
		RefreshTokenScopes:                    []string{"offline_access"},
		DPoPEnabled:                           true,
		OIDCKeyBindingEnabled:                 true,
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}
	compose.ComposeAllEnabled(config, storage.NewMemoryStore(), nil)
	config.TokenEndpointBindingHandlers.Append(&oidckb.Handler{Config: config})

	assert.Contains(t, oauth2.SupportedScopes(context.Background(), config), consts.ScopeBoundKey)
}

func TestSupportedScopesOAuthOnly(t *testing.T) {
	config := &oauth2.Config{ScopesSupported: []string{"b", "a", "a"}}

	assert.Equal(t, []string{"a", "b"}, oauth2.SupportedScopes(context.Background(), config))
}

func TestSupportedScopesExplicitHandlerAddsOpenID(t *testing.T) {
	config := &oauth2.Config{}
	config.AuthorizeEndpointHandlers.Append(&openid.OpenIDConnectExplicitHandler{})

	assert.True(t, oauth2.IsOpenIDConnectRegistered(context.Background(), config))
	assert.Equal(t, []string{"openid"}, oauth2.SupportedScopes(context.Background(), config))
}

func TestSupportedClaimsOAuthOnly(t *testing.T) {
	config := &oauth2.Config{ClaimsSupported: []string{"email", "name"}}

	assert.False(t, oauth2.IsOpenIDConnectRegistered(context.Background(), config))
	assert.Equal(t, []string{"email", "name"}, oauth2.SupportedClaims(context.Background(), config))
}

func TestSupportedClaimsOpenIDConnect(t *testing.T) {
	config := &oauth2.Config{ClaimsSupported: []string{"email"}}
	config.AuthorizeEndpointHandlers.Append(&openid.OpenIDConnectExplicitHandler{})

	assert.Equal(t, []string{"acr", "amr", "at_hash", "aud", "auth_time", "azp", "c_hash", "email", "exp", "iat", "iss", "nonce", "sid", "sub"}, oauth2.SupportedClaims(context.Background(), config))
}

func TestSupportedPromptValues(t *testing.T) {
	testCases := []struct {
		name     string
		config   oauth2.AllowedPromptsProvider
		expected []string
	}{
		{"ShouldDefaultForConfig", &oauth2.Config{}, []string{"login", "none", "consent", "select_account"}},
		{"ShouldDefaultForAnotherProvider", nilPromptsProvider{}, []string{"login", "none", "consent", "select_account"}},
		{"ShouldReturnTheConfiguredValues", &oauth2.Config{AllowedPromptValues: []string{"none", "create"}}, []string{"none", "create"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, oauth2.SupportedPromptValues(context.Background(), tc.config))
		})
	}

	assert.Nil(t, (&oauth2.Config{}).GetAllowedPrompts(context.Background()))
}

func TestInformationalGettersDefaults(t *testing.T) {
	config := &oauth2.Config{}
	ctx := context.Background()

	assert.Equal(t, []string{"public"}, config.GetSubjectTypesSupported(ctx))
	assert.Nil(t, config.GetScopesSupported(ctx))
	assert.Nil(t, config.GetClaimsSupported(ctx))
	assert.Nil(t, config.GetACRValuesSupported(ctx))
	assert.Nil(t, config.GetDisplayValuesSupported(ctx))
	assert.Nil(t, config.GetClaimTypesSupported(ctx))
	assert.Nil(t, config.GetUILocalesSupported(ctx))
	assert.Nil(t, config.GetClaimsLocalesSupported(ctx))
	assert.Equal(t, "", config.GetServiceDocumentation(ctx))
	assert.Equal(t, "", config.GetOPPolicyURI(ctx))
	assert.Equal(t, "", config.GetOPTOSURI(ctx))
}

func TestSupportedIDTokenSigningAlgValues(t *testing.T) {
	es256 := func(config *oauth2.Config) jwt.Strategy {
		return &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
			}}),
		}
	}

	testCases := []struct {
		name     string
		setup    func(config *oauth2.Config)
		expected []string
	}{
		{
			name: "ShouldUseHandlerStrategy",
			setup: func(config *oauth2.Config) {
				compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

				config.JWTStrategy = es256(config)
			},
			expected: []string{"RS256"},
		},
		{
			name: "ShouldFallBackToJWTStrategy",
			setup: func(config *oauth2.Config) {
				config.JWTStrategy = es256(config)
			},
			expected: []string{"ES256"},
		},
		{
			name: "ShouldFallBackWhenHandlerStrategyHasNoKeys",
			setup: func(config *oauth2.Config) {
				config.AuthorizeEndpointHandlers.Append(&openid.OpenIDConnectExplicitHandler{})
				config.TokenEndpointHandlers.Append(&openid.OpenIDConnectRefreshHandler{IDTokenHandleHelper: &openid.IDTokenHandleHelper{IDTokenStrategy: &openid.DefaultStrategy{}}})
				config.JWTStrategy = es256(config)
			},
			expected: []string{"ES256"},
		},
		{
			name:     "ShouldReturnNilWithoutKeys",
			setup:    func(config *oauth2.Config) {},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}

			tc.setup(config)

			assert.Equal(t, tc.expected, oauth2.SupportedIDTokenSigningAlgValues(context.Background(), config))
		})
	}
}

func TestSupportedSignedResponseAlgValues(t *testing.T) {
	ctx := context.Background()

	keyed := &oauth2.Config{}
	es256 := &jwt.DefaultStrategy{
		Config: keyed,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
		}}),
	}

	keyed.JWTStrategy = es256
	keyed.JWTSecuredAuthorizeResponseModeStrategy = es256
	keyed.IntrospectionJWTResponseStrategy = es256

	keyless := &oauth2.Config{}
	keyless.JWTStrategy = &jwt.DefaultStrategy{Config: keyless}

	withoutStrategy := &nilStrategyConfig{Config: &oauth2.Config{}}

	testCases := []struct {
		name     string
		get      func(ctx context.Context, config oauth2.Configurator) []string
		keyed    []string
		keyless  []string
		strategy []string
	}{
		{
			name:     "IDToken",
			get:      oauth2.SupportedIDTokenSignedResponseAlgValues,
			keyed:    []string{"ES256", "HS256", "HS384", "HS512"},
			keyless:  nil,
			strategy: nil,
		},
		{
			name:     "Userinfo",
			get:      oauth2.SupportedUserinfoSignedResponseAlgValues,
			keyed:    []string{"ES256", "HS256", "HS384", "HS512", "none"},
			keyless:  []string{"HS256", "HS384", "HS512", "none"},
			strategy: []string{"none"},
		},
		{
			name:     "Authorization",
			get:      oauth2.SupportedAuthorizationSignedResponseAlgValues,
			keyed:    []string{"ES256", "HS256", "HS384", "HS512"},
			keyless:  nil,
			strategy: nil,
		},
		{
			name:     "Introspection",
			get:      oauth2.SupportedIntrospectionSignedResponseAlgValues,
			keyed:    []string{"ES256", "HS256", "HS384", "HS512"},
			keyless:  nil,
			strategy: nil,
		},
		{
			name:     "AccessToken",
			get:      oauth2.SupportedAccessTokenSignedResponseAlgValues,
			keyed:    []string{"ES256", "HS256", "HS384", "HS512"},
			keyless:  []string{"HS256", "HS384", "HS512"},
			strategy: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.keyed, tc.get(ctx, keyed))
			assert.Equal(t, tc.keyless, tc.get(ctx, keyless))
			assert.Equal(t, tc.strategy, tc.get(ctx, withoutStrategy))
		})
	}
}

type nilPromptsProvider struct{}

func (nilPromptsProvider) GetAllowedPrompts(_ context.Context) []string { return nil }

type nilStrategyConfig struct {
	*oauth2.Config
}

func (c *nilStrategyConfig) GetJWTStrategy(_ context.Context) jwt.Strategy {
	return nil
}
