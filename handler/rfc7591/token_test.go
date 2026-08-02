// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func newTokenFixtures(t *testing.T) (*oauth2.Config, *storage.MemoryStore, *hoauth2.HMACCoreStrategy, oauth2.Client) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: "https://auth.example.com/register",
	}

	return config, storage.NewMemoryStore(), hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"), &oauth2.DefaultClient{ID: "creator"}
}

func TestNewClientCreationToken(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, client := newTokenFixtures(t)

	tokenString, err := NewClientCreationToken(ctx, tokens, store, config, client, oauth2.Arguments{"openid", "profile"})
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// It is an ordinary access token, not a dedicated token kind.
	assert.True(t, strings.HasPrefix(tokenString, "authelia_at_"))

	requester, err := store.GetAccessTokenSession(ctx, tokens.AccessTokenSignature(ctx, tokenString), NewDefaultSession())
	require.NoError(t, err)

	assert.Equal(t, "creator", requester.GetClient().GetID())
	assert.True(t, requester.GetGrantedAudience().Has("https://auth.example.com/register"))

	session, ok := requester.GetSession().(Session)
	require.True(t, ok)

	assert.Equal(t, KindCreate, session.GetClientRegistrationKind())
	assert.Equal(t, oauth2.Arguments{"openid", "profile"}, session.GetGrantableScopes())

	// The default creation lifespan is short and therefore set.
	assert.False(t, session.GetExpiresAt(oauth2.AccessToken).IsZero())
}

func TestNewClientManagementToken(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, _ := newTokenFixtures(t)

	managed := &oauth2.DefaultClient{ID: "managed-one"}

	tokenString, err := NewClientManagementToken(ctx, tokens, store, config, managed, oauth2.Arguments{"openid"})
	require.NoError(t, err)

	requester, err := store.GetAccessTokenSession(ctx, tokens.AccessTokenSignature(ctx, tokenString), NewDefaultSession())
	require.NoError(t, err)

	// The token binds to the client it manages; that is what "what may this token configure" resolves to.
	assert.Equal(t, "managed-one", requester.GetClient().GetID())
	assert.True(t, requester.GetGrantedAudience().Has("https://auth.example.com/register/managed-one"))

	session, ok := requester.GetSession().(Session)
	require.True(t, ok)

	assert.Equal(t, KindManage, session.GetClientRegistrationKind())
	assert.Equal(t, "managed-one", session.GetSubject())
	assert.Equal(t, oauth2.Arguments{"openid"}, session.GetGrantableScopes())

	// A zero management lifespan means the token never expires, which is recorded as an explicit far-future expiry
	// rather than as no expiry at all. See NonExpiringTokenLifespan, and the behavioural proof in
	// TestNewClientManagementTokenNeverExpires.
	exp := session.GetExpiresAt(oauth2.AccessToken)

	require.False(t, exp.IsZero())
	assert.True(t, exp.After(time.Now().UTC().AddDate(50, 0, 0)), "expected a far-future expiry, got '%s'", exp)
}

// TestNewClientManagementTokenNeverExpires proves the documented "a zero management lifespan means the token never
// expires" semantic behaviourally rather than by inspecting how it is recorded: the token must still authenticate at
// the client configuration endpoint long after the global AccessTokenLifespan has elapsed. An unset session expiry
// would not survive this, because HMACCoreStrategy.ValidateAccessToken falls back to RequestedAt plus the global
// AccessTokenLifespan whenever the session records no expiry - see TestZeroExpiryRegistrationTokenIsRetired, the
// control that pins that fallback down.
func TestNewClientManagementTokenNeverExpires(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, _ := newTokenFixtures(t)

	// Deliberately tiny, so the global fallback has certainly elapsed by the time the token is presented.
	config.AccessTokenLifespan = time.Nanosecond

	auth := NewDefaultEndpointAuthStrategy(config, store, tokens)

	tokenString, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "forever"}, oauth2.Arguments{"openid"})
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/forever", tokenString), "forever")
	require.NoError(t, err)

	assert.Equal(t, "forever", requester.GetSession().GetSubject())
}

// TestZeroExpiryRegistrationTokenIsRetired is the control for TestNewClientManagementTokenNeverExpires. It builds the
// same session by hand but leaves the access token expiry unset, which is what NewClientManagementToken used to do for
// a zero lifespan, and shows the resulting token is rejected once the global AccessTokenLifespan has elapsed. Without
// this the test above could pass for the wrong reason.
func TestZeroExpiryRegistrationTokenIsRetired(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, _ := newTokenFixtures(t)

	config.AccessTokenLifespan = time.Nanosecond

	auth := NewDefaultEndpointAuthStrategy(config, store, tokens)

	session := NewDefaultSession()
	session.SetClientRegistrationKind(KindManage)
	session.SetSubject("forever")

	requester := oauth2.NewRequest()
	requester.Client = &oauth2.DefaultClient{ID: "forever"}
	requester.Session = session
	requester.GrantAudience(ClientConfigurationURL("https://auth.example.com/register", "forever"))

	tokenString, signature, err := tokens.GenerateAccessToken(ctx, requester)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, requester))

	time.Sleep(time.Millisecond)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/forever", tokenString), "forever")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

// TestNewClientManagementTokenNeverExpiresUnderJWTProfile is TestNewClientManagementTokenNeverExpires for the other
// access token strategy. The two must agree: the same configuration cannot produce a token that never expires on one
// deployment and one that quietly dies after the global AccessTokenLifespan on another.
func TestNewClientManagementTokenNeverExpiresUnderJWTProfile(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: "https://auth.example.com/register",
		EnforceJWTProfileAccessTokens:        true,
		AccessTokenIssuer:                    "https://auth.example.com",
		AccessTokenLifespan:                  time.Nanosecond,
	}

	store := storage.NewMemoryStore()

	strategy := &hoauth2.JWTProfileCoreStrategy{
		HMACCoreStrategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey()),
		},
		Config: config,
	}

	auth := NewDefaultEndpointAuthStrategy(config, store, strategy)

	tokenString, err := NewClientManagementToken(ctx, strategy, store, config, &oauth2.DefaultClient{ID: "forever-jwt"}, oauth2.Arguments{"openid"})
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/forever-jwt", tokenString), "forever-jwt")
	require.NoError(t, err)

	assert.Equal(t, "forever-jwt", requester.GetSession().GetSubject())

	// The 'exp' claim is present and far in the future rather than absent, so a resource server reading the JWT sees
	// the same lifetime the opaque strategy enforces.
	token, err := strategy.Decode(ctx, tokenString)
	require.NoError(t, err)

	expires, err := token.Claims.GetExpirationTime()
	require.NoError(t, err)
	require.NotNil(t, expires)

	assert.True(t, expires.After(time.Now().UTC().AddDate(50, 0, 0)), "expected a far-future 'exp' claim, got '%s'", expires)
}

func TestNewClientManagementTokenHonoursConfiguredLifespan(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, _ := newTokenFixtures(t)
	config.RFC7591ClientRegistrationManageTokenLifespan = time.Hour

	managed := &oauth2.DefaultClient{ID: "managed-two"}

	tokenString, err := NewClientManagementToken(ctx, tokens, store, config, managed, nil)
	require.NoError(t, err)

	requester, err := store.GetAccessTokenSession(ctx, tokens.AccessTokenSignature(ctx, tokenString), NewDefaultSession())
	require.NoError(t, err)

	assert.False(t, requester.GetSession().GetExpiresAt(oauth2.AccessToken).IsZero())
}

func TestNewClientManagementTokenUnderJWTProfile(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: "https://auth.example.com/register",
		EnforceJWTProfileAccessTokens:        true,
		AccessTokenIssuer:                    "https://auth.example.com",
	}

	store := storage.NewMemoryStore()

	strategy := &hoauth2.JWTProfileCoreStrategy{
		HMACCoreStrategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey()),
		},
		Config: config,
	}

	managed := &oauth2.DefaultClient{ID: "managed-jwt"}

	tokenString, err := NewClientManagementToken(ctx, strategy, store, config, managed, oauth2.Arguments{"openid"})
	require.NoError(t, err)

	// Enforced JWT profile means the access token is a JWT: three dot-separated parts.
	assert.Len(t, strings.SplitN(tokenString, ".", 4), 3)

	requester, err := store.GetAccessTokenSession(ctx, strategy.AccessTokenSignature(ctx, tokenString), NewDefaultSession())
	require.NoError(t, err)

	session, ok := requester.GetSession().(Session)
	require.True(t, ok)

	assert.Equal(t, KindManage, session.GetClientRegistrationKind())
	assert.Equal(t, oauth2.Arguments{"openid"}, session.GetGrantableScopes())
}

// TestRegistrationTokenIsRejectedByIntrospection is the end-to-end counterpart of the unit cases in
// handler/oauth2/introspector_test.go. Registration tokens are ordinary access tokens in ordinary access token
// storage, so without an explicit guard a creation token - typically minted for a privileged onboarding client -
// would authenticate its holder as that client at the introspection endpoint, which
// Fosite.handleNewIntrospectionRequestClientAuthentication derives from whatever bearer token introspects
// successfully. An ordinary access token must keep working.
func TestRegistrationTokenIsRejectedByIntrospection(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, client := newTokenFixtures(t)

	validator := &hoauth2.CoreValidator{CoreStrategy: tokens, CoreStorage: store, Config: config}

	registration, err := NewClientCreationToken(ctx, tokens, store, config, client, oauth2.Arguments{"openid"})
	require.NoError(t, err)

	_, err = validator.IntrospectToken(ctx, registration, oauth2.AccessToken, oauth2.NewAccessRequest(NewDefaultSession()), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)

	ordinary := oauth2.NewRequest()
	ordinary.Client = client
	ordinary.Session = &oauth2.DefaultSession{}

	tokenString, signature, err := tokens.GenerateAccessToken(ctx, ordinary)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, ordinary))

	use, err := validator.IntrospectToken(ctx, tokenString, oauth2.AccessToken, oauth2.NewAccessRequest(&oauth2.DefaultSession{}), nil)
	require.NoError(t, err)
	assert.Equal(t, oauth2.AccessToken, use)
}
