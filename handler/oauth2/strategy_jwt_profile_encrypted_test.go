// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

// FAPI 2.0 Security Profile Section 5.3.4.
func TestEncryptedJWTProfileAccessTokenFAPI2SecurityProfile(t *testing.T) {
	ctx := t.Context()

	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		FAPI2SecurityProfile:          true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	strategy := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: gen.MustRSAKey(), KeyID: "ps256", Algorithm: string(jose.PS256), Use: consts.JSONWebTokenUseSignature},
	}})})

	request := jwtValidCase(oauth2.AccessToken)
	request.Client = &oauth2.DefaultRegisteredClient{
		DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc"},
		JSONWebKeys:                     &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: gen.MustRSAKey().Public(), KeyID: "enc", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)}}},
		AccessTokenSignedResponseAlg:    string(jose.PS256),
		AccessTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
		AccessTokenEncryptedResponseEnc: string(jose.A128GCM),
	}

	token, signature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	require.Len(t, strings.Split(token, "."), 5)

	store := storage.NewHydratingMemoryStore()
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	stateless := &StatelessJWTValidator{StatelessJWTStrategy: strategy.(*JWTProfileCoreStrategy), Config: config}

	_, err = stateless.IntrospectToken(ctx, token, oauth2.AccessToken, oauth2.NewAccessRequest(&JWTSession{}), nil)
	require.ErrorIs(t, err, oauth2.ErrUnknownRequest)

	use, err := (&CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config}).IntrospectToken(ctx, token, oauth2.AccessToken, oauth2.NewAccessRequest(&JWTSession{}), nil)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	assert.Equal(t, oauth2.AccessToken, use)
}

func TestEncryptedJWTProfileAccessTokenStorage(t *testing.T) {
	ctx := t.Context()

	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	strategy := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())})

	newRequest := func(t *testing.T) (request *oauth2.Request, token, signature string) {
		t.Helper()

		request = jwtValidCase(oauth2.AccessToken)
		request.Client = &oauth2.DefaultRegisteredClient{
			DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc"},
			JSONWebKeys:                     &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: gen.MustRSAKey().Public(), KeyID: "enc", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)}}},
			AccessTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
			AccessTokenEncryptedResponseEnc: string(jose.A128GCM),
		}

		var err error

		token, signature, err = strategy.GenerateAccessToken(ctx, request)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		require.Len(t, strings.Split(token, "."), 5)

		return request, token, signature
	}

	t.Run("ShouldStoreUnderTheDigestOfTheToken", func(t *testing.T) {
		_, token, signature := newRequest(t)

		assert.Equal(t, encryptedAccessTokenSignature(token), signature)
		assert.Equal(t, signature, strategy.AccessTokenSignature(ctx, token))
	})

	t.Run("ShouldRecordTheDigestOnTheSession", func(t *testing.T) {
		request, _, signature := newRequest(t)

		assert.Equal(t, signature, request.GetSession().(EncryptedAccessTokenSession).GetAccessTokenDigest())
	})

	for name, store := range map[string]interface {
		CoreStorage
	}{"MemoryStore": storage.NewMemoryStore(), "HydratingMemoryStore": storage.NewHydratingMemoryStore()} {
		t.Run("ShouldIntrospectFromStorage/"+name, func(t *testing.T) {
			request, token, signature := newRequest(t)

			require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

			validator := &CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config}

			use, err := validator.IntrospectToken(ctx, token, oauth2.AccessToken, oauth2.NewAccessRequest(&JWTSession{}), nil)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, oauth2.AccessToken, use)
		})
	}

	t.Run("ShouldRejectAnotherTokenForTheSession", func(t *testing.T) {
		request, _, _ := newRequest(t)
		_, other, _ := newRequest(t)

		require.ErrorIs(t, strategy.ValidateAccessToken(ctx, request, other), oauth2.ErrTokenSignatureMismatch)
	})

	t.Run("ShouldRejectASessionWithoutADigest", func(t *testing.T) {
		request, token, _ := newRequest(t)

		request.Session = &oauth2.DefaultSession{ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)}}

		require.ErrorIs(t, strategy.ValidateAccessToken(ctx, request, token), oauth2.ErrTokenSignatureMismatch)
	})

	t.Run("ShouldRejectARequestWithoutASession", func(t *testing.T) {
		request, token, _ := newRequest(t)

		request.Session = nil

		require.ErrorIs(t, strategy.ValidateAccessToken(ctx, request, token), oauth2.ErrTokenSignatureMismatch)
	})

	t.Run("ShouldVerifyTheSignatureWithoutASession", func(t *testing.T) {
		request, token, signature := newRequest(t)

		request.Session = nil

		verifier := strategy.(AccessTokenSignatureVerifier)

		require.NoError(t, verifier.VerifyAccessTokenSignature(ctx, request, token, signature))
		require.ErrorIs(t, verifier.VerifyAccessTokenSignature(ctx, request, token, "another"), oauth2.ErrTokenSignatureMismatch)
	})

	t.Run("ShouldRevokeFromAStoreReturningNoSession", func(t *testing.T) {
		request, token, signature := newRequest(t)

		store := &sessionlessAccessTokenStore{MemoryStore: storage.NewMemoryStore()}
		require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

		revocation := &TokenRevocationHandler{TokenRevocationStorage: store, AccessTokenStrategy: strategy, RefreshTokenStrategy: strategy, Config: config}
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(revocation.RevokeToken(ctx, token, oauth2.AccessToken, request.GetClient())))

		_, err := store.MemoryStore.GetAccessTokenSession(ctx, signature, nil)
		require.ErrorIs(t, err, oauth2.ErrNotFound)
	})

	t.Run("ShouldNotIntrospectAnAlteredToken", func(t *testing.T) {
		request, token, signature := newRequest(t)

		store := storage.NewMemoryStore()
		require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

		validator := &CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config}

		segments := strings.Split(token, ".")
		segments[3] = "A" + segments[3][1:]

		if segments[3] == strings.Split(token, ".")[3] {
			segments[3] = "B" + segments[3][1:]
		}

		_, err := validator.IntrospectToken(ctx, strings.Join(segments, "."), oauth2.AccessToken, oauth2.NewAccessRequest(&JWTSession{}), nil)
		require.Error(t, err)
	})

	t.Run("ShouldRevokeFromStorage", func(t *testing.T) {
		request, token, signature := newRequest(t)

		store := storage.NewMemoryStore()
		require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

		revocation := &TokenRevocationHandler{TokenRevocationStorage: store, AccessTokenStrategy: strategy, RefreshTokenStrategy: strategy, Config: config}
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(revocation.RevokeToken(ctx, token, oauth2.AccessToken, request.GetClient())))

		validator := &CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config}

		_, err := validator.IntrospectToken(ctx, token, oauth2.AccessToken, oauth2.NewAccessRequest(&JWTSession{}), nil)
		require.Error(t, err)
	})

	t.Run("ShouldRejectAnExpiredToken", func(t *testing.T) {
		request, token, _ := newRequest(t)

		request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(-time.Minute))

		require.ErrorIs(t, strategy.ValidateAccessToken(ctx, request, token), oauth2.ErrTokenExpired)
	})
}

type sessionlessAccessTokenStore struct {
	*storage.MemoryStore
}

func (s *sessionlessAccessTokenStore) GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if request, err = s.MemoryStore.GetAccessTokenSession(ctx, signature, session); err != nil {
		return nil, err
	}

	stored := *request.(*oauth2.Request)
	stored.Session = nil

	return &stored, nil
}

func TestEncryptedJWTProfileAccessTokenStatelessIntrospection(t *testing.T) {
	ctx := t.Context()

	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
		ScopeStrategy:                 oauth2.HierarchicScopeStrategy,
	}

	strategy := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())})

	stateless := &StatelessJWTValidator{StatelessJWTStrategy: strategy.(*JWTProfileCoreStrategy), Config: config}

	foreign := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())})

	testCases := []struct {
		name     string
		client   *oauth2.DefaultRegisteredClient
		issuer   CoreStrategy
		present  bool
		deferred bool
		definite bool
	}{
		{
			name: "ShouldSkipATokenEncryptedToAPublicKeyOfTheClient",
			client: &oauth2.DefaultRegisteredClient{
				DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc"},
				JSONWebKeys:                     &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: gen.MustRSAKey().Public(), KeyID: "enc", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)}}},
				AccessTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
				AccessTokenEncryptedResponseEnc: string(jose.A128GCM),
			},
			present:  true,
			deferred: true,
		},
		{
			name: "ShouldSkipATokenEncryptedToTheClientSecretWithoutTheClient",
			client: &oauth2.DefaultRegisteredClient{
				DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc", ClientSecret: oauth2.NewPlainTextClientSecret("foobarfoobarfoobarfoobarfoobarfoobar")},
				AccessTokenEncryptedResponseAlg: string(jose.A256KW),
				AccessTokenEncryptedResponseEnc: string(jose.A128GCM),
			},
			deferred: true,
		},
		{
			name: "ShouldIntrospectATokenEncryptedToTheClientSecretWithTheClient",
			client: &oauth2.DefaultRegisteredClient{
				DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc", ClientSecret: oauth2.NewPlainTextClientSecret("foobarfoobarfoobarfoobarfoobarfoobar")},
				AccessTokenEncryptedResponseAlg: string(jose.A256KW),
				AccessTokenEncryptedResponseEnc: string(jose.A128GCM),
			},
			present: true,
		},
		{
			name: "ShouldRejectADecryptedTokenWithAnotherSignature",
			client: &oauth2.DefaultRegisteredClient{
				DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc", ClientSecret: oauth2.NewPlainTextClientSecret("foobarfoobarfoobarfoobarfoobarfoobar")},
				AccessTokenEncryptedResponseAlg: string(jose.A256KW),
				AccessTokenEncryptedResponseEnc: string(jose.A128GCM),
			},
			issuer:   foreign,
			present:  true,
			definite: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := jwtValidCase(oauth2.AccessToken)
			request.Client = tc.client

			issuer := strategy
			if tc.issuer != nil {
				issuer = tc.issuer
			}

			token, _, err := issuer.GenerateAccessToken(ctx, request)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			require.Len(t, strings.Split(token, "."), 5)

			introspection := oauth2.NewAccessRequest(&JWTSession{})

			if tc.present {
				introspection.Client = tc.client
			}

			use, err := stateless.IntrospectToken(ctx, token, oauth2.AccessToken, introspection, nil)

			switch {
			case tc.deferred:
				assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
			case tc.definite:
				require.Error(t, err)
				assert.NotErrorIs(t, err, oauth2.ErrUnknownRequest)
			default:
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, oauth2.AccessToken, use)
				assert.Equal(t, "peter", introspection.GetSession().GetSubject())
			}
		})
	}
}
