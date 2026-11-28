// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestEncryptedAccessTokenIntrospection(t *testing.T) {
	for _, st := range encryptedAccessTokenTestStores {
		for _, session := range encryptedAccessTokenTestSessions {
			for _, client := range encryptedAccessTokenTestClients {
				for _, order := range []string{"StatelessFirst", "CoreFirst", "CoreOnly"} {
					t.Run(st.name+"/"+session.name+"/"+client.name+"/"+order, func(t *testing.T) {
						config, strategy := newEncryptedAccessTokenTestStrategy()
						store := st.new()

						token := issueEncryptedAccessTokenTest(t, strategy, store, session.new(), client.new())

						stateless := &hoauth2.StatelessJWTValidator{StatelessJWTStrategy: strategy.(*hoauth2.JWTProfileCoreStrategy), Config: config}
						core := &hoauth2.CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config}

						switch order {
						case "StatelessFirst":
							config.TokenIntrospectionHandlers = oauth2.TokenIntrospectionHandlers{stateless, core}
						case "CoreFirst":
							config.TokenIntrospectionHandlers = oauth2.TokenIntrospectionHandlers{core, stateless}
						default:
							config.TokenIntrospectionHandlers = oauth2.TokenIntrospectionHandlers{core}
						}

						provider := &oauth2.Fosite{Store: store, Config: config}

						use, requester, err := provider.IntrospectToken(t.Context(), token, oauth2.AccessToken, session.new())

						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
						assert.Equal(t, oauth2.AccessToken, use)
						assert.Equal(t, "peter", requester.GetSession().GetSubject())
					})
				}
			}
		}
	}
}

func TestEncryptedAccessTokenIntrospectionRejections(t *testing.T) {
	for _, st := range encryptedAccessTokenTestStores {
		for _, client := range encryptedAccessTokenTestClients {
			t.Run(st.name+"/"+client.name, func(t *testing.T) {
				newProvider := func(t *testing.T, handlers func(stateless, core oauth2.TokenIntrospector) oauth2.TokenIntrospectionHandlers) (provider *oauth2.Fosite, store encryptedAccessTokenTestStore, request *oauth2.Request, token string) {
					t.Helper()

					config, strategy := newEncryptedAccessTokenTestStrategy()
					store = st.new()
					token, request = issueEncryptedAccessTokenTestRequest(t, strategy, store, newEncryptedAccessTokenTestJWTSession(), client.new())

					config.TokenIntrospectionHandlers = handlers(
						&hoauth2.StatelessJWTValidator{StatelessJWTStrategy: strategy.(*hoauth2.JWTProfileCoreStrategy), Config: config},
						&hoauth2.CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config},
					)

					return &oauth2.Fosite{Store: store, Config: config}, store, request, token
				}

				both := func(stateless, core oauth2.TokenIntrospector) oauth2.TokenIntrospectionHandlers {
					return oauth2.TokenIntrospectionHandlers{stateless, core}
				}

				t.Run("ShouldRejectAnAlteredToken", func(t *testing.T) {
					provider, _, _, token := newProvider(t, both)

					segments := strings.Split(token, ".")
					segments[3] = strings.Repeat("A", len(segments[3]))

					_, _, err := provider.IntrospectToken(t.Context(), strings.Join(segments, "."), oauth2.AccessToken, newEncryptedAccessTokenTestJWTSession())

					assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
				})

				t.Run("ShouldRejectARevokedToken", func(t *testing.T) {
					provider, store, request, token := newProvider(t, both)

					require.NoError(t, store.RevokeAccessToken(t.Context(), request.GetID()))

					_, _, err := provider.IntrospectToken(t.Context(), token, oauth2.AccessToken, newEncryptedAccessTokenTestJWTSession())

					assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
				})

				t.Run("ShouldRejectATokenOnlyTheStatelessIntrospectorIsGiven", func(t *testing.T) {
					provider, _, _, token := newProvider(t, func(stateless, _ oauth2.TokenIntrospector) oauth2.TokenIntrospectionHandlers {
						return oauth2.TokenIntrospectionHandlers{stateless}
					})

					_, _, err := provider.IntrospectToken(t.Context(), token, oauth2.AccessToken, newEncryptedAccessTokenTestJWTSession())

					assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
				})
			})
		}
	}
}

func TestEncryptedAccessTokenIssuance(t *testing.T) {
	t.Run("ShouldRefuseASessionWhichCannotRecordTheDigest", func(t *testing.T) {
		_, strategy := newEncryptedAccessTokenTestStrategy()

		request := newEncryptedAccessTokenTestRequest(&encryptedAccessTokenTestDigestlessSession{JWTSessionContainer: newEncryptedAccessTokenTestJWTSession()}, newEncryptedAccessTokenTestPublicKeyClient())

		token, _, err := strategy.GenerateAccessToken(t.Context(), request)

		assert.Empty(t, token)
		assert.ErrorIs(t, err, oauth2.ErrMisconfiguration)
	})

	t.Run("ShouldIssueAnUnencryptedTokenOnASessionWhichCannotRecordTheDigest", func(t *testing.T) {
		_, strategy := newEncryptedAccessTokenTestStrategy()

		request := newEncryptedAccessTokenTestRequest(&encryptedAccessTokenTestDigestlessSession{JWTSessionContainer: newEncryptedAccessTokenTestJWTSession()}, &oauth2.DefaultClient{ID: "client"})

		token, _, err := strategy.GenerateAccessToken(t.Context(), request)

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		assert.Len(t, strings.Split(token, "."), 3)
	})
}

var encryptedAccessTokenTestStores = []struct {
	name string
	new  func() encryptedAccessTokenTestStore
}{
	{name: "MemoryStore", new: func() encryptedAccessTokenTestStore { return storage.NewMemoryStore() }},
	{name: "HydratingMemoryStore", new: func() encryptedAccessTokenTestStore { return storage.NewHydratingMemoryStore() }},
}

type encryptedAccessTokenTestStore interface {
	oauth2.Storage
	hoauth2.CoreStorage
	hoauth2.TokenRevocationStorage
}

var encryptedAccessTokenTestSessions = []struct {
	name string
	new  func() oauth2.Session
}{
	{name: "JWTSession", new: func() oauth2.Session { return newEncryptedAccessTokenTestJWTSession() }},
	{name: "EmbeddedOpenIDSession", new: func() oauth2.Session {
		session := &encryptedAccessTokenTestEmbeddedSession{
			DefaultSession: openid.NewDefaultSession(),
			JWTClaims:      &jwt.JWTClaims{Subject: "peter"},
		}

		session.Subject, session.Claims.Subject = "peter", "peter"
		session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))

		return session
	}},
	{name: "RFC8693DefaultSession", new: func() oauth2.Session {
		session := rfc8693.NewDefaultSession()

		session.Subject, session.Claims.Subject = "peter", "peter"
		session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))

		return session
	}},
}

var encryptedAccessTokenTestClients = []struct {
	name string
	new  func() oauth2.Client
}{
	{name: "PublicKey", new: newEncryptedAccessTokenTestPublicKeyClient},
	{name: "ClientSecret", new: func() oauth2.Client {
		return &oauth2.DefaultRegisteredClient{
			DefaultClient:                   &oauth2.DefaultClient{ID: "client", ClientSecret: oauth2.NewPlainTextClientSecret("foobarfoobarfoobarfoobarfoobarfoobar")},
			AccessTokenEncryptedResponseAlg: string(jose.A256KW),
			AccessTokenEncryptedResponseEnc: string(jose.A128GCM),
		}
	}},
}

type encryptedAccessTokenTestEmbeddedSession struct {
	*openid.DefaultSession `json:"id_token"`

	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
}

func (s *encryptedAccessTokenTestEmbeddedSession) GetJWTClaims() jwt.JWTClaimsContainer {
	return s.JWTClaims
}

func (s *encryptedAccessTokenTestEmbeddedSession) GetJWTHeader() *jwt.Headers {
	return &jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeAccessToken}}
}

type encryptedAccessTokenTestDigestlessSession struct {
	hoauth2.JWTSessionContainer
}

func newEncryptedAccessTokenTestStrategy() (config *oauth2.Config, strategy hoauth2.CoreStrategy) {
	config = &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		Issuer:                        "https://auth.example.com",
		GlobalSecret:                  []byte("some-cool-secret-that-is-32bytes"),
		ScopeStrategy:                 oauth2.HierarchicScopeStrategy,
	}

	return config, hoauth2.NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())})
}

func newEncryptedAccessTokenTestJWTSession() (session *hoauth2.JWTSession) {
	return &hoauth2.JWTSession{
		JWTClaims: &jwt.JWTClaims{Subject: "peter", IssuedAt: time.Now().UTC()},
		JWTHeader: &jwt.Headers{},
		Subject:   "peter",
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}
}

func newEncryptedAccessTokenTestPublicKeyClient() oauth2.Client {
	return &oauth2.DefaultRegisteredClient{
		DefaultClient:                   &oauth2.DefaultClient{ID: "client"},
		JSONWebKeys:                     &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: gen.MustRSAKey().Public(), KeyID: "enc", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)}}},
		AccessTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
		AccessTokenEncryptedResponseEnc: string(jose.A128GCM),
	}
}

func newEncryptedAccessTokenTestRequest(session oauth2.Session, client oauth2.Client) (request *oauth2.Request) {
	request = oauth2.NewRequest()
	request.Session = session
	request.Client = client

	request.GrantScope(consts.ScopeOpenID)
	request.GrantAudience("https://resource.example.com")

	return request
}

func issueEncryptedAccessTokenTest(t *testing.T, strategy hoauth2.CoreStrategy, store hoauth2.CoreStorage, session oauth2.Session, client oauth2.Client) (token string) {
	t.Helper()

	token, _ = issueEncryptedAccessTokenTestRequest(t, strategy, store, session, client)

	return token
}

func issueEncryptedAccessTokenTestRequest(t *testing.T, strategy hoauth2.CoreStrategy, store hoauth2.CoreStorage, session oauth2.Session, client oauth2.Client) (token string, request *oauth2.Request) {
	t.Helper()

	request = newEncryptedAccessTokenTestRequest(session, client)

	token, signature, err := strategy.GenerateAccessToken(t.Context(), request)

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	require.Len(t, strings.Split(token, "."), 5)
	require.NoError(t, store.CreateAccessTokenSession(t.Context(), signature, request))

	return token, request
}
