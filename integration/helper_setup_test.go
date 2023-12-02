// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/gorilla/mux"
	goauth "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/handler/oauth2"
	"github.com/authelia/goauth2/handler/openid"
	"github.com/authelia/goauth2/integration/clients"
	"github.com/authelia/goauth2/internal"
	"github.com/authelia/goauth2/internal/gen"
	"github.com/authelia/goauth2/storage"
	"github.com/authelia/goauth2/token/hmac"
	"github.com/authelia/goauth2/token/jwt"
)

const (
	firstKeyID  = "123"
	secondKeyID = "321"

	firstJWTBearerIssuer  = "first@example.com"
	secondJWTBearerIssuer = "second@example.com"

	firstJWTBearerSubject  = "first-service-client"
	secondJWTBearerSubject = "second-service-client"

	tokenURL          = "https://www.ory.sh/api"
	tokenRelativePath = "/token"
)

var (
	firstPrivateKey, _  = rsa.GenerateKey(rand.Reader, 2048)
	secondPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

var fositeStore = &storage.MemoryStore{
	Clients: map[string]goauth2.Client{
		"my-client": &goauth2.DefaultClient{
			ID:            "my-client",
			Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{"id_token", "code", "token", "token code", "id_token code", "token id_token", "token code id_token"},
			GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
			Scopes:        []string{"goauth2", "offline", "openid"},
			Audience:      []string{tokenURL},
		},
		"custom-lifespan-client": &goauth2.DefaultClientWithCustomTokenLifespans{
			DefaultClient: &goauth2.DefaultClient{
				ID:             "custom-lifespan-client",
				Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
				RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
				RedirectURIs:   []string{"http://localhost:3846/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"goauth2", "openid", "photos", "offline"},
			},
			TokenLifespans: &internal.TestLifespans,
		},
		"public-client": &goauth2.DefaultClient{
			ID:            "public-client",
			Secret:        []byte{},
			Public:        true,
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{"id_token", "code", "code id_token"},
			GrantTypes:    []string{"refresh_token", "authorization_code"},
			Scopes:        []string{"goauth2", "offline", "openid"},
			Audience:      []string{tokenURL},
		},
	},
	Users: map[string]storage.MemoryUserRelation{
		"peter": {
			Username: "peter",
			Password: "secret",
		},
	},
	IssuerPublicKeys: map[string]storage.IssuerPublicKeys{
		firstJWTBearerIssuer: createIssuerPublicKey(
			firstJWTBearerIssuer,
			firstJWTBearerSubject,
			firstKeyID,
			firstPrivateKey.Public(),
			[]string{"goauth2", "gitlab", "example.com", "docker"},
		),
		secondJWTBearerIssuer: createIssuerPublicKey(
			secondJWTBearerIssuer,
			secondJWTBearerSubject,
			secondKeyID,
			secondPrivateKey.Public(),
			[]string{"goauth2"},
		),
	},
	BlacklistedJTIs:        map[string]time.Time{},
	AuthorizeCodes:         map[string]storage.StoreAuthorizeCode{},
	PKCES:                  map[string]goauth2.Requester{},
	AccessTokens:           map[string]goauth2.Requester{},
	RefreshTokens:          map[string]storage.StoreRefreshToken{},
	IDSessions:             map[string]goauth2.Requester{},
	AccessTokenRequestIDs:  map[string]string{},
	RefreshTokenRequestIDs: map[string]string{},
	PARSessions:            map[string]goauth2.AuthorizeRequester{},
}

type defaultSession struct {
	*openid.DefaultSession
}

var accessTokenLifespan = time.Hour

var authCodeLifespan = time.Minute

func createIssuerPublicKey(issuer, subject, keyID string, key crypto.PublicKey, scopes []string) storage.IssuerPublicKeys {
	return storage.IssuerPublicKeys{
		Issuer: issuer,
		KeysBySub: map[string]storage.SubjectPublicKeys{
			subject: {
				Subject: subject,
				Keys: map[string]storage.PublicKeyScopes{
					keyID: {
						Key: &jose.JSONWebKey{
							Key:       key,
							Algorithm: string(jose.RS256),
							Use:       "sig",
							KeyID:     keyID,
						},
						Scopes: scopes,
					},
				},
			},
		},
	}
}

func newOAuth2Client(ts *httptest.Server) *goauth.Config {
	return &goauth.Config{
		ClientID:     "my-client",
		ClientSecret: "foobar",
		RedirectURL:  ts.URL + "/callback",
		Scopes:       []string{"goauth2"},
		Endpoint: goauth.Endpoint{
			TokenURL:  ts.URL + tokenRelativePath,
			AuthURL:   ts.URL + "/auth",
			AuthStyle: goauth.AuthStyleInHeader,
		},
	}
}

func newOAuth2AppClient(ts *httptest.Server) *clientcredentials.Config {
	return &clientcredentials.Config{
		ClientID:     "my-client",
		ClientSecret: "foobar",
		Scopes:       []string{"goauth2"},
		TokenURL:     ts.URL + tokenRelativePath,
	}
}

func newJWTBearerAppClient(ts *httptest.Server) *clients.JWTBearer {
	return clients.NewJWTBearer(ts.URL + tokenRelativePath)
}

var hmacStrategy = &oauth2.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		Config: &goauth2.Config{
			GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
		},
	},
	Config: &goauth2.Config{
		AccessTokenLifespan:   accessTokenLifespan,
		AuthorizeCodeLifespan: authCodeLifespan,
	},
}

var defaultRSAKey = gen.MustRSAKey()

var jwtStrategy = &oauth2.DefaultJWTStrategy{
	Signer: &jwt.DefaultSigner{
		GetPrivateKey: func(ctx context.Context) (interface{}, error) {
			return defaultRSAKey, nil
		},
	},
	Config:          &goauth2.Config{},
	HMACSHAStrategy: hmacStrategy,
}

func mockServer(t *testing.T, f goauth2.OAuth2Provider, session goauth2.Session) *httptest.Server {
	router := mux.NewRouter()
	router.HandleFunc("/auth", authEndpointHandler(t, f, session))
	router.HandleFunc(tokenRelativePath, tokenEndpointHandler(t, f))
	router.HandleFunc("/callback", authCallbackHandler(t))
	router.HandleFunc("/info", tokenInfoHandler(t, f, session))
	router.HandleFunc("/introspect", tokenIntrospectionHandler(t, f, session))
	router.HandleFunc("/revoke", tokenRevocationHandler(t, f, session))
	router.HandleFunc("/par", pushedAuthorizeRequestHandler(t, f, session))

	ts := httptest.NewServer(router)
	return ts
}
