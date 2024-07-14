// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/integration/clients"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	firstKeyID  = "123"
	secondKeyID = "321"

	firstJWTBearerIssuer  = "first@example.com"
	secondJWTBearerIssuer = "second@example.com"

	firstJWTBearerSubject  = "first-service-client"
	secondJWTBearerSubject = "second-service-client"

	tokenURL          = "https://www.authelia.com/api" //nolint:gosec
	tokenRelativePath = "/token"
)

var (
	firstPrivateKey, _  = rsa.GenerateKey(rand.Reader, 2048)
	secondPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

var store = &storage.MemoryStore{
	Clients: map[string]oauth2.Client{
		"my-client": &oauth2.DefaultClient{
			ID:            "my-client",
			ClientSecret:  oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`), // = "foobar"
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowBoth, consts.ResponseTypeHybridFlowIDToken, consts.ResponseTypeHybridFlowToken, consts.ResponseTypeHybridFlowBoth},
			GrantTypes:    []string{consts.GrantTypeImplicit, consts.GrantTypeRefreshToken, consts.GrantTypeAuthorizationCode, consts.GrantTypeResourceOwnerPasswordCredentials, consts.GrantTypeClientCredentials},
			Scopes:        []string{"oauth2", consts.ScopeOffline, consts.ScopeOpenID},
			Audience:      []string{tokenURL},
		},
		"custom-lifespan-client": &oauth2.DefaultClientWithCustomTokenLifespans{
			DefaultClient: &oauth2.DefaultClient{
				ID:                   "custom-lifespan-client",
				ClientSecret:         oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),                        // = "foobar"
				RotatedClientSecrets: []oauth2.ClientSecret{oauth2.NewBCryptClientSecret(`$2a$04$4X4/mCFdQ9tmfjSBBk6RNOhg0MtKE0ql7BPyMHDuiuq7YeY6wGlh.`)}, // = "foobaz"
				RedirectURIs:         []string{"http://localhost:3846/callback"},
				ResponseTypes:        []string{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowBoth, consts.ResponseTypeHybridFlowIDToken, consts.ResponseTypeHybridFlowToken, consts.ResponseTypeHybridFlowBoth},
				GrantTypes:           []string{consts.GrantTypeImplicit, consts.GrantTypeRefreshToken, consts.GrantTypeAuthorizationCode, consts.GrantTypeResourceOwnerPasswordCredentials, consts.GrantTypeClientCredentials},
				Scopes:               []string{"oauth2", consts.ScopeOpenID, "photos", consts.ScopeOffline},
			},
			TokenLifespans: &internal.TestLifespans,
		},
		"public-client": &oauth2.DefaultClient{
			ID:            "public-client",
			Public:        true,
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeHybridFlowIDToken},
			GrantTypes:    []string{consts.GrantTypeRefreshToken, consts.GrantTypeAuthorizationCode},
			Scopes:        []string{"oauth2", consts.ScopeOffline, consts.ScopeOpenID},
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
			[]string{"oauth2", "gitlab", "example.com", "docker"},
		),
		secondJWTBearerIssuer: createIssuerPublicKey(
			secondJWTBearerIssuer,
			secondJWTBearerSubject,
			secondKeyID,
			secondPrivateKey.Public(),
			[]string{"oauth2"},
		),
	},
	BlacklistedJTIs:        map[string]time.Time{},
	AuthorizeCodes:         map[string]storage.StoreAuthorizeCode{},
	PKCES:                  map[string]oauth2.Requester{},
	AccessTokens:           map[string]oauth2.Requester{},
	RefreshTokens:          map[string]storage.StoreRefreshToken{},
	IDSessions:             map[string]oauth2.Requester{},
	AccessTokenRequestIDs:  map[string]string{},
	RefreshTokenRequestIDs: map[string]string{},
	PARSessions:            map[string]oauth2.AuthorizeRequester{},
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

func newOAuth2Client(ts *httptest.Server) *xoauth2.Config {
	return &xoauth2.Config{
		ClientID:     "my-client",
		ClientSecret: "foobar",
		RedirectURL:  ts.URL + "/callback",
		Scopes:       []string{"oauth2"},
		Endpoint: xoauth2.Endpoint{
			TokenURL:  ts.URL + tokenRelativePath,
			AuthURL:   ts.URL + "/auth",
			AuthStyle: xoauth2.AuthStyleInHeader,
		},
	}
}

func newOAuth2AppClient(ts *httptest.Server) *clientcredentials.Config {
	return &clientcredentials.Config{
		ClientID:     "my-client",
		ClientSecret: "foobar",
		Scopes:       []string{"oauth2"},
		TokenURL:     ts.URL + tokenRelativePath,
	}
}

func newJWTBearerAppClient(ts *httptest.Server) *clients.JWTBearer {
	return clients.NewJWTBearer(ts.URL + tokenRelativePath)
}

var hmacStrategy = &hoauth2.HMACCoreStrategy{
	Enigma: &hmac.HMACStrategy{
		Config: &oauth2.Config{
			GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
		},
	},
	Config: &oauth2.Config{
		AccessTokenLifespan:   accessTokenLifespan,
		AuthorizeCodeLifespan: authCodeLifespan,
	},
}

var defaultRSAKey = gen.MustRSAKey()

var jwtStrategy = &hoauth2.JWTProfileCoreStrategy{
	Strategy: &jwt.DefaultStrategy{
		Config: &oauth2.Config{},
		Issuer: jwt.NewDefaultIssuerRS256Unverified(defaultRSAKey),
	},
	Config:           &oauth2.Config{},
	HMACCoreStrategy: hmacStrategy,
}

func mockServer(t *testing.T, f oauth2.Provider, session oauth2.Session) *httptest.Server {
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
