// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"

	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/integration/clients"
	"authelia.com/provider/oauth2/storage"
)

func newDefaultSession() *defaultSession {
	return &defaultSession{DefaultSession: &openid.DefaultSession{}}
}

func createIssuerPublicKey(issuer, subject, keyID string, key crypto.PublicKey, scopes, audience []string) storage.IssuerPublicKeys {
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
						Scopes:   scopes,
						Audience: audience,
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

func mockServer(t *testing.T, f oauth2.Provider, session oauth2.Session) *httptest.Server {
	router := http.NewServeMux()
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

type defaultSession struct {
	*openid.DefaultSession
}
