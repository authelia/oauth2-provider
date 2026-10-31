// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/storage"
)

type sessionBindingStore interface {
	Storage
	rfc9449.Storage
}

func TestAuthReadsTheSessionStateOfEverySessionType(t *testing.T) {
	stores := map[string]func() sessionBindingStore{
		"MemoryStore":          func() sessionBindingStore { return storage.NewMemoryStore() },
		"HydratingMemoryStore": func() sessionBindingStore { return storage.NewHydratingMemoryStore() },
	}

	sessions := map[string]func(exp time.Time, jkt, x5t string) oauth2.Session{
		"DefaultSession": func(exp time.Time, jkt, x5t string) oauth2.Session {
			return &oauth2.DefaultSession{
				ExpiresAt:                   map[oauth2.TokenType]time.Time{oauth2.AccessToken: exp},
				JWKThumbprint:               jkt,
				ClientCertificateThumbprint: x5t,
			}
		},
		"JWTSession": func(exp time.Time, jkt, x5t string) oauth2.Session {
			return &hoauth2.JWTSession{
				ExpiresAt:                   map[oauth2.TokenType]time.Time{oauth2.AccessToken: exp},
				JWKThumbprint:               jkt,
				ClientCertificateThumbprint: x5t,
			}
		},
	}

	for storeName, newStore := range stores {
		for sessionName, newSession := range sessions {
			t.Run(storeName+"/"+sessionName, func(t *testing.T) {
				ctx := context.Background()
				valid := time.Now().UTC().Add(time.Hour)

				mint := func(t *testing.T, auth *DefaultEndpointAuthStrategy, session oauth2.Session) string {
					t.Helper()

					request := oauth2.NewRequest()
					request.Client = &oauth2.DefaultClient{ID: "onboarding"}
					request.Session = session
					request.GrantScope("authelia:oauth2:client_registration")
					request.GrantAudience(testEndpoint)

					token, signature, err := auth.AccessTokenStrategy.GenerateAccessToken(ctx, request)
					require.NoError(t, err)
					require.NoError(t, auth.Store.CreateAccessTokenSession(ctx, signature, request))

					return token
				}

				setup := func(t *testing.T) *DefaultEndpointAuthStrategy {
					t.Helper()

					config := &oauth2.Config{
						GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
						RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
						RFC7591ClientRegistrationEndpointURL:  testEndpoint,
						TokenEntropy:                          32,
						DPoPEnabled:                           true,
						MTLSEnabled:                           true,
					}

					store := newStore()
					config.DPoPStrategy = rfc9449.NewDefaultStrategy(config, store)
					access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

					return NewDefaultEndpointAuthStrategy(config, store, access, access)
				}

				t.Run("ShouldAcceptADPoPBoundTokenPresentedWithAValidProof", func(t *testing.T) {
					auth := setup(t)
					key := newProofKey(t)
					token := mint(t, auth, newSession(valid, proofThumbprint(t, key), ""))

					proof := signDPoPProof(t, key, "reg-1", http.MethodPost, testEndpoint, token)

					_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

					assert.NoError(t, err)
				})

				t.Run("ShouldRejectADPoPBoundTokenPresentedAsABearerToken", func(t *testing.T) {
					auth := setup(t)
					token := mint(t, auth, newSession(valid, proofThumbprint(t, newProofKey(t)), ""))

					_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

					assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
				})

				t.Run("ShouldRejectACertificateBoundTokenPresentedWithoutACertificate", func(t *testing.T) {
					auth := setup(t)
					token := mint(t, auth, newSession(valid, "", "bound-thumbprint"))

					_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

					assert.Error(t, err)
				})

				t.Run("ShouldRejectATokenPastItsSessionExpiry", func(t *testing.T) {
					auth := setup(t)
					token := mint(t, auth, newSession(time.Now().UTC().Add(-time.Minute), "", ""))

					_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

					assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
				})

				t.Run("ShouldAcceptAnUnboundToken", func(t *testing.T) {
					auth := setup(t)
					token := mint(t, auth, newSession(valid, "", ""))

					_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

					assert.NoError(t, err)
				})
			})
		}
	}
}
