// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/idjag"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidateHandlerOrderPKCE(t *testing.T) {
	explicit, proof := &hoauth2.AuthorizeExplicitGrantHandler{}, &pkce.Handler{}

	testCases := []struct {
		name     string
		handlers oauth2.TokenEndpointHandlers
		err      bool
	}{
		{name: "ShouldPassInTheDocumentedOrder", handlers: oauth2.TokenEndpointHandlers{explicit, proof}},
		{name: "ShouldPassWithThePKCEHandlerAlone", handlers: oauth2.TokenEndpointHandlers{proof}},
		{name: "ShouldPassWithTheExplicitHandlerAlone", handlers: oauth2.TokenEndpointHandlers{explicit}},
		{name: "ShouldFailWhenThePKCEHandlerIsRegisteredFirst", handlers: oauth2.TokenEndpointHandlers{proof, explicit}, err: true},
		{name: "ShouldFailWhenAnEarlierPKCEHandlerPrecedesTheExplicitHandler", handlers: oauth2.TokenEndpointHandlers{proof, explicit, proof}, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: tc.handlers})

			if !tc.err {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)
			assert.Contains(t, err.Error(), "pkce.Handler")
		})
	}
}

func TestValidateHandlerOrderOpenIDConnect(t *testing.T) {
	testCases := []struct {
		name  string
		grant oauth2.TokenEndpointHandler
		oidc  oauth2.TokenEndpointHandler
		kind  string
	}{
		{name: "AuthorizationCode", grant: &hoauth2.AuthorizeExplicitGrantHandler{}, oidc: &openid.OpenIDConnectExplicitHandler{}, kind: "openid.OpenIDConnectExplicitHandler"},
		{name: "RefreshToken", grant: &hoauth2.RefreshTokenGrantHandler{}, oidc: &openid.OpenIDConnectRefreshHandler{}, kind: "openid.OpenIDConnectRefreshHandler"},
		{name: "DeviceCode", grant: &rfc8628.DeviceAuthorizeTokenEndpointHandler{}, oidc: &openid.OpenIDConnectDeviceAuthorizeHandler{}, kind: "openid.OpenIDConnectDeviceAuthorizeHandler"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("ShouldPassInTheDocumentedOrder", func(t *testing.T) {
				assert.NoError(t, ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{tc.grant, tc.oidc}}))
			})

			t.Run("ShouldPassWithTheOpenIDConnectHandlerAlone", func(t *testing.T) {
				assert.NoError(t, ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{tc.oidc}}))
			})

			t.Run("ShouldPassWithTheGrantHandlerAlone", func(t *testing.T) {
				assert.NoError(t, ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{tc.grant}}))
			})

			t.Run("ShouldFailWhenTheOpenIDConnectHandlerIsRegisteredFirst", func(t *testing.T) {
				err := ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{tc.oidc, tc.grant}})

				require.ErrorIs(t, err, ErrHandlerOrder)
				assert.Contains(t, err.Error(), tc.kind)
			})
		})
	}
}

func TestValidateHandlerOrderAuthorizeEndpoint(t *testing.T) {
	explicit, hybrid := &hoauth2.AuthorizeExplicitGrantHandler{}, &openid.OpenIDConnectHybridHandler{}
	oidc, proof := &openid.OpenIDConnectExplicitHandler{}, &pkce.Handler{}

	testCases := []struct {
		name     string
		handlers oauth2.AuthorizeEndpointHandlers
		contains []string
	}{
		{name: "ShouldPassInTheDocumentedOrder", handlers: oauth2.AuthorizeEndpointHandlers{explicit, oidc, hybrid, proof}},
		{name: "ShouldPassWithTheDependentHandlersAlone", handlers: oauth2.AuthorizeEndpointHandlers{oidc, proof}},
		{name: "ShouldFailWhenTheOpenIDConnectExplicitHandlerIsRegisteredFirst", handlers: oauth2.AuthorizeEndpointHandlers{oidc, explicit}, contains: []string{"openid.OpenIDConnectExplicitHandler"}},
		{name: "ShouldFailWhenThePKCEHandlerPrecedesTheExplicitHandler", handlers: oauth2.AuthorizeEndpointHandlers{proof, explicit}, contains: []string{"pkce.Handler", "hoauth2.AuthorizeExplicitGrantHandler"}},
		{name: "ShouldFailWhenThePKCEHandlerPrecedesTheHybridHandler", handlers: oauth2.AuthorizeEndpointHandlers{explicit, proof, hybrid}, contains: []string{"pkce.Handler", "openid.OpenIDConnectHybridHandler"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{AuthorizeEndpointHandlers: tc.handlers})

			if len(tc.contains) == 0 {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)

			for _, contains := range tc.contains {
				assert.Contains(t, err.Error(), contains)
			}
		})
	}
}

func TestValidateHandlerOrderRFC8693(t *testing.T) {
	grant, access, refresh, validator := &rfc8693.TokenExchangeGrantHandler{}, &rfc8693.AccessTokenTypeHandler{}, &rfc8693.RefreshTokenTypeHandler{}, &rfc8693.ActorTokenValidationHandler{}
	id, custom, txn := &rfc8693.IDTokenTypeHandler{}, &rfc8693.CustomJWTTypeHandler{}, &rfc8693.TxnTokenTypeHandler{}

	testCases := []struct {
		name     string
		handlers oauth2.TokenEndpointHandlers
		err      string
	}{
		{name: "ShouldPassInTheDocumentedOrder", handlers: oauth2.TokenEndpointHandlers{grant, access, refresh, id, custom, validator}},
		{name: "ShouldPassWithATypeHandlerOmitted", handlers: oauth2.TokenEndpointHandlers{grant, access, validator}},
		{name: "ShouldPassWithUnrelatedHandlersInterleaved", handlers: oauth2.TokenEndpointHandlers{grant, &hoauth2.AuthorizeExplicitGrantHandler{}, access, &pkce.Handler{}, validator}},
		{name: "ShouldPassWithNoRFC8693Handlers", handlers: oauth2.TokenEndpointHandlers{&hoauth2.AuthorizeExplicitGrantHandler{}}},
		{name: "ShouldRejectTheGrantHandlerAfterATypeHandler", handlers: oauth2.TokenEndpointHandlers{access, grant, refresh, validator}, err: "rfc8693.TokenExchangeGrantHandler (RFC8693TokenExchangeGrantFactory) must be registered before"},
		{name: "ShouldRejectTheGrantHandlerAfterTheCustomJWTTypeHandler", handlers: oauth2.TokenEndpointHandlers{custom, grant, validator}, err: "must be registered before every RFC 8693 token type handler"},
		{name: "ShouldRejectAMissingGrantHandler", handlers: oauth2.TokenEndpointHandlers{access, validator}, err: "rfc8693.TokenExchangeGrantHandler (RFC8693TokenExchangeGrantFactory) must be registered with"},
		{name: "ShouldRejectTheValidationHandlerBeforeATypeHandler", handlers: oauth2.TokenEndpointHandlers{grant, validator, access}, err: "rfc8693.ActorTokenValidationHandler (RFC8693ActorTokenValidationFactory) must be registered after"},
		{name: "ShouldRejectTheValidationHandlerBeforeTheIDTokenTypeHandler", handlers: oauth2.TokenEndpointHandlers{grant, access, validator, id}, err: "must be registered after every RFC 8693 token type handler"},
		{name: "ShouldRejectAMissingValidationHandler", handlers: oauth2.TokenEndpointHandlers{grant, access}, err: "rfc8693.ActorTokenValidationHandler (RFC8693ActorTokenValidationFactory) must be registered with"},
		{name: "ShouldPassWithTheTxnTokenTypeHandlerLast", handlers: oauth2.TokenEndpointHandlers{grant, access, refresh, id, custom, txn, validator}},
		{name: "ShouldRejectTheGrantHandlerAfterTheTxnTokenTypeHandler", handlers: oauth2.TokenEndpointHandlers{txn, grant, validator}, err: "must be registered before every RFC 8693 token type handler"},
		{name: "ShouldRejectTheValidationHandlerBeforeTheTxnTokenTypeHandler", handlers: oauth2.TokenEndpointHandlers{grant, validator, txn}, err: "must be registered after every RFC 8693 token type handler"},
		{name: "ShouldRejectATypeHandlerAfterTheTxnTokenTypeHandler", handlers: oauth2.TokenEndpointHandlers{grant, txn, access, validator}, err: "rfc8693.TxnTokenTypeHandler (RFC8693TxnTokenTypeFactory) must be registered after every other RFC 8693 token type handler"},
		{name: "ShouldRejectTheCustomJWTTypeHandlerAfterTheTxnTokenTypeHandler", handlers: oauth2.TokenEndpointHandlers{grant, txn, custom, validator}, err: "must be registered after every other RFC 8693 token type handler"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: tc.handlers})

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)
			assert.Contains(t, err.Error(), tc.err)
		})
	}
}

func TestValidateHandlerOrderIDJAG(t *testing.T) {
	redeem := &idjag.RedeemHandler{}

	testCases := []struct {
		name     string
		token    oauth2.TokenEndpointHandlers
		binding  oauth2.TokenEndpointBindingHandlers
		contains string
	}{
		{name: "ShouldAcceptRedeemAfterDPoP", token: oauth2.TokenEndpointHandlers{redeem}, binding: oauth2.TokenEndpointBindingHandlers{&rfc9449.Handler{}, redeem}},
		{name: "ShouldAcceptRedeemWithoutDPoP", token: oauth2.TokenEndpointHandlers{redeem}, binding: oauth2.TokenEndpointBindingHandlers{redeem}},
		{name: "ShouldRejectRedeemBeforeDPoP", token: oauth2.TokenEndpointHandlers{redeem}, binding: oauth2.TokenEndpointBindingHandlers{redeem, &rfc9449.Handler{}}, contains: "must be registered before the idjag.RedeemHandler"},
		{name: "ShouldRejectRedeemMissingFromBinding", token: oauth2.TokenEndpointHandlers{redeem}, binding: oauth2.TokenEndpointBindingHandlers{&rfc9449.Handler{}}, contains: "must also be registered in the token endpoint binding handlers"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: tc.token, TokenEndpointBindingHandlers: tc.binding})

			if tc.contains == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)
			assert.Contains(t, err.Error(), tc.contains)
		})
	}
}

func TestValidateHandlerOrderReportsEveryFault(t *testing.T) {
	config := &oauth2.Config{
		TokenEndpointHandlers:        oauth2.TokenEndpointHandlers{&pkce.Handler{}, &hoauth2.AuthorizeExplicitGrantHandler{}},
		TokenEndpointBindingHandlers: oauth2.TokenEndpointBindingHandlers{&oidckb.Handler{}, &rfc9449.Handler{}},
	}

	err := ValidateHandlerOrder(config)

	require.ErrorIs(t, err, ErrHandlerOrder)
	assert.Contains(t, err.Error(), "pkce.Handler")
	assert.Contains(t, err.Error(), "oidckb.Handler")
}

func TestComposeAllEnabledPassesValidateHandlerOrder(t *testing.T) {
	config := &oauth2.Config{
		OIDCKeyBindingEnabled:                 true,
		DPoPEnabled:                           true,
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}

	_ = ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	assert.NoError(t, ValidateHandlerOrder(config))
}

func TestValidateHandlerOrderRFC8628UserAuthorize(t *testing.T) {
	connect, device, binding := &openid.OpenIDConnectDeviceAuthorizeHandler{}, &rfc8628.UserAuthorizeHandler{}, &oidckb.UserAuthorizeHandler{}

	testCases := []struct {
		name     string
		handlers oauth2.RFC8628UserAuthorizeEndpointHandlers
		err      string
	}{
		{
			name:     "ShouldPassOpenIDConnectBeforeDevice",
			handlers: oauth2.RFC8628UserAuthorizeEndpointHandlers{connect, device},
		},
		{
			name:     "ShouldPassDeviceAlone",
			handlers: oauth2.RFC8628UserAuthorizeEndpointHandlers{device},
		},
		{
			name:     "ShouldPassOpenIDConnectAlone",
			handlers: oauth2.RFC8628UserAuthorizeEndpointHandlers{connect},
		},
		{
			name:     "ShouldPassKeyBindingBeforeOpenIDConnect",
			handlers: oauth2.RFC8628UserAuthorizeEndpointHandlers{binding, connect, device},
		},
		{
			name:     "ShouldFailKeyBindingAfterOpenIDConnect",
			handlers: oauth2.RFC8628UserAuthorizeEndpointHandlers{connect, binding, device},
			err:      "the oidckb.UserAuthorizeHandler (OpenIDConnectKeyBindingUserAuthorizeFactory) must be registered before the openid.OpenIDConnectDeviceAuthorizeHandler (OpenIDConnectDeviceAuthorizeFactory)",
		},
		{
			name:     "ShouldFailOpenIDConnectAfterDevice",
			handlers: oauth2.RFC8628UserAuthorizeEndpointHandlers{device, connect},
			err:      "the openid.OpenIDConnectDeviceAuthorizeHandler (OpenIDConnectDeviceAuthorizeFactory) must be registered before the rfc8628.UserAuthorizeHandler (RFC8628UserAuthorizeFactory)",
		},
		{
			name:     "ShouldFailOpenIDConnectAfterAnEarlierDevice",
			handlers: oauth2.RFC8628UserAuthorizeEndpointHandlers{connect, device, connect},
			err:      "the openid.OpenIDConnectDeviceAuthorizeHandler (OpenIDConnectDeviceAuthorizeFactory) must be registered before the rfc8628.UserAuthorizeHandler (RFC8628UserAuthorizeFactory)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{RFC8628UserAuthorizeEndpointHandlers: tc.handlers})

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)
			assert.Contains(t, err.Error(), tc.err)
		})
	}
}

func TestComposeAllEnabledDeviceFlowRecordsTheDecisionLast(t *testing.T) {
	for _, st := range deviceOrderTestStores {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldLeaveTheDeviceCodeUndecidedWhenTheNonceIsReused", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				first := newDeviceOrderTestGrant(t, provider, deviceOrderTestNonce)

				require.NoError(t, first.approve(t, provider))

				response, err := first.poll(t, provider)

				require.NoError(t, err)
				assert.NotEmpty(t, response.GetExtra(consts.AccessResponseIDToken))

				second := newDeviceOrderTestGrant(t, provider, deviceOrderTestNonce)

				assert.Equal(t, "invalid_request", deviceOrderTestErrorCode(second.approve(t, provider)))

				_, err = second.poll(t, provider)

				assert.Equal(t, "authorization_pending", deviceOrderTestErrorCode(err))
			})

			t.Run("ShouldLeaveTheDeviceCodeUndecidedWhenTheOpenIDConnectSessionIsNotStored", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(st.failing(store), false)

				grant := newDeviceOrderTestGrant(t, provider, deviceOrderTestNonce)

				assert.Equal(t, "server_error", deviceOrderTestErrorCode(grant.approve(t, provider)))

				_, err := grant.poll(t, provider)

				assert.Equal(t, "authorization_pending", deviceOrderTestErrorCode(err))
			})

			t.Run("ShouldNotIssueTokensWithoutAnIDTokenWhenTheOpenIDConnectSessionIsMissing", func(t *testing.T) {
				store, memory := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				grant := newDeviceOrderTestGrant(t, provider, deviceOrderTestNonce)

				require.NoError(t, grant.approve(t, provider))

				clear(memory.IDSessions)

				response, err := grant.poll(t, provider)

				assert.Nil(t, response)
				assert.Equal(t, "server_error", deviceOrderTestErrorCode(err))
			})

			t.Run("ShouldNotIssueAnIDTokenForASubjectTheDecisionWasNotRecordedFor", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, true)

				grant := newDeviceOrderTestGrant(t, provider, "")

				winner, loser := grant.present(t, provider, deviceOrderTestSubject), grant.present(t, provider, "mallory")

				require.NoError(t, grant.decide(provider, winner, deviceOrderTestSubject))
				assert.Equal(t, "invalid_grant", deviceOrderTestErrorCode(grant.decide(provider, loser, "mallory")))

				response, err := grant.poll(t, provider)

				assert.Nil(t, response)
				assert.Equal(t, "server_error", deviceOrderTestErrorCode(err))
			})

			t.Run("ShouldNotIssueAnIDTokenFromTheSessionOfAnApprovalWhichLost", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				grant := newDeviceOrderTestGrant(t, provider, "")

				winner, loser := grant.present(t, provider, deviceOrderTestSubject), grant.present(t, provider, deviceOrderTestSubject)

				winnerSession, loserSession := newDeviceOrderTestSession(deviceOrderTestSubject), newDeviceOrderTestSession(deviceOrderTestSubject)

				winnerSession.Claims.AuthenticationContextClassReference = "winner"
				loserSession.Claims.AuthenticationContextClassReference = "loser"

				require.NoError(t, grant.decideWithSession(provider, winner, winnerSession))
				assert.Equal(t, "invalid_grant", deviceOrderTestErrorCode(grant.decideWithSession(provider, loser, loserSession)))

				response, err := grant.poll(t, provider)

				assert.Nil(t, response)
				assert.Equal(t, "server_error", deviceOrderTestErrorCode(err))

				_, err = grant.poll(t, provider)

				assert.Equal(t, "invalid_grant", deviceOrderTestErrorCode(err))
			})

			t.Run("ShouldIssueAnIDTokenFromTheSessionOfTheApprovalWhichWon", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				grant := newDeviceOrderTestGrant(t, provider, deviceOrderTestNonce)

				session := newDeviceOrderTestSession(deviceOrderTestSubject)

				session.Claims.AuthenticationContextClassReference = "winner"

				require.NoError(t, grant.decideWithSession(provider, grant.present(t, provider, deviceOrderTestSubject), session))

				response, err := grant.poll(t, provider)

				require.NoError(t, err)
				assert.Equal(t, "winner", deviceOrderTestIDTokenClaims(t, response)[consts.ClaimAuthenticationContextClassReference])
			})

			t.Run("ShouldRefuseAnApprovalWhoseSessionDoesNotIdentifyTheEndUser", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				grant := newDeviceOrderTestGrant(t, provider, "")

				for name, session := range map[string]oauth2.Session{
					"nil":     nil,
					"missing": newDeviceOrderTestSessionWithBinding(deviceOrderTestSubject, ""),
					"sub":     &oauth2.DefaultSession{Subject: deviceOrderTestSubject},
				} {
					request := grant.present(t, provider, deviceOrderTestSubject)

					request.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

					_, err := provider.NewRFC8628UserAuthorizeResponse(context.Background(), request, session)

					assert.ErrorIs(t, err, oauth2.ErrUserCodeClaimed, name)
					assert.Equal(t, "invalid_grant", deviceOrderTestErrorCode(err), name)
				}

				_, err := grant.poll(t, provider)

				assert.Equal(t, "authorization_pending", deviceOrderTestErrorCode(err))
			})

			t.Run("ShouldBindTheUserCodeToTheEndUserRatherThanTheSubject", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				grant := newDeviceOrderTestGrant(t, provider, "")

				request, err := provider.NewRFC8628UserAuthorizeRequest(context.Background(), newDeviceOrderTestRequest(url.Values{consts.FormParameterUserCode: {grant.userCode}}), newDeviceOrderTestSessionWithBinding("", "end-user"))

				require.NoError(t, err)

				require.NoError(t, grant.decideWithSession(provider, request, newDeviceOrderTestSessionWithBinding("pairwise-subject", "end-user")))

				response, err := grant.poll(t, provider)

				require.NoError(t, err)
				assert.Equal(t, "pairwise-subject", deviceOrderTestIDTokenClaims(t, response)[consts.ClaimSubject])
			})

			t.Run("ShouldRefuseAPresentationWhoseSessionDoesNotIdentifyTheEndUser", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				grant := newDeviceOrderTestGrant(t, provider, "")

				_, err := provider.NewRFC8628UserAuthorizeRequest(context.Background(), newDeviceOrderTestRequest(url.Values{consts.FormParameterUserCode: {grant.userCode}}), &oauth2.DefaultSession{Subject: deviceOrderTestSubject})

				assert.Equal(t, "server_error", deviceOrderTestErrorCode(err))
			})

			t.Run("ShouldRecordADenialWhoseSessionIdentifiesAnotherEndUser", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				grant := newDeviceOrderTestGrant(t, provider, "")

				request := grant.present(t, provider, deviceOrderTestSubject)

				request.SetStatus(oauth2.DeviceAuthorizeStatusDenied)

				_, err := provider.NewRFC8628UserAuthorizeResponse(context.Background(), request, newDeviceOrderTestSession("mallory"))

				require.NoError(t, err)

				_, err = grant.poll(t, provider)

				assert.Equal(t, "access_denied", deviceOrderTestErrorCode(err))
			})

			t.Run("ShouldAcceptAnApprovalByAnotherEndUserWhenTheBindingIsDisabled", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, true)

				grant := newDeviceOrderTestGrant(t, provider, "")

				require.NoError(t, grant.decide(provider, grant.present(t, provider, deviceOrderTestSubject), "mallory"))

				response, err := grant.poll(t, provider)

				require.NoError(t, err)
				assert.Equal(t, "mallory", deviceOrderTestIDTokenClaims(t, response)[consts.ClaimSubject])
			})

			t.Run("ShouldRefuseAnApprovalForASubjectTheUserCodeIsNotBoundTo", func(t *testing.T) {
				store, _ := st.new()
				provider := newDeviceOrderTestProvider(store, false)

				grant := newDeviceOrderTestGrant(t, provider, deviceOrderTestNonce)

				request := grant.present(t, provider, deviceOrderTestSubject)

				assert.Equal(t, "invalid_grant", deviceOrderTestErrorCode(grant.decide(provider, request, "mallory")))

				_, err := grant.poll(t, provider)

				assert.Equal(t, "authorization_pending", deviceOrderTestErrorCode(err))

				require.NoError(t, grant.approve(t, provider))

				response, err := grant.poll(t, provider)

				require.NoError(t, err)
				assert.NotEmpty(t, response.GetExtra(consts.AccessResponseIDToken))
			})
		})
	}
}

func TestComposeAllEnabledDeviceFlowRefusesAnOpenIDConnectSessionWithoutTheApprovalID(t *testing.T) {
	store := &deviceOrderTestSerializingStore{HydratingMemoryStore: storage.NewHydratingMemoryStore(), sessions: map[string][]byte{}, strip: true}

	store.Clients[deviceOrderTestClientID] = newDeviceOrderTestClient()

	provider := newDeviceOrderTestProvider(store, false)

	grant := newDeviceOrderTestGrant(t, provider, "")

	require.NoError(t, grant.approve(t, provider))

	response, err := grant.poll(t, provider)

	assert.Nil(t, response)
	assert.Equal(t, "server_error", deviceOrderTestErrorCode(err))
}

func TestComposePanicsWhenThePKCEFactoryPrecedesTheExplicitFactory(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	assert.PanicsWithError(t, "oauth2: handlers are registered in an order which does not work: the pkce.Handler (OAuth2PKCEFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory) in the authorize endpoint handlers, as it records the PKCE request session under the authorization code the hoauth2.AuthorizeExplicitGrantHandler issues\noauth2: handlers are registered in an order which does not work: the pkce.Handler (OAuth2PKCEFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory), as it removes the PKCE request session which must outlive the authorization code", func() {
		_ = Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), OAuth2PKCEFactory, OAuth2AuthorizeExplicitFactory)
	})
}

func TestComposePanicsWhenTheRFC8693GrantFactoryFollowsATypeFactory(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	assert.PanicsWithError(t, "oauth2: handlers are registered in an order which does not work: the rfc8693.TokenExchangeGrantHandler (RFC8693TokenExchangeGrantFactory) must be registered before every RFC 8693 token type handler, as it writes the 'act' claim onto the session they issue the token from", func() {
		_ = Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), RFC8693AccessTokenTypeFactory, RFC8693TokenExchangeGrantFactory, RFC8693ActorTokenValidationFactory)
	})
}

const (
	deviceOrderTestClientID = "device"
	deviceOrderTestSubject  = "peter"
	deviceOrderTestNonce    = "1234567890abcdef1234567890abcdef"
)

var deviceOrderTestStores = []struct {
	name    string
	new     func() (store any, memory *storage.MemoryStore)
	failing func(store any) any
}{
	{
		name: "MemoryStore",
		new: func() (any, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			store.Clients[deviceOrderTestClientID] = newDeviceOrderTestClient()

			return store, store
		},
		failing: func(store any) any {
			return &deviceOrderTestFailingMemoryStore{MemoryStore: store.(*storage.MemoryStore)}
		},
	},
	{
		name: "HydratingMemoryStore",
		new: func() (any, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			store.Clients[deviceOrderTestClientID] = newDeviceOrderTestClient()

			return store, store.MemoryStore
		},
		failing: func(store any) any {
			return &deviceOrderTestFailingHydratingMemoryStore{HydratingMemoryStore: store.(*storage.HydratingMemoryStore)}
		},
	},
	{
		name: "SerializingStore",
		new: func() (any, *storage.MemoryStore) {
			store := &deviceOrderTestSerializingStore{HydratingMemoryStore: storage.NewHydratingMemoryStore(), sessions: map[string][]byte{}}

			store.Clients[deviceOrderTestClientID] = newDeviceOrderTestClient()

			return store, store.MemoryStore
		},
		failing: func(store any) any {
			return &deviceOrderTestFailingSerializingStore{deviceOrderTestSerializingStore: store.(*deviceOrderTestSerializingStore)}
		},
	},
}

type deviceOrderTestSerializingStore struct {
	*storage.HydratingMemoryStore

	mu       sync.Mutex
	sessions map[string][]byte
	strip    bool
}

func (s *deviceOrderTestSerializingStore) CreateOpenIDConnectSession(ctx context.Context, signature string, request oauth2.Requester) (err error) {
	var data []byte

	if data, err = json.Marshal(request.GetSession()); err != nil {
		return err
	}

	if s.strip {
		values := map[string]any{}

		if err = json.Unmarshal(data, &values); err != nil {
			return err
		}

		delete(values, "approval_id")

		if data, err = json.Marshal(values); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.sessions[signature] = data
	s.mu.Unlock()

	return s.HydratingMemoryStore.CreateOpenIDConnectSession(ctx, signature, request)
}

func (s *deviceOrderTestSerializingStore) GetOpenIDConnectSession(ctx context.Context, signature string, request oauth2.Requester) (oauth2.Requester, error) {
	stored, err := s.HydratingMemoryStore.GetOpenIDConnectSession(ctx, signature, request)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	data := s.sessions[signature]
	s.mu.Unlock()

	if session, ok := request.GetSession().(openid.ApprovalSession); ok {
		session.SetApprovalID("")
	}

	if err = json.Unmarshal(data, request.GetSession()); err != nil {
		return nil, err
	}

	restored := *stored.(*oauth2.Request)
	restored.Session = request.GetSession()

	return &restored, nil
}

type deviceOrderTestFailingSerializingStore struct {
	*deviceOrderTestSerializingStore
}

func (s *deviceOrderTestFailingSerializingStore) CreateOpenIDConnectSession(_ context.Context, _ string, _ oauth2.Requester) error {
	return errors.New("unavailable")
}

type deviceOrderTestFailingMemoryStore struct {
	*storage.MemoryStore
}

func (s *deviceOrderTestFailingMemoryStore) CreateOpenIDConnectSession(_ context.Context, _ string, _ oauth2.Requester) error {
	return errors.New("unavailable")
}

type deviceOrderTestFailingHydratingMemoryStore struct {
	*storage.HydratingMemoryStore
}

func (s *deviceOrderTestFailingHydratingMemoryStore) CreateOpenIDConnectSession(_ context.Context, _ string, _ oauth2.Requester) error {
	return errors.New("unavailable")
}

type deviceOrderTestGrant struct {
	deviceCode, userCode string
}

func newDeviceOrderTestProvider(store any, disableSubjectBinding bool) (provider oauth2.Provider) {
	config := &oauth2.Config{
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC8628UserVerificationURL:            "https://www.authelia.com/device",
		RFC8628TokenPollingInterval:           time.Nanosecond,
		RFC8628DisableUserCodeSubjectBinding:  disableSubjectBinding,
	}

	return ComposeAllEnabled(config, store, gen.MustRSAKey())
}

func deviceOrderTestErrorCode(err error) (code string) {
	if err == nil {
		return ""
	}

	return oauth2.ErrorToRFC6749Error(err).ErrorField
}

func newDeviceOrderTestClient() (client oauth2.Client) {
	return &oauth2.DefaultClient{
		ID:         deviceOrderTestClientID,
		Public:     true,
		GrantTypes: []string{consts.GrantTypeOAuthDeviceCode},
		Scopes:     []string{consts.ScopeOpenID},
	}
}

func newDeviceOrderTestSession(subject string) (session *openid.DefaultSession) {
	return newDeviceOrderTestSessionWithBinding(subject, subject)
}

func newDeviceOrderTestSessionWithBinding(subject, binding string) (session *openid.DefaultSession) {
	return &openid.DefaultSession{
		Subject:                subject,
		UserCodeBindingSubject: binding,
		Claims:                 &jwt.IDTokenClaims{Subject: subject},
		Headers:                &jwt.Headers{},
	}
}

func deviceOrderTestIDTokenClaims(t *testing.T, response oauth2.AccessResponder) (claims map[string]any) {
	t.Helper()

	claims = map[string]any{}

	_, err := jwt.UnsafeParseSignedAny(response.GetExtra(consts.AccessResponseIDToken).(string), &claims)

	require.NoError(t, err)

	return claims
}

func newDeviceOrderTestRequest(form url.Values) (r *http.Request) {
	r = httptest.NewRequest(http.MethodPost, "https://www.authelia.com/", strings.NewReader(form.Encode()))

	r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")

	return r
}

func newDeviceOrderTestGrant(t *testing.T, provider oauth2.Provider, nonce string) (grant deviceOrderTestGrant) {
	t.Helper()

	form := url.Values{consts.FormParameterClientID: {deviceOrderTestClientID}, consts.FormParameterScope: {consts.ScopeOpenID}}

	if nonce != "" {
		form.Set(consts.FormParameterNonce, nonce)
	}

	ctx := context.Background()

	request, err := provider.NewRFC862DeviceAuthorizeRequest(ctx, newDeviceOrderTestRequest(form))

	require.NoError(t, err)

	response, err := provider.NewRFC862DeviceAuthorizeResponse(ctx, request, newDeviceOrderTestSession(""))

	require.NoError(t, err)

	return deviceOrderTestGrant{deviceCode: response.GetDeviceCode(), userCode: response.GetUserCode()}
}

func (g deviceOrderTestGrant) present(t *testing.T, provider oauth2.Provider, subject string) (request oauth2.DeviceAuthorizeRequester) {
	t.Helper()

	request, err := provider.NewRFC8628UserAuthorizeRequest(context.Background(), newDeviceOrderTestRequest(url.Values{consts.FormParameterUserCode: {g.userCode}}), newDeviceOrderTestSession(subject))

	require.NoError(t, err)

	return request
}

func (g deviceOrderTestGrant) decide(provider oauth2.Provider, request oauth2.DeviceAuthorizeRequester, subject string) (err error) {
	return g.decideWithSession(provider, request, newDeviceOrderTestSession(subject))
}

func (g deviceOrderTestGrant) decideWithSession(provider oauth2.Provider, request oauth2.DeviceAuthorizeRequester, session *openid.DefaultSession) (err error) {
	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}

	request.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

	_, err = provider.NewRFC8628UserAuthorizeResponse(context.Background(), request, session)

	return err
}

func (g deviceOrderTestGrant) approve(t *testing.T, provider oauth2.Provider) (err error) {
	t.Helper()

	return g.decide(provider, g.present(t, provider, deviceOrderTestSubject), deviceOrderTestSubject)
}

func (g deviceOrderTestGrant) poll(t *testing.T, provider oauth2.Provider) (response oauth2.AccessResponder, err error) {
	t.Helper()

	ctx := context.Background()

	form := url.Values{
		consts.FormParameterClientID:   {deviceOrderTestClientID},
		consts.FormParameterGrantType:  {consts.GrantTypeOAuthDeviceCode},
		consts.FormParameterDeviceCode: {g.deviceCode},
	}

	request, err := provider.NewAccessRequest(ctx, newDeviceOrderTestRequest(form), newDeviceOrderTestSession(""))
	if err != nil {
		return nil, err
	}

	return provider.NewAccessResponse(ctx, request)
}
