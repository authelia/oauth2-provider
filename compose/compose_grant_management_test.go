// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	"authelia.com/provider/oauth2/handler/grantmgmt"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestGrantManagementFactory(t *testing.T) {
	t.Run("ShouldProduceTheHandler", func(t *testing.T) {
		config := &oauth2.Config{}
		store := storage.NewMemoryStore()

		handler, ok := GrantManagementFactory(config, store, nil).(*grantmgmt.Handler)
		require.True(t, ok)

		assert.Same(t, config, handler.Config)
		assert.Same(t, store, handler.Storage)
	})

	t.Run("ShouldPanicWithoutGrantManagementStorage", func(t *testing.T) {
		assert.PanicsWithValue(t, "oauth2: GrantManagementFactory requires a storage implementing oauth2.GrantManagementStorage", func() {
			GrantManagementFactory(&oauth2.Config{}, struct{}{}, nil)
		})
	})

	t.Run("ShouldRegisterTheHandlerInEveryListItImplements", func(t *testing.T) {
		_, _, config := newGrantManagementProvider(t, true)

		assert.True(t, grantManagementRegistered(config.AuthorizeEndpointBindingHandlers))
		assert.True(t, grantManagementRegistered(config.RFC8628DeviceAuthorizeEndpointBindingHandlers))
		assert.True(t, grantManagementRegistered(config.BackChannelAuthenticationEndpointBindingHandlers))
		assert.True(t, grantManagementRegistered(config.BackChannelAuthenticationDecisionHandlers))
		assert.True(t, grantManagementRegistered(config.TokenEndpointBindingHandlers))
	})

	t.Run("ShouldNotBePartOfComposeAllEnabled", func(t *testing.T) {
		config := &oauth2.Config{
			GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
			RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		}

		_ = ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

		assert.False(t, grantManagementRegistered(config.AuthorizeEndpointBindingHandlers))
		assert.False(t, grantManagementRegistered(config.RFC8628DeviceAuthorizeEndpointBindingHandlers))
		assert.False(t, grantManagementRegistered(config.BackChannelAuthenticationEndpointBindingHandlers))
		assert.False(t, grantManagementRegistered(config.BackChannelAuthenticationDecisionHandlers))
		assert.False(t, grantManagementRegistered(config.TokenEndpointBindingHandlers))
	})

	t.Run("ShouldPrecedeTheCIBADecisionHandler", func(t *testing.T) {
		handler, decision := &grantmgmt.Handler{}, &ciba.DecisionHandler{}

		assert.NoError(t, ValidateHandlerOrder(&oauth2.Config{BackChannelAuthenticationDecisionHandlers: oauth2.BackChannelAuthenticationDecisionHandlers{handler, decision}}))
		assert.NoError(t, ValidateHandlerOrder(&oauth2.Config{BackChannelAuthenticationDecisionHandlers: oauth2.BackChannelAuthenticationDecisionHandlers{handler}}))

		err := ValidateHandlerOrder(&oauth2.Config{BackChannelAuthenticationDecisionHandlers: oauth2.BackChannelAuthenticationDecisionHandlers{decision, handler}})

		require.ErrorIs(t, err, ErrHandlerOrder)
		assert.EqualError(t, err, "oauth2: handlers are registered in an order which does not work: the grantmgmt.Handler (GrantManagementFactory) must be registered before the ciba.DecisionHandler (CIBADecisionFactory) in the backchannel authentication decision handlers, as it grants the permissions of a merged grant on the request the ciba.DecisionHandler persists")

		config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

		assert.Panics(t, func() {
			_ = Compose(config, storage.NewMemoryStore(), newCIBATestStrategy(config), append(CIBAFactories(), GrantManagementFactory)...)
		})
	})
}

func TestGrantCreateIssuesGrantID(t *testing.T) {
	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			flow := newGrantManagementFlow(t, sc.new)

			id, code := flow.authorize(url.Values{
				consts.FormParameterScope:                 []string{"read offline_access"},
				consts.FormParameterGrantManagementAction: []string{"create"},
			}, "read", "offline_access")

			assert.Empty(t, flow.memory.Grants)

			before := time.Now().UTC()

			response := flow.redeem(code)

			grantID, ok := response.GetExtra("grant_id").(string)
			require.True(t, ok)

			decoded, err := base64.RawURLEncoding.DecodeString(grantID)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(decoded), 16)

			grant, err := flow.memory.GetGrant(flow.ctx, grantID)
			require.NoError(t, err)

			assert.Equal(t, grantID, grant.ID)
			assert.Equal(t, grantManagementClientID, grant.ClientID)
			assert.Equal(t, "peter", grant.Subject)
			assert.Equal(t, oauth2.Arguments{"read", "offline_access"}, grant.Permissions.ScopeValues())
			assert.Equal(t, []string{id}, grant.RequestIDs)
			assert.Equal(t, "client", grant.UpdatedBy)
			assert.False(t, grant.CreatedAt.Before(before))
			assert.Equal(t, grant.CreatedAt, grant.UpdatedAt)

			assert.Len(t, flow.memory.Grants, 1)
		})
	}
}

func TestGrantIDEchoedOnRefresh(t *testing.T) {
	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			flow := newGrantManagementFlow(t, sc.new)

			id, code := flow.authorize(url.Values{
				consts.FormParameterScope:                 []string{"read offline_access"},
				consts.FormParameterGrantManagementAction: []string{"create"},
			}, "read", "offline_access")

			issued := flow.redeem(code)

			grantID, ok := issued.GetExtra("grant_id").(string)
			require.True(t, ok)
			require.NotEmpty(t, grantID)

			refreshed, err := flow.refresh(grantManagementRefreshToken(t, issued))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.Equal(t, grantID, refreshed.GetExtra("grant_id"))

			again, err := flow.refresh(grantManagementRefreshToken(t, refreshed))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.Equal(t, grantID, again.GetExtra("grant_id"))

			grant, err := flow.memory.GetGrant(flow.ctx, grantID)
			require.NoError(t, err)

			assert.Equal(t, []string{id}, grant.RequestIDs)
			assert.Equal(t, grant.CreatedAt, grant.UpdatedAt)
		})
	}
}

func TestGrantMergeRevokesPriorRefreshTokens(t *testing.T) {
	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			flow := newGrantManagementFlow(t, sc.new)

			first, code := flow.authorize(url.Values{
				consts.FormParameterScope:                 []string{"read offline_access"},
				consts.FormParameterGrantManagementAction: []string{"create"},
			}, "read", "offline_access")

			created := flow.redeem(code)

			grantID, ok := created.GetExtra("grant_id").(string)
			require.True(t, ok)

			second, code := flow.authorize(url.Values{
				consts.FormParameterScope:                 []string{"write offline_access"},
				consts.FormParameterGrantManagementAction: []string{"merge"},
				consts.FormParameterGrantID:               []string{grantID},
			}, "write", "offline_access")

			require.NotEqual(t, first, second)

			merged := flow.redeem(code)

			assert.Equal(t, grantID, merged.GetExtra("grant_id"))

			grant, err := flow.memory.GetGrant(flow.ctx, grantID)
			require.NoError(t, err)

			assert.Equal(t, []string{first, second}, grant.RequestIDs)
			assert.ElementsMatch(t, []string{"read", "write", "offline_access"}, grant.Permissions.ScopeValues())
			assert.Equal(t, "client", grant.UpdatedBy)
			assert.False(t, grant.UpdatedAt.Before(grant.CreatedAt))

			assert.True(t, flow.active(created.GetAccessToken()))
			assert.True(t, flow.active(merged.GetAccessToken()))

			_, err = flow.refresh(grantManagementRefreshToken(t, created))
			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

			refreshed, err := flow.refresh(grantManagementRefreshToken(t, merged))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.Equal(t, grantID, refreshed.GetExtra("grant_id"))
			assert.True(t, flow.active(refreshed.GetAccessToken()))
		})
	}
}

func TestGrantMergeDoesNotGrantOpenIDWhenNotRequested(t *testing.T) {
	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			ctx := context.Background()

			store, memory := sc.new()

			provider := newGrantManagementFlowProvider(t, store, memory,
				OAuth2AuthorizeExplicitFactory,
				OpenIDConnectExplicitFactory,
				OAuth2RefreshTokenGrantFactory,
				OAuth2TokenIntrospectionFactory,
				GrantManagementFactory,
			)

			issue := func(form url.Values, scopes ...string) oauth2.AccessResponder {
				t.Helper()

				requester, err := provider.NewAuthorizeRequest(ctx, newGrantManagementAuthorizeRequest(form))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				for _, scope := range scopes {
					requester.GrantScope(scope)
				}

				session := openid.NewDefaultSession()
				session.Subject, session.Claims.Subject = "peter", "peter"

				responder, err := provider.NewAuthorizeResponse(ctx, requester, session)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				access, err := provider.NewAccessRequest(ctx, newGrantManagementClientRequest("https://as.example.com/token", url.Values{
					consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
					consts.FormParameterAuthorizationCode: []string{responder.GetCode()},
					consts.FormParameterRedirectURI:       []string{grantManagementRedirectURI},
				}), openid.NewDefaultSession())
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				response, err := provider.NewAccessResponse(ctx, access)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return response
			}

			created := issue(url.Values{
				consts.FormParameterScope:                 []string{"openid read offline_access"},
				consts.FormParameterGrantManagementAction: []string{"create"},
			}, consts.ScopeOpenID, "read", "offline_access")

			require.NotEmpty(t, created.GetExtra(consts.AccessResponseIDToken))

			id, ok := created.GetExtra(consts.AccessResponseGrantID).(string)
			require.True(t, ok)

			// The merged authorization does not request 'openid', so it is not an authentication request (Section 5.2).
			merged := issue(url.Values{
				consts.FormParameterScope:                 []string{"write"},
				consts.FormParameterGrantManagementAction: []string{"merge"},
				consts.FormParameterGrantID:               []string{id},
			}, "write")

			assert.Nil(t, merged.GetExtra(consts.AccessResponseIDToken))
			assert.Equal(t, id, merged.GetExtra(consts.AccessResponseGrantID))

			_, introspected, err := provider.IntrospectToken(ctx, merged.GetAccessToken(), oauth2.AccessToken, openid.NewDefaultSession())
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.ElementsMatch(t, []string{"write", "read", "offline_access"}, introspected.GetGrantedScopes())

			grant, err := memory.GetGrant(ctx, id)
			require.NoError(t, err)

			assert.ElementsMatch(t, []string{consts.ScopeOpenID, "read", "write", "offline_access"}, grant.Permissions.ScopeValues())
		})
	}
}

func TestGrantReplaceRevokesPriorTokens(t *testing.T) {
	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			flow := newGrantManagementFlow(t, sc.new)

			first, code := flow.authorize(url.Values{
				consts.FormParameterScope:                 []string{"read offline_access"},
				consts.FormParameterGrantManagementAction: []string{"create"},
			}, "read", "offline_access")

			created := flow.redeem(code)

			grantID, ok := created.GetExtra("grant_id").(string)
			require.True(t, ok)

			require.True(t, flow.active(created.GetAccessToken()))

			second, code := flow.authorize(url.Values{
				consts.FormParameterScope:                 []string{"write offline_access"},
				consts.FormParameterGrantManagementAction: []string{"replace"},
				consts.FormParameterGrantID:               []string{grantID},
			}, "write", "offline_access")

			require.NotEqual(t, first, second)

			require.True(t, flow.active(created.GetAccessToken()))

			replaced := flow.redeem(code)

			assert.Equal(t, grantID, replaced.GetExtra("grant_id"))

			grant, err := flow.memory.GetGrant(flow.ctx, grantID)
			require.NoError(t, err)

			assert.Equal(t, []string{second}, grant.RequestIDs)
			assert.Equal(t, oauth2.Arguments{"write", "offline_access"}, grant.Permissions.ScopeValues())
			assert.Equal(t, "client", grant.UpdatedBy)

			assert.False(t, flow.active(created.GetAccessToken()))
			assert.True(t, flow.active(replaced.GetAccessToken()))

			_, err = flow.refresh(grantManagementRefreshToken(t, created))
			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

			_, err = flow.refresh(grantManagementRefreshToken(t, replaced))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestGrantDeletedBeforeTokenRequest(t *testing.T) {
	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			flow := newGrantManagementFlow(t, sc.new)

			require.NoError(t, flow.memory.CreateGrant(flow.ctx, &oauth2.Grant{
				ID:          "seeded",
				ClientID:    grantManagementClientID,
				Subject:     "peter",
				Permissions: oauth2.GrantPermissions{Scopes: []oauth2.GrantScope{{Scope: "read"}}},
			}))

			_, code := flow.authorize(url.Values{
				consts.FormParameterScope:                 []string{"write offline_access"},
				consts.FormParameterGrantManagementAction: []string{"merge"},
				consts.FormParameterGrantID:               []string{"seeded"},
			}, "write", "offline_access")

			_, derr := flow.memory.DeleteGrant(flow.ctx, "seeded")

			require.NoError(t, derr)

			_, err := flow.provider.NewAccessRequest(flow.ctx, newGrantManagementClientRequest("https://as.example.com/token", url.Values{
				consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
				consts.FormParameterAuthorizationCode: []string{code},
				consts.FormParameterRedirectURI:       []string{grantManagementRedirectURI},
			}), &oauth2.DefaultSession{})

			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
			assert.Equal(t, "invalid_grant", oauth2.ErrorToRFC6749Error(err).ErrorField)

			assert.Empty(t, flow.memory.AccessTokens)
			assert.Empty(t, flow.memory.RefreshTokens)
			assert.Empty(t, flow.memory.Grants)
		})
	}
}

func TestGrantNoActionUnchanged(t *testing.T) {
	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			flow := newGrantManagementFlow(t, sc.new)

			_, code := flow.authorize(url.Values{
				consts.FormParameterScope: []string{"read offline_access"},
			}, "read", "offline_access")

			issued := flow.redeem(code)

			assert.Nil(t, issued.GetExtra("grant_id"))
			assert.NotContains(t, issued.ToMap(), "grant_id")
			assert.Empty(t, flow.memory.Grants)

			refreshed, err := flow.refresh(grantManagementRefreshToken(t, issued))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.NotContains(t, refreshed.ToMap(), "grant_id")
			assert.Empty(t, flow.memory.Grants)
		})
	}
}

func TestGrantDisabledAfterAuthorization(t *testing.T) {
	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			flow := newGrantManagementFlow(t, sc.new)

			_, code := flow.authorize(url.Values{
				consts.FormParameterScope:                 []string{"read offline_access"},
				consts.FormParameterGrantManagementAction: []string{"create"},
			}, "read", "offline_access")

			config, ok := flow.provider.(*oauth2.Fosite).Config.(*oauth2.Config)
			require.True(t, ok)

			config.GrantManagement = nil

			issued := flow.redeem(code)

			assert.NotContains(t, issued.ToMap(), "grant_id")
			assert.Empty(t, flow.memory.Grants)
		})
	}
}

func TestGrantUnchangedWhenTheTokenRequestIsRejected(t *testing.T) {
	rejections := []struct {
		name   string
		err    error
		reject func(config *oauth2.Config) (restore func())
	}{
		{
			name: "ShouldNotWriteWhenALaterBindingHandlerRejects", err: oauth2.ErrInvalidDPoPProof,
			reject: func(config *oauth2.Config) (restore func()) {
				handlers := config.TokenEndpointBindingHandlers

				config.TokenEndpointBindingHandlers = append(slices.Clone(handlers), &grantManagementRejectingBinder{err: oauth2.ErrInvalidDPoPProof})

				return func() { config.TokenEndpointBindingHandlers = handlers }
			},
		},
		{
			name: "ShouldNotWriteWhenTheSenderConstraintCheckRejects", err: oauth2.ErrInvalidRequest,
			reject: func(config *oauth2.Config) (restore func()) {
				config.EnforceSenderConstrainedAccessTokens = true

				return func() { config.EnforceSenderConstrainedAccessTokens = false }
			},
		},
	}

	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, rc := range rejections {
				t.Run(rc.name, func(t *testing.T) {
					for _, action := range []string{"create", "merge", "replace"} {
						t.Run(action, func(t *testing.T) {
							flow := newGrantManagementFlow(t, sc.new)

							config, ok := flow.provider.(*oauth2.Fosite).Config.(*oauth2.Config)
							require.True(t, ok)

							require.IsType(t, &grantmgmt.Handler{}, config.TokenEndpointBindingHandlers[len(config.TokenEndpointBindingHandlers)-1])

							form := url.Values{
								consts.FormParameterScope:                 []string{"write offline_access"},
								consts.FormParameterGrantManagementAction: []string{action},
							}

							var (
								created oauth2.AccessResponder
								before  *oauth2.Grant
								grantID string
								err     error
							)

							if action != "create" {
								_, code := flow.authorize(url.Values{
									consts.FormParameterScope:                 []string{"read offline_access"},
									consts.FormParameterGrantManagementAction: []string{"create"},
								}, "read", "offline_access")

								created = flow.redeem(code)

								grantID, ok = created.GetExtra("grant_id").(string)
								require.True(t, ok)

								before, err = flow.memory.GetGrant(flow.ctx, grantID)
								require.NoError(t, err)

								form.Set(consts.FormParameterGrantID, grantID)
							}

							id, code := flow.authorize(form, "write", "offline_access")

							restore := rc.reject(config)

							_, err = flow.exchange(url.Values{
								consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
								consts.FormParameterAuthorizationCode: []string{code},
								consts.FormParameterRedirectURI:       []string{grantManagementRedirectURI},
							})
							require.ErrorIs(t, err, rc.err)

							restore()

							if action == "create" {
								assert.Empty(t, flow.memory.Grants)
							} else {
								after, err := flow.memory.GetGrant(flow.ctx, grantID)
								require.NoError(t, err)

								assert.Equal(t, before, after)
								assert.Len(t, flow.memory.Grants, 1)

								assert.True(t, flow.active(created.GetAccessToken()))

								refreshed, err := flow.refresh(grantManagementRefreshToken(t, created))
								require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

								assert.Equal(t, grantID, refreshed.GetExtra("grant_id"))
							}

							issued := flow.redeem(code)

							grantID, ok = issued.GetExtra("grant_id").(string)
							require.True(t, ok)

							grant, err := flow.memory.GetGrant(flow.ctx, grantID)
							require.NoError(t, err)

							assert.Contains(t, grant.RequestIDs, id)
							assert.Contains(t, grant.Permissions.ScopeValues(), "write")
						})
					}
				})
			}
		})
	}
}

func TestMergeReachesRefreshedTokens(t *testing.T) {
	detailA := oauth2.AuthorizationDetail{Type: "account", Actions: []string{"read"}}
	detailB := oauth2.AuthorizationDetail{Type: "payment", Actions: []string{"write"}}

	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			ctx := context.Background()

			store, memory := sc.new()

			provider := newGrantManagementFlowProvider(t, store, memory,
				OAuth2AuthorizeExplicitFactory,
				OAuth2RefreshTokenGrantFactory,
				OAuth2TokenIntrospectionFactory,
				GrantManagementFactory,
			)

			require.NoError(t, memory.CreateGrant(ctx, &oauth2.Grant{
				ID:       "seeded",
				ClientID: grantManagementClientID,
				Subject:  "peter",
				Permissions: oauth2.GrantPermissions{
					Scopes:               []oauth2.GrantScope{{Scope: "read"}},
					AuthorizationDetails: oauth2.AuthorizationDetails{detailA},
				},
			}))

			details, err := json.Marshal(oauth2.AuthorizationDetails{detailB})
			require.NoError(t, err)

			requester, err := provider.NewAuthorizeRequest(ctx, newGrantManagementAuthorizeRequest(url.Values{
				consts.FormParameterScope:                 []string{"write offline_access"},
				consts.FormParameterAuthorizationDetails:  []string{string(details)},
				consts.FormParameterGrantManagementAction: []string{"merge"},
				consts.FormParameterGrantID:               []string{"seeded"},
			}))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			requester.GrantScope("write")
			requester.GrantScope("offline_access")
			requester.SetGrantedAuthorizationDetails(requester.GetRequestedAuthorizationDetails())

			responder, err := provider.NewAuthorizeResponse(ctx, requester, &oauth2.DefaultSession{Subject: "peter"})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			exchange := func(form url.Values) oauth2.AccessResponder {
				t.Helper()

				access, err := provider.NewAccessRequest(ctx, newGrantManagementClientRequest("https://as.example.com/token", form), &oauth2.DefaultSession{})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				response, err := provider.NewAccessResponse(ctx, access)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return response
			}

			issued := exchange(url.Values{
				consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
				consts.FormParameterAuthorizationCode: []string{responder.GetCode()},
				consts.FormParameterRedirectURI:       []string{grantManagementRedirectURI},
			})

			refresh, ok := issued.GetExtra(consts.AccessResponseRefreshToken).(string)
			require.True(t, ok)
			require.NotEmpty(t, refresh)

			check := func(name, token string) {
				t.Helper()

				_, introspected, err := provider.IntrospectToken(ctx, token, oauth2.AccessToken, &oauth2.DefaultSession{})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err), name)

				assert.ElementsMatch(t, []string{"read", "write", "offline_access"}, introspected.GetGrantedScopes(), name)
				assert.ElementsMatch(t, oauth2.AuthorizationDetails{detailA, detailB}, introspected.GetGrantedAuthorizationDetails(), name)

				session, ok := introspected.GetSession().(oauth2.GrantManagementSession)
				require.True(t, ok, name)

				assert.Equal(t, "seeded", session.GetGrantID(), name)
				assert.Equal(t, oauth2.GrantManagementActionMerge, session.GetGrantManagementAction(), name)

				require.NotNil(t, session.GetGrantPermissions(), name)
				assert.ElementsMatch(t, []string{"read", "write", "offline_access"}, session.GetGrantPermissions().ScopeValues(), name)
				assert.ElementsMatch(t, oauth2.AuthorizationDetails{detailA, detailB}, session.GetGrantPermissions().AuthorizationDetails, name)
			}

			check("Issued", issued.GetAccessToken())

			refreshed := exchange(url.Values{
				consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: []string{refresh},
			})

			check("Refreshed", refreshed.GetAccessToken())
		})
	}
}

func TestGrantManagementBackChannelApproval(t *testing.T) {
	const subject = "peter"

	testCases := []struct {
		name    string
		action  string
		id      string
		deleted bool
		err     error
		scopes  []string
	}{
		{name: "ShouldCarryAMergedGrant", action: "merge", id: "seeded", scopes: []string{consts.ScopeOpenID, "write", "read"}},
		{name: "ShouldCarryAReplacedGrant", action: "replace", id: "seeded", scopes: []string{consts.ScopeOpenID, "write"}},
		{name: "ShouldCarryACreatedGrant", action: "create", scopes: []string{consts.ScopeOpenID, "write"}},
		{name: "ShouldRejectAGrantDeletedBeforeApproval", action: "merge", id: "seeded", deleted: true, err: oauth2.ErrInvalidGrantID},
	}

	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ctx := context.Background()

					store, memory := sc.new()

					provider := newGrantManagementFlowProvider(t, store, memory, append([]Factory{GrantManagementFactory, OAuth2TokenIntrospectionFactory}, CIBAFactories()...)...)

					require.NoError(t, memory.CreateGrant(ctx, &oauth2.Grant{
						ID:          "seeded",
						ClientID:    grantManagementClientID,
						Subject:     subject,
						Permissions: oauth2.GrantPermissions{Scopes: []oauth2.GrantScope{{Scope: "read"}}},
					}))

					form := url.Values{
						consts.FormParameterScope:                 []string{"openid write"},
						consts.FormParameterLoginHint:             []string{subject},
						consts.FormParameterGrantManagementAction: []string{tc.action},
					}

					if tc.id != "" {
						form.Set(consts.FormParameterGrantID, tc.id)
					}

					session := openid.NewDefaultSession()

					request, err := provider.NewBackChannelAuthenticationRequest(ctx, newGrantManagementClientRequest("https://as.example.com/bc-authorize", form), session)
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					session.Subject, session.Claims.Subject = subject, subject

					response, err := provider.NewBackChannelAuthenticationResponse(ctx, request)
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					if tc.deleted {
						_, derr := memory.DeleteGrant(ctx, "seeded")
						require.NoError(t, derr)
					}

					decision, err := provider.NewBackChannelAuthenticationDecisionRequest(ctx, request.GetID(), openid.NewDefaultSession())
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					pending, ok := decision.GetSession().(oauth2.GrantManagementSession)
					require.True(t, ok)

					assert.Equal(t, oauth2.GrantManagementAction(tc.action), pending.GetGrantManagementAction())
					assert.NotEmpty(t, pending.GetGrantID())
					assert.Nil(t, pending.GetGrantPermissions())

					decision.GrantScope(consts.ScopeOpenID)
					decision.GrantScope("write")

					approval := openid.NewDefaultSession()
					approval.Subject, approval.Claims.Subject = subject, subject

					_, err = provider.ApproveBackChannelAuthentication(ctx, decision, approval)

					stored, gerr := provider.(*oauth2.Fosite).Store.(oauth2.CIBADecisionStorage).GetCIBASessionByRequestID(ctx, request.GetID(), openid.NewDefaultSession())
					require.NoError(t, gerr)

					if tc.err != nil {
						require.ErrorIs(t, err, tc.err)
						assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())
						assert.Empty(t, stored.GetGrantedScopes())

						return
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					assert.Equal(t, oauth2.CIBAStatusApproved, stored.GetStatus())
					assert.ElementsMatch(t, tc.scopes, stored.GetGrantedScopes())

					check := func(name string, have oauth2.Session) {
						t.Helper()

						carried, ok := have.(oauth2.GrantManagementSession)
						require.True(t, ok, name)

						assert.Equal(t, oauth2.GrantManagementAction(tc.action), carried.GetGrantManagementAction(), name)

						if tc.id != "" {
							assert.Equal(t, tc.id, carried.GetGrantID(), name)
						} else {
							assert.NotEmpty(t, carried.GetGrantID(), name)
						}

						require.NotNil(t, carried.GetGrantPermissions(), name)
						assert.ElementsMatch(t, tc.scopes, carried.GetGrantPermissions().ScopeValues(), name)
					}

					check("Stored", stored.GetSession())

					access, err := provider.NewAccessRequest(ctx, newGrantManagementClientRequest("https://as.example.com/token", url.Values{
						consts.FormParameterGrantType: []string{consts.GrantTypeOpenIDCIBA},
						consts.FormParameterAuthReqID: []string{response.GetAuthRequestID()},
					}), openid.NewDefaultSession())
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					check("Redeemed", access.GetSession())

					token, err := provider.NewAccessResponse(ctx, access)
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					assert.ElementsMatch(t, tc.scopes, access.GetGrantedScopes())

					carried, ok := access.GetSession().(oauth2.GrantManagementSession)
					require.True(t, ok)

					assert.Equal(t, request.GetID(), access.GetID())
					assert.Equal(t, carried.GetGrantID(), token.GetExtra("grant_id"))

					grant, err := memory.GetGrant(ctx, carried.GetGrantID())
					require.NoError(t, err)

					assert.Equal(t, grantManagementClientID, grant.ClientID)
					assert.Equal(t, subject, grant.Subject)
					assert.Equal(t, []string{request.GetID()}, grant.RequestIDs)
					assert.Equal(t, "client", grant.UpdatedBy)
					assert.ElementsMatch(t, tc.scopes, grant.Permissions.ScopeValues())

					_, introspected, err := provider.IntrospectToken(ctx, token.GetAccessToken(), oauth2.AccessToken, openid.NewDefaultSession())
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					check("Issued", introspected.GetSession())
				})
			}
		})
	}
}

func TestGrantManagementRequestValidation(t *testing.T) {
	unknown := url.Values{
		consts.FormParameterGrantManagementAction: []string{"merge"},
		consts.FormParameterGrantID:               []string{"unknown"},
	}

	testCases := []struct {
		name    string
		factory bool
		err     error
	}{
		{name: "ShouldRejectAnUnknownGrant", factory: true, err: oauth2.ErrInvalidGrantID},
		{name: "ShouldIgnoreTheParametersWithoutTheFactory", factory: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			check := func(t *testing.T, err error) {
				t.Helper()

				if tc.err == nil {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					return
				}

				require.ErrorIs(t, err, tc.err)
				assert.Equal(t, consts.ErrorInvalidGrantID, oauth2.ErrorToRFC6749Error(err).ErrorField)
			}

			t.Run("AuthorizationRequest", func(t *testing.T) {
				provider, _, _ := newGrantManagementProvider(t, tc.factory)

				_, err := provider.NewAuthorizeRequest(context.Background(), newGrantManagementAuthorizeRequest(unknown))

				check(t, err)
			})

			t.Run("PushedAuthorizationRequest", func(t *testing.T) {
				provider, _, _ := newGrantManagementProvider(t, tc.factory)

				_, err := provider.NewPushedAuthorizeRequest(context.Background(), newGrantManagementPushedRequest(unknown))

				check(t, err)
			})

			t.Run("RequestObject", func(t *testing.T) {
				provider, _, _ := newGrantManagementProvider(t, tc.factory)

				form := url.Values{
					consts.FormParameterClientID:     []string{grantManagementClientID},
					consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
					consts.FormParameterRequest:      []string{signGrantManagementRequestObject(t, unknown)},
				}

				r := httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil)

				requester, err := provider.NewAuthorizeRequest(context.Background(), r)

				check(t, err)

				require.NotNil(t, requester)
				assert.Equal(t, "merge", requester.GetRequestForm().Get(consts.FormParameterGrantManagementAction))
				assert.Equal(t, "unknown", requester.GetRequestForm().Get(consts.FormParameterGrantID))
			})

			t.Run("PushedRequestObject", func(t *testing.T) {
				provider, _, _ := newGrantManagementProvider(t, tc.factory)

				form := url.Values{
					consts.FormParameterRequest: []string{signGrantManagementRequestObject(t, unknown)},
				}

				_, err := provider.NewPushedAuthorizeRequest(context.Background(), newGrantManagementClientRequest("https://as.example.com/par", form))

				check(t, err)
			})
		})
	}
}

func TestGrantManagementRequestValidationThroughRequestURI(t *testing.T) {
	testCases := []struct {
		name    string
		revoked bool
		err     error
	}{
		{name: "ShouldCarryTheParameters"},
		{name: "ShouldRejectAGrantRevokedSinceTheRequestWasPushed", revoked: true, err: oauth2.ErrInvalidGrantID},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			provider, store, _ := newGrantManagementProvider(t, true)

			require.NoError(t, store.CreateGrant(ctx, &oauth2.Grant{ID: "known", ClientID: grantManagementClientID, Subject: "peter"}))

			requester, err := provider.NewPushedAuthorizeRequest(ctx, newGrantManagementPushedRequest(url.Values{
				consts.FormParameterGrantManagementAction: []string{"merge"},
				consts.FormParameterGrantID:               []string{"known"},
			}))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			responder, err := provider.NewPushedAuthorizeResponse(ctx, requester, &oauth2.DefaultSession{})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			if tc.revoked {
				_, derr := store.DeleteGrant(ctx, "known")
				require.NoError(t, derr)
			}

			form := url.Values{
				consts.FormParameterClientID:   []string{grantManagementClientID},
				consts.FormParameterRequestURI: []string{responder.GetRequestURI()},
			}

			resolved, err := provider.NewAuthorizeRequest(ctx, httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil))

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.Equal(t, "merge", resolved.GetRequestForm().Get(consts.FormParameterGrantManagementAction))
			assert.Equal(t, "known", resolved.GetRequestForm().Get(consts.FormParameterGrantID))
		})
	}
}

func TestGrantManagementDeviceAuthorizationRequest(t *testing.T) {
	testCases := []struct {
		name    string
		factory bool
		err     error
	}{
		{name: "ShouldRejectTheParameters", factory: true, err: oauth2.ErrInvalidRequest},
		{name: "ShouldIgnoreTheParametersWithoutTheFactory", factory: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _, _ := newGrantManagementProvider(t, tc.factory)

			form := url.Values{
				consts.FormParameterScope:                 []string{"foo"},
				consts.FormParameterGrantManagementAction: []string{"create"},
			}

			requester, err := provider.NewRFC862DeviceAuthorizeRequest(context.Background(), newGrantManagementClientRequest("https://as.example.com/device", form))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			_, err = provider.NewRFC862DeviceAuthorizeResponse(context.Background(), requester, &oauth2.DefaultSession{})

			if tc.err == nil {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, tc.err)
			assert.Equal(t, "Grant management is not supported at the device authorization endpoint.", oauth2.ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestGrantManagementBackChannelApprovalRetry(t *testing.T) {
	const subject = "peter"

	detailA := oauth2.AuthorizationDetail{Type: "account", Actions: []string{"read"}}
	detailB := oauth2.AuthorizationDetail{Type: "payment", Actions: []string{"write"}}

	for _, sc := range grantManagementTestStores {
		t.Run(sc.name, func(t *testing.T) {
			ctx := context.Background()

			store, memory := sc.new()

			provider := newGrantManagementFlowProvider(t, store, memory, append([]Factory{GrantManagementFactory}, CIBAFactories()...)...)

			config, ok := provider.(*oauth2.Fosite).Config.(*oauth2.Config)
			require.True(t, ok)

			failing := &grantManagementFailingDecisionHandler{err: oauth2.ErrServerError.WithDebug("The decision could not be recorded.")}

			require.IsType(t, &grantmgmt.Handler{}, config.BackChannelAuthenticationDecisionHandlers[0])

			config.BackChannelAuthenticationDecisionHandlers = slices.Insert(config.BackChannelAuthenticationDecisionHandlers, 1, oauth2.BackChannelAuthenticationDecisionHandler(failing))

			require.NoError(t, memory.CreateGrant(ctx, &oauth2.Grant{
				ID:       "seeded",
				ClientID: grantManagementClientID,
				Subject:  subject,
				Permissions: oauth2.GrantPermissions{
					Scopes:               []oauth2.GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}},
					Audience:             []string{"https://rs1"},
					AuthorizationDetails: oauth2.AuthorizationDetails{detailA},
				},
			}))

			memory.Clients[grantManagementClientID].(*oauth2.DefaultCIBAClient).Audience = []string{"https://rs1"}

			details, err := json.Marshal(oauth2.AuthorizationDetails{detailB})
			require.NoError(t, err)

			session := openid.NewDefaultSession()

			request, err := provider.NewBackChannelAuthenticationRequest(ctx, newGrantManagementClientRequest("https://as.example.com/bc-authorize", url.Values{
				consts.FormParameterScope:                 []string{"openid write"},
				consts.FormParameterLoginHint:             []string{subject},
				consts.FormParameterAuthorizationDetails:  []string{string(details)},
				consts.FormParameterGrantManagementAction: []string{"merge"},
				consts.FormParameterGrantID:               []string{"seeded"},
			}), session)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			session.Subject, session.Claims.Subject = subject, subject

			_, err = provider.NewBackChannelAuthenticationResponse(ctx, request)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			decision, err := provider.NewBackChannelAuthenticationDecisionRequest(ctx, request.GetID(), openid.NewDefaultSession())
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			decision.GrantScope(consts.ScopeOpenID)
			decision.GrantScope("write")
			decision.SetGrantedAuthorizationDetails(decision.GetRequestedAuthorizationDetails())

			pending := decision.GetSession()

			approval := openid.NewDefaultSession()
			approval.Subject, approval.Claims.Subject = subject, subject

			_, err = provider.ApproveBackChannelAuthentication(ctx, decision, approval)
			require.ErrorIs(t, err, oauth2.ErrServerError)

			assert.Equal(t, 1, failing.calls)
			assert.Equal(t, oauth2.CIBAStatusPending, decision.GetStatus())
			assert.Same(t, pending, decision.GetSession())
			assert.Equal(t, oauth2.Arguments{consts.ScopeOpenID, "write"}, decision.GetGrantedScopes())
			assert.Empty(t, decision.GetGrantedAudience())
			assert.Empty(t, decision.GetGrantedResource())
			assert.Equal(t, oauth2.AuthorizationDetails{detailB}, decision.GetGrantedAuthorizationDetails())

			failing.err = nil

			_, err = provider.ApproveBackChannelAuthentication(ctx, decision, approval)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			stored, err := provider.(*oauth2.Fosite).Store.(oauth2.CIBADecisionStorage).GetCIBASessionByRequestID(ctx, request.GetID(), openid.NewDefaultSession())
			require.NoError(t, err)

			assert.Equal(t, oauth2.CIBAStatusApproved, stored.GetStatus())
			assert.Equal(t, oauth2.Arguments{consts.ScopeOpenID, "write", "read"}, stored.GetGrantedScopes())
			assert.Equal(t, oauth2.Arguments{"https://rs1"}, stored.GetGrantedAudience())
			assert.Equal(t, oauth2.Arguments{"https://rs1"}, stored.GetGrantedResource())
			assert.ElementsMatch(t, oauth2.AuthorizationDetails{detailA, detailB}, stored.GetGrantedAuthorizationDetails())

			carried, ok := stored.GetSession().(oauth2.GrantManagementSession)
			require.True(t, ok)

			assert.Equal(t, "seeded", carried.GetGrantID())
			require.NotNil(t, carried.GetGrantPermissions())
			assert.ElementsMatch(t, []string{consts.ScopeOpenID, "write", "read"}, carried.GetGrantPermissions().ScopeValues())
		})
	}
}

const (
	grantManagementClientID     = "grant-client"
	grantManagementClientSecret = "grant-client-secret"
	grantManagementRedirectURI  = "https://client.example.com/cb"
)

var grantManagementClientKey = gen.MustRSAKey()

type grantManagementRejectingBinder struct {
	err error
}

func (b *grantManagementRejectingBinder) BindAccessRequest(context.Context, oauth2.AccessRequester) error {
	return b.err
}

func (b *grantManagementRejectingBinder) PopulateBoundTokenEndpointResponse(context.Context, oauth2.AccessRequester, oauth2.AccessResponder) error {
	return nil
}

type grantManagementFailingDecisionHandler struct {
	err   error
	calls int
}

func (h *grantManagementFailingDecisionHandler) HandleBackChannelAuthenticationDecision(_ context.Context, _ oauth2.BackChannelAuthenticationRequester, _ *oauth2.BackChannelAuthenticationDecisionResult) error {
	h.calls++

	return h.err
}

var grantManagementTestStores = []struct {
	name string
	new  func() (any, *storage.MemoryStore)
}{
	{"MemoryStore", func() (any, *storage.MemoryStore) {
		store := storage.NewMemoryStore()

		return store, store
	}},
	{"HydratingMemoryStore", func() (any, *storage.MemoryStore) {
		store := storage.NewHydratingMemoryStore()

		return store, store.MemoryStore
	}},
}

type grantManagementFlow struct {
	t        *testing.T
	ctx      context.Context
	provider oauth2.Provider
	memory   *storage.MemoryStore
}

func newGrantManagementFlow(t *testing.T, stores func() (any, *storage.MemoryStore)) *grantManagementFlow {
	t.Helper()

	store, memory := stores()

	return &grantManagementFlow{
		t:      t,
		ctx:    context.Background(),
		memory: memory,
		provider: newGrantManagementFlowProvider(t, store, memory,
			OAuth2AuthorizeExplicitFactory,
			OAuth2RefreshTokenGrantFactory,
			OAuth2TokenIntrospectionFactory,
			GrantManagementFactory,
		),
	}
}

func (f *grantManagementFlow) authorize(form url.Values, scopes ...string) (id, code string) {
	f.t.Helper()

	requester, err := f.provider.NewAuthorizeRequest(f.ctx, newGrantManagementAuthorizeRequest(form))
	require.NoError(f.t, oauth2.ErrorToDebugRFC6749Error(err))

	for _, scope := range scopes {
		requester.GrantScope(scope)
	}

	responder, err := f.provider.NewAuthorizeResponse(f.ctx, requester, &oauth2.DefaultSession{Subject: "peter"})
	require.NoError(f.t, oauth2.ErrorToDebugRFC6749Error(err))

	require.NotEmpty(f.t, requester.GetID())
	require.NotEmpty(f.t, responder.GetCode())

	return requester.GetID(), responder.GetCode()
}

func (f *grantManagementFlow) exchange(form url.Values) (oauth2.AccessResponder, error) {
	f.t.Helper()

	access, err := f.provider.NewAccessRequest(f.ctx, newGrantManagementClientRequest("https://as.example.com/token", form), &oauth2.DefaultSession{})
	if err != nil {
		return nil, err
	}

	return f.provider.NewAccessResponse(f.ctx, access)
}

func (f *grantManagementFlow) redeem(code string) oauth2.AccessResponder {
	f.t.Helper()

	response, err := f.exchange(url.Values{
		consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: []string{code},
		consts.FormParameterRedirectURI:       []string{grantManagementRedirectURI},
	})
	require.NoError(f.t, oauth2.ErrorToDebugRFC6749Error(err))

	return response
}

func (f *grantManagementFlow) refresh(token string) (oauth2.AccessResponder, error) {
	f.t.Helper()

	return f.exchange(url.Values{
		consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: []string{token},
	})
}

func (f *grantManagementFlow) active(token string) bool {
	f.t.Helper()

	_, _, err := f.provider.IntrospectToken(f.ctx, token, oauth2.AccessToken, &oauth2.DefaultSession{})

	return err == nil
}

func grantManagementRefreshToken(t *testing.T, response oauth2.AccessResponder) string {
	t.Helper()

	token, ok := response.GetExtra(consts.AccessResponseRefreshToken).(string)
	require.True(t, ok)
	require.NotEmpty(t, token)

	return token
}

func newGrantManagementFlowProvider(t *testing.T, store any, memory *storage.MemoryStore, factories ...Factory) oauth2.Provider {
	t.Helper()

	config := &oauth2.Config{
		Issuer:       "https://as.example.com",
		GlobalSecret: []byte("some-cool-secret-that-is-32bytes"),
		AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{
			&oauth2.DefaultAuthorizationDetailsTypeHandler{Name: "account"},
			&oauth2.DefaultAuthorizationDetailsTypeHandler{Name: "payment"},
		},
		GrantManagement: &oauth2.GrantManagementConfig{
			Actions: []oauth2.GrantManagementAction{
				oauth2.GrantManagementActionCreate,
				oauth2.GrantManagementActionMerge,
				oauth2.GrantManagementActionReplace,
			},
			Endpoint: "https://as.example.com/grants",
		},
	}

	provider := Compose(config, store, newCIBATestStrategy(config), factories...)

	memory.Clients[grantManagementClientID] = &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode: consts.CIBAModePoll,
		DefaultClient: &oauth2.DefaultClient{
			ID:            grantManagementClientID,
			ClientSecret:  oauth2.NewPlainTextClientSecret(grantManagementClientSecret),
			RedirectURIs:  []string{grantManagementRedirectURI},
			ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
			GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken, consts.GrantTypeOpenIDCIBA},
			Scopes:        []string{consts.ScopeOpenID, "read", "write", "offline_access"},
		},
	}

	return provider
}

func newGrantManagementProvider(t *testing.T, factory bool) (oauth2.Provider, *storage.MemoryStore, *oauth2.Config) {
	t.Helper()

	key := gen.MustRSAKey()

	store := storage.NewMemoryStore()

	config := &oauth2.Config{
		Issuer:                     "https://as.example.com",
		RFC8628UserVerificationURL: "https://as.example.com/device/verify",
		GlobalSecret:               []byte("some-cool-secret-that-is-32bytes"),
		GrantManagement: &oauth2.GrantManagementConfig{
			Actions: []oauth2.GrantManagementAction{
				oauth2.GrantManagementActionCreate,
				oauth2.GrantManagementActionMerge,
				oauth2.GrantManagementActionReplace,
			},
			Endpoint: "https://as.example.com/grants",
		},
	}

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	factories := []Factory{
		OAuth2AuthorizeExplicitFactory,
		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,
		RFC8628DeviceAuthorizeFactory,
	}

	if factory {
		factories = append(factories, GrantManagementFactory)
	}

	provider := Compose(config, store, &CommonStrategy{
		CoreStrategy: NewOAuth2HMACStrategy(config),
		Strategy:     strategy,
	}, factories...)

	store.Clients[grantManagementClientID] = &oauth2.DefaultJARClient{
		DefaultClient: &oauth2.DefaultClient{
			ID:            grantManagementClientID,
			ClientSecret:  oauth2.NewPlainTextClientSecret(grantManagementClientSecret),
			RedirectURIs:  []string{grantManagementRedirectURI},
			ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
			GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeOAuthDeviceCode},
			Scopes:        []string{"foo"},
		},
		JSONWebKeys:             &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "k", Use: "sig", Algorithm: "RS256", Key: &grantManagementClientKey.PublicKey}}},
		RequestObjectSigningAlg: "RS256",
	}

	return provider, store, config
}

func grantManagementRegistered[H any](handlers []H) bool {
	for _, h := range handlers {
		if _, ok := any(h).(*grantmgmt.Handler); ok {
			return true
		}
	}

	return false
}

func newGrantManagementAuthorizeForm(extra url.Values) url.Values {
	form := url.Values{
		consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:  []string{grantManagementRedirectURI},
		consts.FormParameterScope:        []string{"foo"},
		consts.FormParameterState:        []string{"abcdefghijklmnop"},
	}

	for k, v := range extra {
		form[k] = v
	}

	return form
}

func newGrantManagementAuthorizeRequest(extra url.Values) *http.Request {
	form := newGrantManagementAuthorizeForm(extra)
	form.Set(consts.FormParameterClientID, grantManagementClientID)

	return httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil)
}

func newGrantManagementPushedRequest(extra url.Values) *http.Request {
	return newGrantManagementClientRequest("https://as.example.com/par", newGrantManagementAuthorizeForm(extra))
}

func newGrantManagementClientRequest(endpoint string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.SetBasicAuth(grantManagementClientID, grantManagementClientSecret)

	return r
}

func signGrantManagementRequestObject(t *testing.T, extra url.Values) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: grantManagementClientKey, KeyID: "k"}}, (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt"))
	require.NoError(t, err)

	claims := map[string]any{consts.FormParameterClientID: grantManagementClientID}

	for k, v := range newGrantManagementAuthorizeForm(extra) {
		claims[k] = v[0]
	}

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	assertion, err := signed.CompactSerialize()
	require.NoError(t, err)

	return assertion
}
