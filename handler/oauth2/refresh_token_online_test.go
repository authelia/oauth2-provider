// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

type onlineRefreshTokenClient struct {
	*oauth2.DefaultClient

	allow bool
}

func (c *onlineRefreshTokenClient) GetAllowOnlineRefreshTokens() bool {
	return c.allow
}

func newOnlineRefreshTokenClient(allow bool) *onlineRefreshTokenClient {
	return &onlineRefreshTokenClient{
		DefaultClient: &oauth2.DefaultClient{
			ID:         "foo",
			GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
			Scopes:     []string{"foo", consts.ScopeOffline, consts.ScopeOfflineAccess},
		},
		allow: allow,
	}
}

func onlineRefreshTokenStores() []struct {
	name string
	new  func() deadlineStore
} {
	return []struct {
		name string
		new  func() deadlineStore
	}{
		{"MemoryStore", func() deadlineStore { return storage.NewMemoryStore() }},
		{"HydratingMemoryStore", func() deadlineStore { return storage.NewHydratingMemoryStore() }},
	}
}

func storedRefreshTokenMode(t *testing.T, requester oauth2.Requester) oauth2.RefreshTokenMode {
	t.Helper()

	session, ok := requester.GetSession().(oauth2.RefreshTokenModeSession)
	require.True(t, ok)

	return session.GetRefreshTokenMode()
}

func TestAuthorizeCodeGrantOnlineRefreshToken(t *testing.T) {
	testCases := []struct {
		name     string
		scopes   []string
		granted  oauth2.Arguments
		allow    bool
		stored   *bool
		expected oauth2.RefreshTokenMode
	}{
		{"ShouldIssueOfflineWithOfflineAccess", nil, oauth2.Arguments{"foo", consts.ScopeOfflineAccess}, false, nil, oauth2.RefreshTokenModeOffline},
		{"ShouldIssueOfflineWithOfflineAccessWhenOnlineIsAllowed", nil, oauth2.Arguments{"foo", consts.ScopeOfflineAccess}, true, nil, oauth2.RefreshTokenModeOffline},
		{"ShouldNotIssueWithoutOfflineAccess", nil, oauth2.Arguments{"foo"}, false, nil, oauth2.RefreshTokenModeNone},
		{"ShouldIssueOnlineWithoutOfflineAccessWhenAllowed", nil, oauth2.Arguments{"foo"}, true, nil, oauth2.RefreshTokenModeOnline},
		{"ShouldIssueOfflineWithoutRefreshTokenScopes", []string{}, oauth2.Arguments{"foo"}, false, nil, oauth2.RefreshTokenModeOffline},
		{"ShouldIssueOnlineWhenTheAuthenticatedClientNowAllowsIt", nil, oauth2.Arguments{"foo"}, true, new(false), oauth2.RefreshTokenModeOnline},
		{"ShouldNotIssueOnlineWhenTheAuthenticatedClientNoLongerAllowsIt", nil, oauth2.Arguments{"foo"}, false, new(true), oauth2.RefreshTokenModeNone},
	}

	for _, s := range onlineRefreshTokenStores() {
		for _, tc := range testCases {
			t.Run(s.name+"/"+tc.name, func(t *testing.T) {
				store := s.new()
				strategy := &hmacshaStrategy
				client := newOnlineRefreshTokenClient(tc.allow)

				stored := client
				if tc.stored != nil {
					stored = newOnlineRefreshTokenClient(*tc.stored)
				}

				handler := AuthorizeExplicitGrantHandler{
					CoreStorage:           store,
					AuthorizeCodeStrategy: strategy,
					AccessTokenStrategy:   strategy,
					RefreshTokenStrategy:  strategy,
					Config: &oauth2.Config{
						ScopeStrategy:         oauth2.HierarchicScopeStrategy,
						AudienceStrategy:      oauth2.DefaultAudienceStrategy,
						AccessTokenLifespan:   time.Minute,
						AuthorizeCodeLifespan: time.Minute,
						RefreshTokenScopes:    tc.scopes,
					},
				}

				code, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)

				authorize := &oauth2.AuthorizeRequest{
					Request: oauth2.Request{
						Client:         stored,
						Form:           url.Values{},
						RequestedScope: tc.granted,
						GrantedScope:   tc.granted,
						Session:        &oauth2.DefaultSession{},
						RequestedAt:    time.Now().UTC(),
					},
				}

				require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), signature, authorize))

				access := &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					Request: oauth2.Request{
						Client:      client,
						Form:        url.Values{consts.FormParameterAuthorizationCode: []string{code}},
						Session:     &oauth2.DefaultSession{},
						RequestedAt: time.Now().UTC(),
					},
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), access)))

				response := oauth2.NewAccessResponse()
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), access, response)))

				storedAccess, err := store.GetAccessTokenSession(t.Context(), strategy.AccessTokenSignature(t.Context(), response.GetAccessToken()), &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, tc.expected, storedRefreshTokenMode(t, storedAccess))

				refresh, issued := response.ToMap()[consts.AccessResponseRefreshToken].(string)
				if tc.expected == oauth2.RefreshTokenModeNone {
					assert.False(t, issued)

					return
				}

				require.True(t, issued)

				storedRefresh, err := store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), refresh), &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, tc.expected, storedRefreshTokenMode(t, storedRefresh))
			})
		}
	}
}

func TestRefreshGrantOnlineRefreshToken(t *testing.T) {
	testCases := []struct {
		name     string
		granted  oauth2.Arguments
		scope    string
		allow    bool
		disable  bool
		expected oauth2.RefreshTokenMode
		err      error
	}{
		{name: "ShouldRedeemOnlineWhenAllowed", granted: oauth2.Arguments{"foo"}, allow: true, expected: oauth2.RefreshTokenModeOnline},
		{name: "ShouldRejectOnlineWhenNotAllowed", granted: oauth2.Arguments{"foo"}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRedeemOfflineWhenOnlineIsNotAllowed", granted: oauth2.Arguments{"foo", consts.ScopeOfflineAccess}, expected: oauth2.RefreshTokenModeOffline},
		{name: "ShouldKeepOfflineWhenOnlineIsAllowed", granted: oauth2.Arguments{"foo", consts.ScopeOfflineAccess}, allow: true, expected: oauth2.RefreshTokenModeOffline},
		{name: "ShouldKeepOfflineWithoutRotationWhenOnlineIsAllowed", granted: oauth2.Arguments{"foo", consts.ScopeOfflineAccess}, allow: true, disable: true, expected: oauth2.RefreshTokenModeOffline},
		{name: "ShouldRecordOnlineWhenTheRefreshNarrowsOfflineAccessAway", granted: oauth2.Arguments{"foo", consts.ScopeOfflineAccess}, scope: "foo", allow: true, expected: oauth2.RefreshTokenModeOnline},
		{name: "ShouldKeepThePresentedModeWithoutRotation", granted: oauth2.Arguments{"foo", consts.ScopeOfflineAccess}, scope: "foo", allow: true, disable: true, expected: oauth2.RefreshTokenModeOffline},
		{name: "ShouldRejectOnlineWithoutRotationWhenNotAllowed", granted: oauth2.Arguments{"foo"}, disable: true, err: oauth2.ErrInvalidGrant},
	}

	for _, s := range onlineRefreshTokenStores() {
		for _, tc := range testCases {
			t.Run(s.name+"/"+tc.name, func(t *testing.T) {
				store := s.new()
				strategy := &hmacshaStrategy
				client := newOnlineRefreshTokenClient(tc.allow)
				now := time.Now().UTC()

				original := &oauth2.Request{
					ID:             "req-id",
					Client:         client,
					RequestedAt:    now,
					GrantedScope:   tc.granted,
					RequestedScope: tc.granted,
					Session: &oauth2.DefaultSession{
						Subject:          "peter",
						ExpiresAt:        map[oauth2.TokenType]time.Time{oauth2.RefreshToken: now.Add(time.Hour)},
						RefreshTokenMode: oauth2.GetRefreshTokenModeForScopes([]string{consts.ScopeOffline, consts.ScopeOfflineAccess}, tc.granted),
					},
					Form: url.Values{},
				}

				token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
				require.NoError(t, err)

				_, accessSignature, err := strategy.GenerateAccessToken(t.Context(), nil)
				require.NoError(t, err)

				require.NoError(t, store.CreateAccessTokenSession(t.Context(), accessSignature, original))
				require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, accessSignature, original))

				handler := &RefreshTokenGrantHandler{
					TokenRevocationStorage: store,
					RefreshTokenStrategy:   strategy,
					AccessTokenStrategy:    strategy,
					Config: &oauth2.Config{
						AccessTokenLifespan:         time.Hour,
						RefreshTokenLifespan:        time.Hour,
						ScopeStrategy:               oauth2.HierarchicScopeStrategy,
						AudienceStrategy:            oauth2.DefaultAudienceStrategy,
						DisableRefreshTokenRotation: tc.disable,
					},
				}

				request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				request.Client = client
				request.Form = url.Values{consts.FormParameterRefreshToken: {token}}

				if tc.scope != "" {
					request.Form.Set(consts.FormParameterScope, tc.scope)
					request.SetRequestedScopes(oauth2.RemoveEmpty([]string{tc.scope}))
				}

				err = handler.HandleTokenEndpointRequest(t.Context(), request)
				if tc.err != nil {
					assert.ErrorIs(t, err, tc.err)

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				response := oauth2.NewAccessResponse()
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				storedAccess, err := store.GetAccessTokenSession(t.Context(), strategy.AccessTokenSignature(t.Context(), response.GetAccessToken()), &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, tc.expected, storedRefreshTokenMode(t, storedAccess))

				if tc.disable {
					return
				}

				refresh, ok := response.ToMap()[consts.AccessResponseRefreshToken].(string)
				require.True(t, ok)

				storedRefresh, err := store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), refresh), &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, tc.expected, storedRefreshTokenMode(t, storedRefresh))
			})
		}
	}
}
