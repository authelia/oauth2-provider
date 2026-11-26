// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestRFC8693RefreshTokenSubjectRequiresOptIn(t *testing.T) {
	testCases := []struct {
		name      string
		optedIn   bool
		requested string
	}{
		{name: "ShouldRejectAnAccessTokenByDefault", requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldRejectARefreshTokenByDefault", requested: consts.TokenTypeRFC8693RefreshToken},
		{name: "ShouldIssueAnAccessTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldIssueARefreshTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, sc := range refreshSubjectStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				f := newRefreshSubjectFixture(t, sc.newStore, true)
				f.client.TokenExchangeOwnRefreshToken = tc.optedIn

				response, err := f.token(f.exchange(f.subject, tc.requested, "openid offline_access read"))

				if tc.optedIn {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.NotEmpty(t, response.GetAccessToken())

					return
				}

				// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2
				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), "Clients are not allowed to perform a token exchange on their own refresh tokens.")

				_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), f.subject), rfc8693.NewDefaultSession())
				require.NoError(t, err)

				refreshed, err := f.token(f.refresh(f.subject))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.NotEmpty(t, refreshed.GetAccessToken())
			})
		}
	}
}

func TestRFC8693RefreshTokenSubjectIsRestrictedToItsGrant(t *testing.T) {
	testCases := []struct {
		name     string
		audience []string
		resource []string
		expected error
	}{
		{name: "ShouldRejectAnAudienceOutsideTheGrant", audience: []string{refreshSubjectOtherAudience}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAResourceOutsideTheGrant", resource: []string{refreshSubjectOtherResource}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectOneAudienceOutsideTheGrant", audience: []string{refreshSubjectAudience, refreshSubjectOtherAudience}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectTheGrantedResourceAsAnAudience", audience: []string{refreshSubjectResource}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldAcceptTheGrantedAudience", audience: []string{refreshSubjectAudience}},
		{name: "ShouldAcceptTheGrantedResource", resource: []string{refreshSubjectResource}},
		{name: "ShouldAcceptTheGrantedAudienceAndResource", audience: []string{refreshSubjectAudience}, resource: []string{refreshSubjectResource}},
		{name: "ShouldAcceptNoTarget"},
	}

	for _, sc := range refreshSubjectStores() {
		for _, issue := range []bool{false, true} {
			for _, requested := range []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken} {
				if requested == consts.TokenTypeRFC8693RefreshToken && !issue {
					continue
				}

				for _, tc := range testCases {
					t.Run(refreshSubjectName(sc.name, issue, requested)+"/"+tc.name, func(t *testing.T) {
						f := newRefreshSubjectFixture(t, sc.newStore, issue)

						form := f.exchange(f.subject, requested, "openid offline_access read")
						form[consts.FormParameterAudience] = tc.audience
						form[consts.FormParameterResource] = tc.resource

						response, err := f.token(form)

						if tc.expected != nil {
							require.ErrorIs(t, err, tc.expected)

							original, err := f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), f.subject), rfc8693.NewDefaultSession())
							require.NoError(t, err)
							assert.Equal(t, oauth2.Arguments{refreshSubjectAudience}, original.GetGrantedAudience())
							assert.Equal(t, oauth2.Arguments{refreshSubjectResource}, original.GetGrantedResource())

							return
						}

						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

						if requested == consts.TokenTypeRFC8693AccessToken {
							issued := f.accessToken(t, response.GetAccessToken())

							assert.Equal(t, f.grant.GetID(), issued.GetID())
							assert.ElementsMatch(t, tc.audience, issued.GetGrantedAudience())
							assert.ElementsMatch(t, tc.resource, issued.GetGrantedResource())
						}

						refresh := response.GetAccessToken()
						if requested == consts.TokenTypeRFC8693AccessToken {
							refresh, _ = response.GetExtra(consts.AccessResponseRefreshToken).(string)
						}

						if !issue {
							assert.Empty(t, refresh)

							return
						}

						require.NotEmpty(t, refresh)

						// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
						rotated := f.refreshToken(t, refresh)

						assert.Equal(t, f.grant.GetID(), rotated.GetID())
						assert.Equal(t, f.grant.GetGrantedScopes(), rotated.GetGrantedScopes())
						assert.Equal(t, f.grant.GetGrantedAudience(), rotated.GetGrantedAudience())
						assert.Equal(t, f.grant.GetGrantedResource(), rotated.GetGrantedResource())

						refreshed, err := f.token(f.refresh(refresh))
						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

						issued := f.accessToken(t, refreshed.GetAccessToken())

						assert.Equal(t, f.grant.GetID(), issued.GetID())
						assert.Equal(t, f.grant.GetGrantedAudience(), issued.GetGrantedAudience())
						assert.Equal(t, f.grant.GetGrantedResource(), issued.GetGrantedResource())
					})
				}
			}
		}
	}
}

func TestRFC8693RefreshTokenSubjectNarrowsTheScopeOfTheAccessTokenOnly(t *testing.T) {
	for _, sc := range refreshSubjectStores() {
		for _, requested := range []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken} {
			t.Run(refreshSubjectName(sc.name, true, requested), func(t *testing.T) {
				f := newRefreshSubjectFixture(t, sc.newStore, true)

				response, err := f.token(f.exchange(f.subject, requested, "offline_access read"))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				refresh := response.GetAccessToken()

				if requested == consts.TokenTypeRFC8693AccessToken {
					assert.Equal(t, oauth2.Arguments{consts.ScopeOfflineAccess, "read"}, f.accessToken(t, response.GetAccessToken()).GetGrantedScopes())

					refresh, _ = response.GetExtra(consts.AccessResponseRefreshToken).(string)
				}

				// See: https://datatracker.ietf.org/doc/html/rfc6749#section-6
				assert.Equal(t, f.grant.GetGrantedScopes(), f.refreshToken(t, refresh).GetGrantedScopes())

				refreshed, err := f.token(f.refresh(refresh))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, f.grant.GetGrantedScopes(), f.accessToken(t, refreshed.GetAccessToken()).GetGrantedScopes())
			})
		}
	}
}

func TestRFC8693RefreshTokenSubjectAccessTokenIsRevokedWithTheGrant(t *testing.T) {
	for _, sc := range refreshSubjectStores() {
		for _, issue := range []bool{false, true} {
			t.Run(refreshSubjectName(sc.name, issue, consts.TokenTypeRFC8693AccessToken), func(t *testing.T) {
				f := newRefreshSubjectFixture(t, sc.newStore, issue)

				response, err := f.token(f.exchange(f.subject, consts.TokenTypeRFC8693AccessToken, "openid offline_access read"))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				signature := f.strategy.AccessTokenSignature(t.Context(), response.GetAccessToken())

				_, err = f.store.GetAccessTokenSession(t.Context(), signature, rfc8693.NewDefaultSession())
				require.NoError(t, err)

				// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
				require.NoError(t, f.store.RevokeRefreshToken(t.Context(), f.grant.GetID()))
				require.NoError(t, f.store.RevokeAccessToken(t.Context(), f.grant.GetID()))

				_, err = f.store.GetAccessTokenSession(t.Context(), signature, rfc8693.NewDefaultSession())
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				for _, token := range []string{f.subject, refreshSubjectString(response.GetExtra(consts.AccessResponseRefreshToken))} {
					if token == "" {
						continue
					}

					_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), token), rfc8693.NewDefaultSession())
					assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
				}
			})
		}
	}
}

func TestRFC8693RefreshTokenSubjectWithoutRotationIsRevokedWithTheGrant(t *testing.T) {
	for _, sc := range refreshSubjectStores() {
		for _, requested := range []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken} {
			t.Run(refreshSubjectName(sc.name, true, requested), func(t *testing.T) {
				f := newRefreshSubjectFixture(t, sc.newStore, true)

				f.client.TokenExchangeRefreshTokenRotationOverride = true
				f.client.TokenExchangeRefreshTokenRotation = false

				response, err := f.token(f.exchange(f.subject, requested, "openid offline_access read"))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				refresh := response.GetAccessToken()
				if requested == consts.TokenTypeRFC8693AccessToken {
					refresh = refreshSubjectString(response.GetExtra(consts.AccessResponseRefreshToken))
				}

				require.NotEmpty(t, refresh)

				for _, token := range []string{f.subject, refresh} {
					_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), token), rfc8693.NewDefaultSession())
					require.NoError(t, err)
				}

				// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
				require.NoError(t, f.store.RevokeRefreshToken(t.Context(), f.grant.GetID()))
				require.NoError(t, f.store.RevokeAccessToken(t.Context(), f.grant.GetID()))

				for _, token := range []string{f.subject, refresh} {
					_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), token), rfc8693.NewDefaultSession())
					assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
				}

				if requested == consts.TokenTypeRFC8693AccessToken {
					_, err = f.store.GetAccessTokenSession(t.Context(), f.strategy.AccessTokenSignature(t.Context(), response.GetAccessToken()), rfc8693.NewDefaultSession())
					assert.ErrorIs(t, err, oauth2.ErrNotFound)
				}
			})
		}
	}
}

func TestRFC8693RefreshTokenSubjectKeepsTheAuthenticationOfTheGrant(t *testing.T) {
	for _, sc := range refreshSubjectStores() {
		for _, requested := range []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken} {
			t.Run(refreshSubjectName(sc.name, true, requested), func(t *testing.T) {
				direct := newRefreshSubjectFixture(t, sc.newStore, true)

				expected, err := direct.token(direct.refresh(direct.subject))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				f := newRefreshSubjectFixture(t, sc.newStore, true)

				response, err := f.token(f.exchange(f.subject, requested, "openid offline_access read"))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				refresh := response.GetAccessToken()
				if requested == consts.TokenTypeRFC8693AccessToken {
					refresh = refreshSubjectString(response.GetExtra(consts.AccessResponseRefreshToken))
				}

				actual, err := f.token(f.refresh(refresh))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				// See: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
				assert.Equal(t, refreshSubjectIDTokenClaims(t, expected), refreshSubjectIDTokenClaims(t, actual))
				assert.Equal(t, "peter", f.accessToken(t, actual.GetAccessToken()).GetSession().GetSubject())
			})
		}
	}
}

func TestRFC8693RefreshTokenSubjectKeepsTheSessionOfTheGrant(t *testing.T) {
	for _, sc := range refreshSubjectStores() {
		for _, requested := range []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken} {
			t.Run(refreshSubjectName(sc.name, true, requested), func(t *testing.T) {
				f := newRefreshSubjectFixture(t, sc.newStore, true)

				response, err := f.token(f.exchange(f.subject, requested, "openid offline_access read"))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				refresh := response.GetAccessToken()
				if requested == consts.TokenTypeRFC8693AccessToken {
					refresh = refreshSubjectString(response.GetExtra(consts.AccessResponseRefreshToken))
				}

				// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
				assert.Equal(t, "peter@example.com", f.refreshToken(t, refresh).GetSession().GetUsername())

				actual, err := f.token(f.refresh(refresh))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				session, ok := f.accessToken(t, actual.GetAccessToken()).GetSession().(*rfc8693.DefaultSession)
				require.True(t, ok)

				assert.Equal(t, "peter@example.com", session.GetUsername())
				assert.Equal(t, "acme", session.IDTokenClaims().Extra["tenant"])
			})
		}
	}
}

const (
	refreshSubjectClientID      = "refresh-subject-client"
	refreshSubjectClientSecret  = "foobarfoobarfoobarfoobarfoobar12"
	refreshSubjectAudience      = "https://api.example.com"
	refreshSubjectOtherAudience = "https://other.example.com"
	refreshSubjectResource      = "https://resource.example.com/api"
	refreshSubjectOtherResource = "https://resource.example.com/other"
)

type refreshSubjectStore interface {
	hoauth2.TokenRevocationStorage
}

type refreshSubjectFixture struct {
	provider oauth2.Provider
	store    refreshSubjectStore
	strategy hoauth2.CoreStrategy
	client   *oauth2.DefaultRegisteredClient
	grant    *oauth2.AccessRequest
	subject  string
}

func refreshSubjectStores() []struct {
	name     string
	newStore func() (refreshSubjectStore, *storage.MemoryStore)
} {
	return []struct {
		name     string
		newStore func() (refreshSubjectStore, *storage.MemoryStore)
	}{
		{
			name: "MemoryStore",
			newStore: func() (refreshSubjectStore, *storage.MemoryStore) {
				store := storage.NewMemoryStore()

				return store, store
			},
		},
		{
			name: "HydratingMemoryStore",
			newStore: func() (refreshSubjectStore, *storage.MemoryStore) {
				store := storage.NewHydratingMemoryStore()

				return store, store.MemoryStore
			},
		},
	}
}

func refreshSubjectName(store string, issue bool, requested string) string {
	name := store + "/AccessToken"

	switch {
	case requested == consts.TokenTypeRFC8693RefreshToken:
		name = store + "/RefreshToken"
	case issue:
		name += "WithRefreshToken"
	}

	return name
}

func refreshSubjectString(value any) string {
	s, _ := value.(string)

	return s
}

func refreshSubjectIDTokenClaims(t *testing.T, response oauth2.AccessResponder) (claims map[string]any) {
	t.Helper()

	raw, ok := response.GetExtra(consts.AccessResponseIDToken).(string)
	require.True(t, ok, "the response has no ID Token")

	signed, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(signed.UnsafePayloadWithoutVerification(), &claims))

	kept := map[string]any{}

	for _, claim := range []string{consts.ClaimIssuer, consts.ClaimSubject, consts.ClaimAudience, consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationMethodsReference} {
		require.Contains(t, claims, claim)

		kept[claim] = claims[claim]
	}

	return kept
}

func newRefreshSubjectFixture(t *testing.T, newStore func() (refreshSubjectStore, *storage.MemoryStore), issue bool) *refreshSubjectFixture {
	t.Helper()

	store, memory := newStore()

	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOfflineAccess, "read"}

	client := &oauth2.DefaultRegisteredClient{TokenExchangeRefreshToken: issue, TokenExchangeOwnRefreshToken: true, DefaultClient: &oauth2.DefaultClient{
		ID:           refreshSubjectClientID,
		ClientSecret: oauth2.NewPlainTextClientSecret(refreshSubjectClientSecret),
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
		Scopes:       scopes,
		Audience:     []string{refreshSubjectAudience, refreshSubjectOtherAudience, refreshSubjectResource},
		Resource:     []string{refreshSubjectResource, refreshSubjectOtherResource},
	}}

	memory.Clients[refreshSubjectClientID] = client

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		Issuer:                                "https://as.example.com",
		AccessTokenLifespan:                   time.Hour,
		RefreshTokenLifespan:                  time.Hour,
		TokenEntropy:                          32,
		DefaultRequestedTokenType:             consts.TokenTypeRFC8693AccessToken,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken:  &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
			consts.TokenTypeRFC8693RefreshToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken},
		},
	}

	session := rfc8693.NewDefaultSession()
	session.SetSubject("peter")
	session.Username = "peter@example.com"
	session.SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(time.Hour))

	claims := session.IDTokenClaims()
	claims.Subject = "peter"
	claims.Extra = map[string]any{"tenant": "acme"}
	claims.AuthTime = jwt.NewNumericDate(time.Unix(1790000000, 0))
	claims.AuthenticationContextClassReference = "gold"
	claims.AuthenticationMethodsReferences = []string{"mfa"}

	grant := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request: oauth2.Request{
			ID:                "grant-id",
			RequestedAt:       time.Now().UTC(),
			Client:            client,
			RequestedScope:    scopes,
			GrantedScope:      scopes,
			RequestedAudience: oauth2.Arguments{refreshSubjectAudience},
			GrantedAudience:   oauth2.Arguments{refreshSubjectAudience},
			RequestedResource: oauth2.Arguments{refreshSubjectResource},
			GrantedResource:   oauth2.Arguments{refreshSubjectResource},
			Session:           session,
		},
	}

	ctx := context.Background()
	strategy := NewOAuth2HMACStrategy(config)

	token, signature, err := strategy.GenerateRefreshToken(ctx, grant)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, "", grant.Sanitize(nil)))

	return &refreshSubjectFixture{
		provider: ComposeAllEnabled(config, store, gen.MustRSAKey()),
		store:    store,
		strategy: strategy,
		client:   client,
		grant:    grant,
		subject:  token,
	}
}

func (f *refreshSubjectFixture) exchange(subject, requested, scope string) url.Values {
	return url.Values{
		consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectToken:       {subject},
		consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
		consts.FormParameterRequestedTokenType: {requested},
		consts.FormParameterScope:              {scope},
	}
}

func (f *refreshSubjectFixture) refresh(token string) url.Values {
	return url.Values{
		consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: {token},
	}
}

func (f *refreshSubjectFixture) token(form url.Values) (response oauth2.AccessResponder, err error) {
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
	r.SetBasicAuth(refreshSubjectClientID, refreshSubjectClientSecret)

	ctx := context.Background()

	var request oauth2.AccessRequester

	if request, err = f.provider.NewAccessRequest(ctx, r, rfc8693.NewDefaultSession()); err != nil {
		return nil, err
	}

	return f.provider.NewAccessResponse(ctx, request)
}

func (f *refreshSubjectFixture) accessToken(t *testing.T, token string) oauth2.Requester {
	t.Helper()

	request, err := f.store.GetAccessTokenSession(t.Context(), f.strategy.AccessTokenSignature(t.Context(), token), rfc8693.NewDefaultSession())
	require.NoError(t, err)

	return request
}

func (f *refreshSubjectFixture) refreshToken(t *testing.T, token string) oauth2.Requester {
	t.Helper()

	request, err := f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), token), rfc8693.NewDefaultSession())
	require.NoError(t, err)

	return request
}
