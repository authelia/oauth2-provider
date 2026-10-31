// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestDeviceCodeTokenRequestResourceAndAudience(t *testing.T) {
	const (
		resourceA = "https://a.example.com/"
		resourceB = "https://b.example.com/"
		audienceA = "https://aud-a.example.com"
		audienceB = "https://aud-b.example.com"
		never     = "https://never.example.com/"
	)

	testCases := []struct {
		name            string
		audience        oauth2.Arguments
		resource        oauth2.Arguments
		grantedAudience oauth2.Arguments
		grantedResource oauth2.Arguments
		err             error
	}{
		{
			name:            "ShouldGrantEverythingWithoutANarrowing",
			grantedAudience: oauth2.Arguments{audienceA, audienceB},
			grantedResource: oauth2.Arguments{resourceA, resourceB},
		},
		{
			name:            "ShouldNarrowTheResource",
			resource:        oauth2.Arguments{resourceA},
			grantedAudience: oauth2.Arguments{audienceA, audienceB},
			grantedResource: oauth2.Arguments{resourceA},
		},
		{
			name:            "ShouldNarrowTheAudience",
			audience:        oauth2.Arguments{audienceB},
			grantedAudience: oauth2.Arguments{audienceB},
			grantedResource: oauth2.Arguments{resourceA, resourceB},
		},
		{
			name:     "ShouldRefuseAResourceOutsideTheGrant",
			resource: oauth2.Arguments{never},
			err:      oauth2.ErrInvalidTarget,
		},
		{
			name:     "ShouldRefuseAnAudienceOutsideTheGrant",
			audience: oauth2.Arguments{never},
			err:      oauth2.ErrInvalidTarget,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &o2hmacshaStrategy
			store := storage.NewHydratingMemoryStore()

			config := &oauth2.Config{
				ScopeStrategy:        oauth2.ExactScopeStrategy,
				AudienceStrategy:     oauth2.DefaultAudienceStrategy,
				ResourceStrategy:     oauth2.DefaultResourceStrategy,
				AccessTokenLifespan:  time.Minute,
				RefreshTokenLifespan: time.Hour,
				RefreshTokenScopes:   []string{},
			}

			handler := hoauth2.GenericCodeTokenEndpointHandler{
				CodeTokenEndpointHandler: &DeviceCodeTokenHandler{Strategy: strategy, Storage: store, Config: config},
				AccessTokenStrategy:      strategy,
				RefreshTokenStrategy:     strategy,
				Config:                   config,
				CoreStorage:              store,
				TokenRevocationStorage:   store,
			}

			client := &oauth2.DefaultClient{
				ID:         "foo",
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode, consts.GrantTypeRefreshToken},
				Audience:   []string{audienceA, audienceB},
				Resource:   []string{resourceA, resourceB},
			}

			code, signature, err := strategy.GenerateRFC8628DeviceCode(t.Context())
			require.NoError(t, err)

			_, userSignature, err := strategy.GenerateRFC8628UserCode(t.Context())
			require.NoError(t, err)

			grant := oauth2.NewDeviceAuthorizeRequest()
			grant.Client = client
			grant.Session = &oauth2.DefaultSession{}
			grant.RequestedAt = time.Now().UTC()
			grant.RequestedAudience = oauth2.Arguments{audienceA, audienceB, never}
			grant.RequestedResource = oauth2.Arguments{resourceA, resourceB, never}
			grant.GrantAudience(audienceA)
			grant.GrantAudience(audienceB)
			grant.GrantResource(resourceA)
			grant.GrantResource(resourceB)
			grant.GrantScope(consts.ScopeOfflineAccess)
			grant.SetDeviceCodeSignature(signature)
			grant.SetUserCodeSignature(userSignature)
			grant.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

			require.NoError(t, store.CreateDeviceCodeSession(t.Context(), signature, grant))

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
				Request: oauth2.Request{
					Client:            client,
					Form:              url.Values{consts.FormParameterDeviceCode: {code}},
					RequestedAudience: tc.audience,
					RequestedResource: tc.resource,
					Session:           &oauth2.DefaultSession{},
					RequestedAt:       time.Now().UTC(),
				},
			}

			err = handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			assert.ElementsMatch(t, tc.grantedAudience, request.GetGrantedAudience())
			assert.ElementsMatch(t, tc.grantedResource, request.GetGrantedResource())

			refresh, _ := response.GetExtra(consts.AccessResponseRefreshToken).(string)
			require.NotEmpty(t, refresh)

			stored, err := store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), refresh), &oauth2.DefaultSession{})
			require.NoError(t, err)

			// RFC 8707 Section 2.2: a refresh token is bound to the full original grant.
			assert.ElementsMatch(t, oauth2.Arguments{audienceA, audienceB}, stored.GetGrantedAudience())
			assert.ElementsMatch(t, oauth2.Arguments{resourceA, resourceB}, stored.GetGrantedResource())
		})
	}
}
