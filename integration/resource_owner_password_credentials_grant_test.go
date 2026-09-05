// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestResourceOwnerPasswordCredentialsFlow(t *testing.T) {
	for _, strategy := range []hoauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runResourceOwnerPasswordCredentialsGrantTest(t, strategy)
	}
}

func runResourceOwnerPasswordCredentialsGrantTest(t *testing.T, strategy hoauth2.AccessTokenStrategy) {
	f := compose.Compose(
		new(oauth2.Config),
		store,
		strategy,
		compose.OAuth2ResourceOwnerPasswordCredentialsFactory, //nolint:staticcheck
	)

	ts := mockServer(t, f, &oauth2.DefaultSession{})

	defer ts.Close()

	var username, password string

	oauthClient := newOAuth2Client(ts)

	testCases := []struct {
		name  string
		setup func()
		check func(t *testing.T, token *xoauth2.Token)
		err   bool
	}{
		{
			name: "should fail because invalid password",
			setup: func() {
				username = "peter"
				password = "something-wrong"
			},
			err: true,
		},
		{
			name: "should pass",
			setup: func() {
				password = "secret"
			},
		},
		{
			name: "should pass with custom client token lifespans",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				oauthClient.ClientID = testClientIDLifespan
			},
			check: func(t *testing.T, token *xoauth2.Token) {
				s, err := store.GetAccessTokenSession(t.Context(), strings.Split(token.AccessToken, ".")[1], nil)
				require.NoError(t, err)
				atExp := s.GetSession().GetExpiresAt(oauth2.AccessToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.PasswordGrantAccessTokenLifespan), atExp, time.Minute)
				atExpIn := time.Duration(token.Extra(consts.AccessResponseExpiresIn).(float64)) * time.Second
				internal.RequireEqualDuration(t, *internal.TestLifespans.PasswordGrantAccessTokenLifespan, atExpIn, time.Minute)
				rtExp := s.GetSession().GetExpiresAt(oauth2.RefreshToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.PasswordGrantRefreshTokenLifespan), rtExp, time.Minute)
			},
		},
	}

	for _, tc := range testCases {
		tc.setup()

		token, err := oauthClient.PasswordCredentialsToken(t.Context(), username, password)
		require.Equal(t, tc.err, err != nil)

		if !tc.err {
			assert.NotEmpty(t, token.AccessToken)

			if tc.check != nil {
				tc.check(t, token)
			}
		}
	}
}
