// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidateJWTSecuredAuthorizeResponseMode(t *testing.T) {
	const issuer = "https://id.example.com"

	testCases := []struct {
		name   string
		config *oauth2.Config
		err    bool
	}{
		{name: "ShouldPassWithoutAJARMStrategy", config: &oauth2.Config{}},
		{name: "ShouldPassWithTheJARMIssuer", config: &oauth2.Config{JWTSecuredAuthorizeResponseModeStrategy: &jwt.DefaultStrategy{}, JWTSecuredAuthorizeResponseModeIssuer: "https://jarm.example.com"}},
		{name: "ShouldPassWithTheIDTokenIssuer", config: &oauth2.Config{JWTSecuredAuthorizeResponseModeStrategy: &jwt.DefaultStrategy{}, IDTokenIssuer: issuer}},
		{name: "ShouldFailWithoutAnIssuer", config: &oauth2.Config{JWTSecuredAuthorizeResponseModeStrategy: &jwt.DefaultStrategy{}}, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateJWTSecuredAuthorizeResponseMode(tc.config)

			if !tc.err {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrJWTSecuredAuthorizeResponseModeIssuer)
		})
	}
}

func TestComposePanicsWhenTheJARMStrategyHasNoIssuer(t *testing.T) {
	config := &oauth2.Config{
		GlobalSecret:                            []byte("some-cool-secret-that-is-32bytes"),
		JWTSecuredAuthorizeResponseModeStrategy: &jwt.DefaultStrategy{},
	}

	assert.PanicsWithError(t, ErrJWTSecuredAuthorizeResponseModeIssuer.Error(), func() {
		_ = Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), OAuth2AuthorizeExplicitFactory)
	})
}
