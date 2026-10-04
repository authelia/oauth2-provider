// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestIsIDJAGAssertion(t *testing.T) {
	testCases := []struct {
		name     string
		typ      string
		expected bool
	}{
		{"ShouldMatchIDJAG", consts.JSONWebTokenTypeIDJAG, true},
		{"ShouldMatchUpperCase", idjagTypeUpper, true},
		{"ShouldMatchMediaType", idjagTypeMediaType, true},
		{"ShouldNotMatchJWT", "JWT", false},
		{"ShouldNotMatchAbsent", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, rfc7523.IsIDJAGAssertion(signIDJAGDispatchAssertion(t, tc.typ)))
		})
	}

	assert.False(t, rfc7523.IsIDJAGAssertion("not-a-jwt"))
}

func TestHandlerStepsAsideForIDJAG(t *testing.T) {
	handler := &rfc7523.Handler{Config: &oauth2.Config{}, HandleHelper: &hoauth2.HandleHelper{Config: &oauth2.Config{}}}

	for _, typ := range []string{consts.JSONWebTokenTypeIDJAG, idjagTypeUpper, idjagTypeMediaType} {
		t.Run(typ, func(t *testing.T) {
			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer},
				Request: oauth2.Request{
					Client:  &oauth2.DefaultClient{ID: "c", GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer}},
					Form:    url.Values{consts.FormParameterAssertion: {signIDJAGDispatchAssertion(t, typ)}},
					Session: &oauth2.DefaultSession{},
				},
			}

			require.ErrorIs(t, handler.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrUnknownRequest)
			require.ErrorIs(t, handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse()), oauth2.ErrUnknownRequest)
		})
	}
}

const (
	idjagTypeUpper     = "OAUTH-ID-JAG+JWT"
	idjagTypeMediaType = "application/oauth-id-jag+jwt"
)

func signIDJAGDispatchAssertion(t *testing.T, typ string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	options := &jose.SignerOptions{}
	if typ != "" {
		options = options.WithType(jose.ContentType(typ))
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, options)
	require.NoError(t, err)

	raw, err := josejwt.Signed(signer).Claims(map[string]any{"iss": "https://idp.example.com", "exp": time.Now().Add(time.Minute).Unix()}).Serialize()
	require.NoError(t, err)

	return raw
}
