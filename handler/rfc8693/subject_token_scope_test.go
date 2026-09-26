// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIDTokenSubjectTokenScope(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	client := store.Clients["my-client"]

	handler := &IDTokenTypeHandler{
		Config:             cfg,
		Strategy:           jwtStrategy,
		IssueStrategy:      &openid.DefaultStrategy{Strategy: jwtStrategy, Config: cfg},
		ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
		Storage:            store,
	}

	testCases := []struct {
		name   string
		claims jwt.MapClaims
		scopes oauth2.Arguments
		err    string
	}{
		{
			name: "ShouldAcceptWithoutRequestedScope",
		},
		{
			name:   "ShouldRejectARequestedScope",
			scopes: oauth2.Arguments{"offline"},
			err:    "The requested scope is invalid, unknown, or malformed. The subject token is not granted 'offline' and so this scope cannot be requested.",
		},
		{
			name:   "ShouldRejectARequestedScopeEvenWithAScopeClaim",
			claims: jwt.MapClaims{consts.ClaimScope: "offline"},
			scopes: oauth2.Arguments{"offline"},
			err:    "The requested scope is invalid, unknown, or malformed. The subject token is not granted 'offline' and so this scope cannot be requested.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				consts.ClaimSubject:        "peter",
				consts.ClaimAudience:       []string{client.GetID()},
				consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
			}

			for k, v := range tc.claims {
				claims[k] = v
			}

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				Request: oauth2.Request{
					ID:             uuid.New().String(),
					Client:         client,
					RequestedScope: tc.scopes,
					Form: url.Values{
						consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693IDToken},
						consts.FormParameterSubjectToken:     {createJWT(t.Context(), client, jwtStrategy, claims)},
					},
					Session: newSpecSession("peter"),
				},
			}

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidScope)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
		})
	}
}

func TestCustomJWTSubjectTokenScope(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	client := store.Clients["my-client"]

	handler := &CustomJWTTypeHandler{
		Config:   cfg,
		Strategy: jwtStrategy,
		Storage:  store,
	}

	testCases := []struct {
		name   string
		scope  any
		scopes oauth2.Arguments
		err    string
	}{
		{
			name: "ShouldAcceptWithoutRequestedScope",
		},
		{
			name:   "ShouldRejectARequestedScopeWithoutAScopeClaim",
			scopes: oauth2.Arguments{"foo"},
			err:    "The requested scope is invalid, unknown, or malformed. The subject token is not granted 'foo' and so this scope cannot be requested.",
		},
		{
			name:   "ShouldAcceptARequestedScopeInAStringScopeClaim",
			scope:  "foo bar",
			scopes: oauth2.Arguments{"foo"},
		},
		{
			name:   "ShouldAcceptARequestedScopeInAnArrayScopeClaim",
			scope:  []string{"foo", "bar"},
			scopes: oauth2.Arguments{"bar"},
		},
		{
			name:   "ShouldRejectARequestedScopeNotInTheScopeClaim",
			scope:  "foo bar",
			scopes: oauth2.Arguments{"foo", "baz"},
			err:    "The requested scope is invalid, unknown, or malformed. The subject token is not granted 'baz' and so this scope cannot be requested.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				consts.ClaimIssuer:         "https://as.example.com",
				consts.ClaimSubject:        "peter",
				"subject":                  "peter",
				consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
			}

			if tc.scope != nil {
				claims[consts.ClaimScope] = tc.scope
			}

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				Request: oauth2.Request{
					ID:             uuid.New().String(),
					Client:         client,
					RequestedScope: tc.scopes,
					Form: url.Values{
						consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
						consts.FormParameterSubjectToken:     {createJWT(t.Context(), client, jwtStrategy, claims)},
					},
					Session: newSpecSession("peter"),
				},
			}

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidScope)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
		})
	}
}
